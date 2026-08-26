# Known Limitations

Sentinel is a static analysis tool. Static analysis is fundamentally limited by
Rice's theorem: no analyzer can be both sound (zero false negatives) and complete
(zero false positives) for all programs. Every tool makes tradeoffs. Here are ours.

## Analysis Layer Limitations

### No Type Resolution

Sentinel uses `solang-parser` for Solidity parsing. This gives us a concrete
syntax tree (CST/parse tree), not a fully-resolved AST with type information.
Consequences:

- No inheritance linearization (C3). Detectors cannot resolve virtual dispatch,
  know which override actually executes, or correctly trace through diamond
  inheritance.
- No cross-file import resolution. If `ContractA` imports and calls
  `ContractB.withdraw()`, Sentinel cannot follow that call.
- No type inference on expressions. We cannot distinguish `uint256` from
  `int256` from `address` in complex expressions without solc type annotations.

**Mitigation planned**: integrate `solc --standard-json` output for
fully-resolved AST with type info, similar to how Aderyn uses
`foundry-compilers`.

### No Intermediate Representation (IR / SSA)

Sentinel has no SSA-form IR. Slither has SlithIR; Securify has Datalog facts.
Without IR:

- Cannot track a value through reassignments (`x = a; y = x; z = y;` -- we
  lose the chain).
- Cannot reason about which path a variable took through branches.
- Cannot perform fixpoint data-flow or taint analysis.

**Consequence**: detectors that need data-flow (e.g., "is this value
user-controlled?") fall back to regex heuristics on function bodies, which
break when variables are renamed, wrapped in helpers, or split across functions.

### No Control Flow Graph (CFG)

Without a CFG:

- Cannot reason about statement ordering within a function (only pattern
  matching on source text).
- Cannot compute dominators or post-dominators.
- Cannot do path-sensitive analysis ("is the external call always preceded by
  a require?").

### No Call Graph / Cross-Contract Analysis

- Detectors analyze one contract at a time.
- Cross-function reentrancy (function A calls external, function B writes
  state, both callable in same transaction) is not detected.
- Proxy-to-implementation relationships are not modeled.

### No Storage Layout Model

- Cannot compute actual storage slot positions.
- Cannot detect proxy storage collisions between implementation versions.
- Cannot verify ERC-1967 slot compliance.

## Detector Limitations

### Body-Pattern Matching

Most detectors use string/regex matching on function body source code. This
means:

- Renaming a variable defeats detection.
- Wrapping a dangerous operation in a helper function defeats detection.
- Using an alias or intermediate variable defeats detection.
- Code split across multiple functions is invisible.

### Known False Negative Categories

Based on OWASP Smart Contract Top 10 (2026) and 2024-2026 exploit data:

| Category | Coverage | Gap |
|----------|----------|-----|
| SC01: Access Control | Minimal | No role/privilege model, no blast-radius analysis |
| SC02: Price Oracle | None | No oracle staleness, single-source, or TWAP checks |
| SC03: Flash Loan / Economic | None | No snapshot vs. live balance, no share-price manipulation |
| SC04: Reentrancy | Partial | Single-function only; cross-function and cross-contract missed |
| SC05: Input Validation | Partial | Missing zero-check only; no range, bounds, or semantic validation |
| SC06: Unchecked Returns | Good | Covered for calls and transfers |
| SC07: Frontrunning | None | No mempool-sensitive pattern detection |
| SC08: Denial of Service | Partial | Calls-in-loop only; no gas griefing or state bloat |
| SC09: Gas Optimization | None | Not a security category but requested |
| SC10: Upgradeability | Minimal | Missing-gap only; no slot collision, no initializer analysis |

### Known False Positive Sources

- `FLOATING_PRAGMA` fires on test files and scripts where pinning is unnecessary.
- `REENTRANCY` fires on functions with external calls + state writes even when
  the external call is to a trusted contract (e.g., WETH).
- `LOCKED_ETHER` fires on contracts that intentionally hold ETH (e.g., vaults).
- `UNUSED_RETURN` fires on intentionally-discarded returns.

## Architectural Acknowledgments

Sentinel's architecture (WorkspaceContext, Detector trait, project auto-detection)
is directly inspired by [Aderyn](https://github.com/Cyfrin/aderyn) (Cyfrin, GPL-3.0).
The detector taxonomy draws from [Slither](https://github.com/crytic/slither)
(Trail of Bits, AGPL-3.0) and the
[SWC Registry](https://swcregistry.io/). No code was copied from either project.

## What To Use Alongside Sentinel

| Need | Tool |
|------|------|
| Type-aware static analysis | [Slither](https://github.com/crytic/slither), [Aderyn](https://github.com/Cyfrin/aderyn) |
| Symbolic execution | [Halmos](https://github.com/a16z/halmos), [Kontrol](https://github.com/runtimeverification/kontrol) |
| Fuzz testing | [Foundry](https://book.getfoundry.sh/forge/fuzz-testing), [Echidna](https://github.com/crytic/echidna), [Medusa](https://github.com/crytic/medusa) |
| Formal verification | [Certora Prover](https://www.certora.com/) |
| Runtime monitoring | [Forta](https://forta.org/), [OpenZeppelin Defender](https://www.openzeppelin.com/defender) |
| Solana analysis | [Sec3 X-Ray](https://sec3.dev/) |
