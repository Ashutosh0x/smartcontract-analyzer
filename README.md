<p align="center">
  <img src="https://img.shields.io/badge/Sentinel-Smart_Contract_Security-blue?style=for-the-badge&labelColor=1a1a2e" alt="Sentinel" />
</p>

<h1 align="center">Sentinel</h1>
<h3 align="center">Rust-Native Smart Contract Security Analyzer</h3>

<p align="center">
  <strong>30 precision-tuned detectors | Zero-config on Foundry and Hardhat | Audit printers | SARIF output</strong>
</p>

<p align="center">
  <a href="#installation"><img src="https://img.shields.io/badge/Install-Guide-blue?style=flat-square" alt="Install" /></a>
  <a href="#usage"><img src="https://img.shields.io/badge/Usage-Docs-green?style=flat-square" alt="Usage" /></a>
  <a href="#detectors"><img src="https://img.shields.io/badge/Detectors-30-orange?style=flat-square" alt="Detectors" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow?style=flat-square" alt="License" /></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white" alt="Rust" />
  <img src="https://img.shields.io/badge/Solidity-363636?style=for-the-badge&logo=solidity&logoColor=white" alt="Solidity" />
  <img src="https://img.shields.io/badge/Ethereum-3C3C3D?style=for-the-badge&logo=ethereum&logoColor=white" alt="Ethereum" />
  <img src="https://img.shields.io/badge/GitHub_Actions-2088FF?style=for-the-badge&logo=github-actions&logoColor=white" alt="GitHub Actions" />
</p>

---

## What Sentinel Does

Sentinel is a **Rust-native** static security analyzer for Solidity smart contracts. It parses Solidity source code using [solang-parser](https://crates.io/crates/solang-parser), builds an indexed AST database (WorkspaceContext), and runs 30 precision-tuned detectors against it.

It runs **entirely locally** — your source code never leaves your machine.

### Design Principles

- **Precision over quantity** — 30 detectors with known-safe suppression, not 200 noisy rules
- **Zero configuration** — auto-detects Foundry (`foundry.toml`) and Hardhat (`hardhat.config`) projects
- **Confidence scoring** — every finding has both severity (Critical/High/Medium/Low) and confidence (High/Medium/Low)
- **Honest scope** — Sentinel does static analysis. For symbolic execution use [Halmos](https://github.com/a16z/halmos). For fuzzing use [Foundry](https://book.getfoundry.sh/forge/fuzz-testing) or [Echidna](https://github.com/crytic/echidna).

---

## Tech Stack

<table>
<tr>
<td align="center"><img src="https://cdn.simpleicons.org/rust/000000" width="40"/><br/><b>Rust</b><br/><sub>Core Engine</sub></td>
<td align="center"><img src="https://cdn.simpleicons.org/solidity/363636" width="40"/><br/><b>Solidity</b><br/><sub>Target Language</sub></td>
<td align="center"><img src="https://cdn.simpleicons.org/ethereum/3C3C3D" width="40"/><br/><b>Ethereum</b><br/><sub>EVM Analysis</sub></td>
<td align="center"><img src="https://cdn.simpleicons.org/githubactions/2088FF" width="40"/><br/><b>GitHub Actions</b><br/><sub>CI/CD</sub></td>
</tr>
</table>

| Crate | Purpose |
|-------|---------|
| `solang-parser` | Solidity AST parsing (LALRPOP-based, supports 0.8.x) |
| `clap` | CLI argument parsing |
| `serde` / `serde_json` | JSON, SARIF, config serialization |
| `walkdir` | Project file discovery |
| `regex` | Pattern matching in function bodies |
| `petgraph` | Graph structures for inheritance |
| `colored` / `comfy-table` | Terminal output |

---

## Installation

### From Source

```bash
git clone https://github.com/Ashutosh0x/smartcontract-analyzer.git
cd smartcontract-analyzer
cargo build --release
./target/release/sentinel --help
```

### Prerequisites

- **Rust** 1.75+ ([rustup](https://rustup.rs/))

---

## Usage

### Scan a Project

```bash
# Scan current directory (auto-detects Foundry/Hardhat)
sentinel scan

# Scan a specific path
sentinel scan /path/to/project

# JSON output
sentinel scan --json

# SARIF output (for GitHub Code Scanning)
sentinel scan --sarif --output results.sarif

# Markdown report
sentinel scan --markdown

# Filter by severity
sentinel scan --severity high
```

### List Detectors

```bash
sentinel list-detectors
```

### Audit Printers

Printers extract key structural information for manual audits:

```bash
# Inheritance graph (Mermaid diagram)
sentinel print inheritance

# All external/public functions with visibility and modifiers
sentinel print functions

# State variables with types, visibility, mutability
sentinel print state-vars

# External calls map (which functions call what)
sentinel print external-calls

# Access control map (who can call what, unrestricted functions highlighted)
sentinel print permissions
```

### CI/CD Integration

```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  sentinel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
      - name: Install Sentinel
        run: cargo install --git https://github.com/Ashutosh0x/smartcontract-analyzer
      - name: Scan
        run: sentinel scan --sarif --output results.sarif --severity medium
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

---

## Detectors

### Tier 1 — High Severity

| ID | Name | Description |
|----|------|-------------|
| REENT-01 | Reentrancy | State write after external call without `nonReentrant` guard |
| UNCHECKED-01 | Unchecked Call | Low-level `.call()` without checking return value |
| UNCHECKED-02 | Unchecked Transfer | ERC20 `.transfer()` / `.transferFrom()` without `SafeERC20` |
| TXORIGIN-01 | tx.origin Auth | `tx.origin` used for authentication |
| DESTRUCT-01 | Unsafe Selfdestruct | `selfdestruct` without access control |
| DELEGATECALL-01 | Arbitrary Delegatecall | `delegatecall` to user-controlled address |
| TRANSFER-01 | Arbitrary TransferFrom | `transferFrom` with user-supplied `from` address |
| UNINIT-01 | Uninitialized Storage | Local storage variable not initialized |
| SHADOW-01 | State Shadowing | State variable shadows parent contract |
| MSGVAL-01 | msg.value in Loop | `msg.value` used inside a loop |

### Tier 2 — Medium Severity

| ID | Name | Description |
|----|------|-------------|
| LOOP-01 | Calls in Loop | External calls inside loops (DoS risk) |
| PRECISION-01 | Division Before Multiply | `a / b * c` causes precision loss |
| ZERO-01 | Missing Zero Check | Constructor address param without zero-address check |
| LOCKED-01 | Locked Ether | Contract accepts ETH but has no withdrawal |
| RAND-01 | Block Randomness | `block.timestamp` / `blockhash` used as randomness |
| BALANCE-01 | Strict Balance | `address(this).balance ==` breaks with `selfdestruct` |
| PRAGMA-01 | Floating Pragma | Pragma with `^` or `>=` (not pinned) |
| CAST-01 | Unsafe Downcast | Integer downcast without bounds check |
| GAP-01 | Missing Gap | Upgradeable contract without `__gap` variable |
| VIS-01 | Default Visibility | Function missing explicit visibility |

### Tier 3 — Low / Informational

| ID | Name | Description |
|----|------|-------------|
| RETURN-01 | Unused Return | Function return value not captured |
| ENCODE-01 | Packed Encoding | `abi.encodePacked` with dynamic types (hash collision) |
| STRUCT-01 | Struct Delete | `delete` on struct containing mapping |
| PAYABLE-01 | Empty Payable | Empty receive/fallback traps ETH |
| UNICODE-01 | Unicode Override | Directional override characters |
| UNARY-01 | Unary Plus | `=+` likely typo for `+=` |
| ASM-01 | Assembly Return | `return()` in assembly instead of `leave` |
| SHIFT-01 | Swapped Shift | Assembly shift parameter order confusion |
| CTOR-01 | Multiple Constructors | More than one constructor |
| ENUM-01 | Enum Cast | Integer-to-enum cast without bounds check |

### Known-Safe Suppression

Detectors automatically suppress findings when recognized guards are present:

| Guard | Suppresses |
|-------|-----------|
| `nonReentrant` modifier | Reentrancy findings |
| `SafeERC20` / `safeTransfer` | Unchecked transfer findings |
| `onlyOwner` / `require(msg.sender ==` | Selfdestruct, access control |
| `msg.sender` check with `tx.origin` | tx.origin findings |
| Constructor/initializer with `initializer` modifier | Uninitialized findings |

---

## What Sentinel Does NOT Do

| Capability | Use Instead |
|-----------|-------------|
| Symbolic execution | [Halmos](https://github.com/a16z/halmos), [Kontrol](https://github.com/runtimeverification/kontrol) |
| Fuzz testing | [Foundry fuzz](https://book.getfoundry.sh/forge/fuzz-testing), [Echidna](https://github.com/crytic/echidna), [Medusa](https://github.com/crytic/medusa) |
| Formal verification | [Certora Prover](https://www.certora.com/), [Halmos](https://github.com/a16z/halmos) |
| Runtime monitoring | [Forta](https://forta.org/), [OpenZeppelin Defender](https://www.openzeppelin.com/defender) |
| Bytecode decompilation | [Dedaub](https://library.dedaub.com/), [Panoramix](https://github.com/palkeo/panoramix) |

---

## Architecture

```
src/
├── ast/          Solidity parsing via solang-parser
├── context/      WorkspaceContext — indexed AST database
├── compiler/     Project type detection (Foundry/Hardhat/Bare)
├── ingestion/    Zero-config project discovery
├── detectors/    30 detector implementations + registry
├── printers/     Audit printers (inheritance, functions, permissions)
├── reporting/    JSON, SARIF 2.1.0, Markdown, Terminal output
├── lib.rs        Orchestrator pipeline
└── main.rs       CLI (clap)
```

### How It Works

```
sentinel scan /path/to/project
        │
        ├── 1. Detect project type (Foundry/Hardhat/Bare)
        ├── 2. Discover .sol source files
        ├── 3. Parse each file with solang-parser → AST
        ├── 4. Build WorkspaceContext (indexed contracts, functions, vars)
        ├── 5. Run 30 detectors against WorkspaceContext
        ├── 6. Filter by severity, apply suppressions
        └── 7. Generate report (Terminal/JSON/SARIF/Markdown)
```

---

## Configuration (Optional)

Sentinel works zero-config, but you can override with `sentinel.toml`:

```toml
[project]
name = "MyProtocol"
src_paths = ["src", "contracts"]
exclude_paths = ["test", "script"]

[analysis]
severity_threshold = "medium"

[detectors]
disabled = ["PRAGMA-01"]
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).

---

<p align="center">
  <sub>Built with Rust | Solidity/EVM security analysis | 2026</sub>
</p>
