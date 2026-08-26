# Sentinel Custom Rule Schema

Sentinel allows security researchers and developers to define custom detectors using a structured YAML schema. This document outlines the schema, validation rules, and provides guidance for writing effective custom rules.

## Schema Definition

A custom rule must adhere to the following YAML structure:

```yaml
id: string (required)
name: string (required)
description: string (required)
category: enum (required)
severity: enum [CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL]
confidence: enum [HIGH, MEDIUM, LOW]
cwe: string[]
swc: string[]
eip: string[]
solidity_versions: string (semver range)
compiler_versions: string (semver range)
preconditions: string[]
signals: SignalSpec[]
anti_patterns: string[]
impact: string[]
recommendation: string[]
references: string[]
test_fixtures:
  vulnerable: string (path)
  safe: string (path)
  false_positive: string (path)
```

## Field Descriptions & Validation Rules

- **`id` (Required):** A unique identifier for the rule (e.g., `CUSTOM-REENTRANCY-01`). Must be alphanumeric with hyphens.
- **`name` (Required):** A concise, human-readable name for the vulnerability.
- **`description` (Required):** A detailed explanation of the vulnerability and how the detector identifies it.
- **`category` (Required):** Must be one of the predefined categories (e.g., `Reentrancy`, `Access Control`, `Oracle`).
- **`severity`:** Indicates the potential impact. Must be one of: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`.
- **`confidence`:** Indicates the likelihood of the finding being a true positive. Must be one of: `HIGH`, `MEDIUM`, `LOW`.
- **`cwe` / `swc` / `eip`:** Optional arrays of strings linking to relevant standards.
- **`solidity_versions` / `compiler_versions`:** Semver strings defining applicability (e.g., `>=0.8.0 <0.9.0`).
- **`preconditions`:** Conditions that must be met for the rule to trigger.
- **`signals`:** Array of `SignalSpec` objects defining AST patterns or data flow signals to match.
- **`anti_patterns`:** Known patterns that typically indicate the vulnerability.
- **`impact`:** Expected consequences if the vulnerability is exploited.
- **`recommendation`:** Steps to remediate the vulnerability.
- **`references`:** URLs or citations providing further context.
- **`test_fixtures`:** Paths to Solidity files used to test the rule's accuracy.

## Example Custom Rule

```yaml
id: UNPROTECTED-MINT-001
name: Unprotected Mint Function
description: Detects token minting functions that lack proper access control modifiers, allowing unauthorized token creation.
category: Access Control
severity: CRITICAL
confidence: HIGH
cwe:
  - CWE-284
swc: []
eip: []
solidity_versions: ">=0.4.0"
preconditions:
  - "Contract imports ERC20 or implements IERC20"
signals:
  - type: AST_MATCH
    pattern: "FunctionDefinition[name='mint'][modifiers=[]]"
impact:
  - "Attacker can mint arbitrary amounts of tokens, diluting value and stealing funds."
recommendation:
  - "Add access control modifiers such as `onlyOwner` or `onlyRole(MINTER_ROLE)` to the mint function."
references:
  - "https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/access-control/"
test_fixtures:
  vulnerable: "./tests/fixtures/unprotected_mint_vuln.sol"
  safe: "./tests/fixtures/unprotected_mint_safe.sol"
```

## Guidance for Writing Custom Detectors

1. **Start Specific:** Begin with strict preconditions and signals to minimize false positives, then generalize as needed.
2. **Leverage Existing Signals:** Use Sentinel's built-in AST parsing and data flow analysis signals rather than writing raw regex.
3. **Comprehensive Testing:** Always provide `vulnerable`, `safe`, and `false_positive` test fixtures to ensure the rule behaves as expected across different scenarios.
4. **Clear Recommendations:** Ensure the `recommendation` field provides actionable, secure code alternatives.
