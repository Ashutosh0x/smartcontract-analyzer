# Competitive Feature Matrix

This document provides a comprehensive comparison of **Sentinel** (our smart contract security analyzer) against major competitors and complementary tools in the Web3 security landscape.

## Key Differentiators for Sentinel

1. **Holistic Semantic Understanding**: Unlike Aderyn which relies on AST pattern matching, Sentinel builds a robust Intermediate Representation (IR) with Static Single Assignment (SSA), Control Flow Graphs (CFG), and full data-flow tracking in Rust, enabling Slither-level depth with Rust-level performance.
2. **Advanced Taint Analysis**: Built-in tracking of user-controlled inputs across complex call chains and state modifications, reducing false positives.
3. **DeFi-Specific Semantics**: Natively understands DeFi primitives (AMMs, lending pools, flash loans) to detect logic flaws that generic static analyzers miss.
4. **Modern Architecture**: Written entirely in Rust for maximum speed, enabling real-time IDE feedback and instant CI pipeline checks.
5. **Actionable Outputs**: Moves beyond simple detection to Exploitability Scoring and automated Proof of Concept (PoC) generation generation targets.

---

### Legend
- ✅ Full Support
- ⚡ Partial / Basic Support
- ❌ Not Supported
- 🔄 Via Integration / Plugin
- 🎯 Planned (Target Capability)

---

## Static Analysis Capabilities

| Feature | Sentinel | Slither | Aderyn | Mythril | Manticore | Foundry | Echidna | Semgrep | solc | CertiK |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **AST Parsing** | ✅ | ✅ | ✅ | ⚡ | ⚡ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Compiler Integration** | ✅ | ✅ | ✅ | ⚡ | ❌ | ✅ | ✅ | ⚡ | ✅ | ✅ |
| **IR / SSA** | ✅ | ✅ | ❌ | ⚡ | ⚡ | ❌ | ❌ | ❌ | ✅ | ✅ |
| **Control Flow Graph (CFG)** | ✅ | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ | ⚡ | ✅ | ✅ |
| **Call Graph** | ✅ | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ | ⚡ | ✅ | ✅ |
| **Inheritance Graph** | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| **Data-Flow Analysis** | ✅ | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ |
| **Taint Analysis** | ✅ | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ✅ |
| **State-Var Dependency** | ✅ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ⚡ | ❌ | ✅ |
| **Function Summaries** | ✅ | ✅ | ❌ | ⚡ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Authorization Analysis** | ✅ | ✅ | ⚡ | ⚡ | ❌ | ❌ | ❌ | ⚡ | ❌ | ✅ |
| **External-Call Analysis** | ✅ | ✅ | ⚡ | ✅ | ✅ | ❌ | ❌ | ⚡ | ❌ | ✅ |
| **Storage Analysis** | ✅ | ✅ | ❌ | ✅ | ❌ | ✅ | ❌ | ❌ | ✅ | ✅ |
| **Cross-Contract Analysis**| ✅ | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ⚡ | ✅ |

---

## Security Detection (Vulnerability Coverage)

| Feature | Sentinel | Slither | Aderyn | Mythril | Manticore | Foundry | Echidna | Semgrep | solc | CertiK |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Reentrancy (All Types)** | ✅ | ✅ | ⚡ | ✅ | ✅ | ❌ | 🔄 | ⚡ | ❌ | ✅ |
| **Access Control Flaws** | ✅ | ✅ | ✅ | ⚡ | ⚡ | ❌ | 🔄 | ✅ | ❌ | ✅ |
| **Arithmetic Over/Underflow**| ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | 🔄 | ⚡ | ✅ | ✅ |
| **Unchecked Return Values**| ✅ | ✅ | ✅ | ⚡ | ⚡ | ❌ | 🔄 | ✅ | ⚡ | ✅ |
| **Front-Running / MEV** | 🎯 | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Time Manipulation** | ✅ | ✅ | ✅ | ⚡ | ❌ | ❌ | ❌ | ⚡ | ❌ | ✅ |
| **Flash Loan Attacks** | 🎯 | ⚡ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Oracle Manipulation** | 🎯 | ⚡ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Signature Replay** | ✅ | ✅ | ⚡ | ❌ | ❌ | ❌ | ❌ | ⚡ | ❌ | ✅ |
| **Bad Randomness** | ✅ | ✅ | ✅ | ⚡ | ❌ | ❌ | ❌ | ⚡ | ❌ | ✅ |

---

## Dynamic Analysis

| Feature | Sentinel | Slither | Aderyn | Mythril | Manticore | Foundry | Echidna | Semgrep | solc | CertiK |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Fuzzing** | 🔄 | 🔄 | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ |
| **Invariant Testing** | 🔄 | 🔄 | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ |
| **Symbolic Execution** | 🎯 | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |
| **Concrete Execution** | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ |

---

## Reporting & Integration

| Feature | Sentinel | Slither | Aderyn | Mythril | Manticore | Foundry | Echidna | Semgrep | solc | CertiK |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Terminal / CLI Output** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| **Markdown Reports** | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **JSON Output** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SARIF Output** | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
| **GitHub Actions / CI/CD** | ✅ | ✅ | ✅ | ✅ | ⚡ | ✅ | ✅ | ✅ | ⚡ | 🔄 |
| **IDE Integration** | ✅ | ⚡ | ⚡ | ❌ | ❌ | ⚡ | ❌ | ✅ | ✅ | ❌ |
| **Custom Detector API** | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
| **Suppression / Baseline** | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |

---

## Advanced Features

| Feature | Sentinel | Slither | Aderyn | Mythril | Manticore | Foundry | Echidna | Semgrep | solc | CertiK |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Bytecode Analysis** | 🎯 | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ⚡ | ✅ |
| **Dependency Analysis** | ✅ | ✅ | ⚡ | ❌ | ❌ | ✅ | ❌ | ⚡ | ❌ | ✅ |
| **Upgradeability Analysis**| ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **DeFi Semantic Analysis** | 🎯 | ⚡ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Exploitability Scoring** | 🎯 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Attack Path Generation** | 🎯 | ❌ | ❌ | ⚡ | ⚡ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **PoC Generation** | 🎯 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **AI Integration** | 🎯 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |

