<p align="center">
  <img src="https://img.shields.io/badge/Sentinel-Smart_Contract_Security-blue?style=for-the-badge&labelColor=1a1a2e" alt="Sentinel" />
</p>

<h1 align="center">Sentinel</h1>
<h3 align="center">Professional-Grade Smart Contract Security Analyzer</h3>

<p align="center">
  <strong>128 vulnerability rules | 28 test fixtures | Rust-native engine | Self-maintaining CI/CD</strong>
</p>

<p align="center">
  <a href="#installation"><img src="https://img.shields.io/badge/Install-Guide-blue?style=flat-square" alt="Install" /></a>
  <a href="#usage"><img src="https://img.shields.io/badge/Usage-Docs-green?style=flat-square" alt="Usage" /></a>
  <a href="docs/DETECTOR_CATALOG.md"><img src="https://img.shields.io/badge/Detectors-128-orange?style=flat-square" alt="Detectors" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow?style=flat-square" alt="License" /></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white" alt="Rust" />
  <img src="https://img.shields.io/badge/Solidity-363636?style=for-the-badge&logo=solidity&logoColor=white" alt="Solidity" />
  <img src="https://img.shields.io/badge/Ethereum-3C3C3D?style=for-the-badge&logo=ethereum&logoColor=white" alt="Ethereum" />
  <img src="https://img.shields.io/badge/GitHub_Actions-2088FF?style=for-the-badge&logo=github-actions&logoColor=white" alt="GitHub Actions" />
  <img src="https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker" />
  <img src="https://img.shields.io/badge/SARIF-0078D4?style=for-the-badge&logo=github&logoColor=white" alt="SARIF" />
</p>

---

## What is Sentinel?

Sentinel is a **Rust-native** static security analyzer for Solidity/EVM smart contracts designed to compete with and exceed the capabilities of leading tools like Slither, Aderyn, Mythril, and Olympix.

Unlike cloud-based analyzers, Sentinel runs **entirely locally** — your source code never leaves your machine.



---

## Tech Stack

<table>
<tr>
<td align="center"><img src="https://cdn.simpleicons.org/rust/000000" width="40"/><br/><b>Rust</b><br/><sub>Core Engine</sub></td>
<td align="center"><img src="https://cdn.simpleicons.org/solidity/363636" width="40"/><br/><b>Solidity</b><br/><sub>Target Language</sub></td>
<td align="center"><img src="https://cdn.simpleicons.org/ethereum/3C3C3D" width="40"/><br/><b>Ethereum</b><br/><sub>EVM Analysis</sub></td>
<td align="center"><img src="https://cdn.simpleicons.org/githubactions/2088FF" width="40"/><br/><b>GitHub Actions</b><br/><sub>CI/CD Pipeline</sub></td>
<td align="center"><img src="https://cdn.simpleicons.org/docker/2496ED" width="40"/><br/><b>Docker</b><br/><sub>Containerized</sub></td>
</tr>
</table>

### Rust Dependencies

| Crate | Purpose |
|-------|---------|
| `clap` | CLI argument parsing |
| `serde` / `serde_json` | Serialization (JSON, SARIF, config) |
| `tokio` | Async runtime |
| `rayon` | Parallel analysis |
| `petgraph` | CFG, call graph, inheritance graph |
| `tracing` | Structured logging |
| `semver` | Solidity version management |
| `walkdir` | Project file discovery |
| `toml` | Configuration parsing |
| `chrono` | Timestamps |
| `sha2` | Content hashing |
| `thiserror` / `anyhow` | Error handling |

---

## Installation

### From Source (Recommended)

```bash
# Clone the repository
git clone https://github.com/Ashutosh0x/smartcontract-analyzer.git
cd smartcontract-analyzer

# Build release binary
cargo build --release

# The binary is at target/release/sentinel
./target/release/sentinel --help
```

### Prerequisites

- **Rust** 1.75+ (install via [rustup](https://rustup.rs/))
- **solc** (optional, for compilation — install via [solc-select](https://github.com/crytic/solc-select))

### Docker

```bash
docker build -t sentinel .
docker run --rm -v $(pwd):/project sentinel scan /project
```

---

## Usage

### Quick Scan

```bash
# Scan current directory
sentinel scan

# Scan a specific project
sentinel scan /path/to/solidity/project

# Deep analysis (semantic + data-flow + taint)
sentinel scan --deep

# Maximum analysis (+ fuzzing hints, symbolic, exploit sim)
sentinel scan --max-mode
```

### Output Formats

```bash
# Terminal output (default — colored, human-readable)
sentinel scan

# JSON output
sentinel scan --json

# SARIF output (for GitHub Code Scanning)
sentinel scan --sarif -o results.sarif

# Markdown report
sentinel scan --markdown -o report.md
```

### Filter by Severity

```bash
# Only critical and high findings
sentinel scan --severity high

# Only critical findings
sentinel scan --severity critical
```

### Explore Detectors

```bash
# List all available detectors
sentinel list-detectors

# Explain a specific detector
sentinel explain REENTRANCY-001
```

### Differential Scanning

```bash
# Create a baseline
sentinel baseline create

# Scan only new findings (ignore known issues)
sentinel scan --baseline baseline.json

# Compare two revisions
sentinel diff HEAD~1 HEAD
```

### CI/CD Integration

```yaml
# .github/workflows/security.yml
name: Smart Contract Security
on: [push, pull_request]

jobs:
  sentinel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Sentinel
        run: cargo install --path .
      - name: Run Security Scan
        run: sentinel scan --sarif -o results.sarif --severity medium
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

---

## Vulnerability Coverage (128 Rules)

### By Category

| Category | Rules | Coverage |
|----------|-------|----------|
| **Upgradeability / Proxy** | 11 | UUPS, Transparent, Beacon, Diamond, ERC1967, storage collisions, __gap |
| **Gas / Denial of Service** | 10 | Calls in loop, msg.value reuse, locked ether, unbounded arrays |
| **Compiler Quirks** | 10 | Assembly return vs leave, ABI encoder, enum OOR, shift params |
| **Access Control** | 8 | Missing auth, tx.origin, unprotected init, centralization |
| **Code Quality** | 8 | Unicode RTL, floating pragma, unused returns, default visibility |
| **DeFi Economic** | 8 | Bad debt, share inflation, donation attack, slippage |
| **Oracle** | 8 | Spot price, stale data, sequencer, TWAP, decimal mismatch |
| **Token Compliance** | 8 | Fee-on-transfer, ERC4626 inflation, rebasing, ERC777 |
| **Signatures** | 8 | Replay, nonce, malleability, cross-chain, EIP-712 |
| **Reentrancy** | 6 | Classic, cross-function, cross-contract, read-only, EIP-1153, events |
| **Arithmetic** | 6 | Unsafe cast, precision loss, unchecked, rounding |
| **Cross-Chain / L2** | 6 | Address aliasing, sequencer, DVN trust, block assumptions |
| **Compiler Bugs** | 5 | Known solc bugs, via-IR, ABI encoder v2 |
| **Flash Loan** | 5 | Price manipulation, governance, donation, callbacks |
| **Governance** | 5 | Flash loan voting, timelock bypass, quorum manipulation |
| **2026 Exploit Patterns** | 5 | EIP-1153 poisoning, EIP-7702 hijacking, Cetus overflow |
| **Data Initialization** | 3 | Uninitialized storage, state vars, function pointers |
| **Shadowing** | 3 | State variable, builtin, reserved keyword |
| **Arbitrary Transfer** | 2 | transferFrom drain, ERC-2771+multicall spoof |
| **Randomness** | 1 | block.timestamp/blockhash misuse |
| **Division by Zero** | 1 | Unchecked divisor |
| **Self-Destruct** | 1 | Unprotected selfdestruct |

### Real-World Exploit Coverage (2025-2026)

| Exploit | Value | Pattern |
|---------|-------|---------|
| Cetus Protocol | \$223M | Concentrated liquidity integer overflow |
| KelpDAO | \$292M | DVN single-point compromise |
| Balancer | \$128M | Asymmetric rounding in multi-asset pools |
| SIR.trading | — | EIP-1153 transient storage poisoning |
| Pectra upgrade | — | EIP-7702 delegation hijacking |

---

## Project Structure

```
smartcontract-analyzer/
├── src/                             29 Rust files — core analysis engine
│   ├── lib.rs                       Sentinel orchestrator & pipeline
│   ├── main.rs                      CLI (clap) — scan/explain/diff/baseline
│   ├── ir/                          SentinelIR — SSA, types, instructions
│   ├── compiler/                    solc integration, project detection
│   ├── parser/                      Solidity AST parsing
│   ├── detectors/                   Detector trait, registry, built-in detectors
│   ├── analyses/                    CFG, data-flow, taint, call graph, storage
│   ├── reporting/                   JSON, SARIF 2.1.0, Markdown, Terminal
│   ├── defi/                        DeFi semantic analysis
│   ├── exploit/                     Exploitability scoring
│   └── ...                          bytecode, symbolic, fuzzing, integrations
│
├── rules/                           22 YAML files — 128 security rules
│   ├── solidity/                    Reentrancy, access, arithmetic, gas, quality
│   ├── defi/                        Oracle, flash-loan, economic
│   ├── proxy/                       Upgradeability (11 rules)
│   └── ...                          signatures, erc, compiler, bridge, governance
│
├── tests/fixtures/                  28 Solidity contracts
│   ├── vulnerable/                  27 vulnerable contracts
│   └── safe/                        1 fixed contract
│
├── knowledge/                       Compiler bugs, opcodes, exploits, standards
├── .github/workflows/               12 CI/CD workflows
└── docs/                            Architecture, threat model, detector catalog
```

---

## Self-Maintaining Pipeline

Sentinel includes **12 GitHub Actions workflows** that keep the analyzer continuously updated:

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | Push/PR | Build, test, lint (multi-platform) |
| `update-solidity.yml` | Weekly | Detect new Solidity versions |
| `update-compiler-bugs.yml` | Daily | Sync compiler bug database |
| `update-rules.yml` | On push to rules/ | Validate rule changes |
| `update-dependencies.yml` | Weekly | cargo update + audit |
| `security-audit.yml` | Daily + PR | cargo audit + cargo deny |
| `regression.yml` | PR | Detector regression tests |
| `benchmark.yml` | PR | Performance + precision benchmarks |
| `fuzz.yml` | Nightly | Fuzzing with cargo-fuzz |
| `release.yml` | Tag (v*) | Cross-platform release + Docker |
| `nightly.yml` | Nightly | Full regression + security report |
| `dependabot.yml` | Weekly | Automated dependency PRs |

### Update Flow

```
New Vulnerability  -->  Rule Added  -->  Tests Pass  -->  PR  -->  Review  -->  Release
New Solidity Version  -->  Detected  -->  Tested  -->  PR  -->  Review  -->  Release
Rust Advisory  -->  Dependency Updated  -->  Tested  -->  PR  -->  Review  -->  Release
```

---

## Configuration

Create `sentinel.toml` in your project root:

```toml
[project]
name = "MyProtocol"
src_paths = ["src", "contracts"]
exclude_paths = ["test", "script", "lib"]

[analysis]
max_depth = 10
timeout_seconds = 300
severity_threshold = "low"

[detectors]
disabled = ["QUALITY-002"]  # Disable specific detectors

[output]
format = "terminal"  # terminal, json, sarif, markdown
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on:

- Adding new detectors (Rust or YAML rules)
- Adding test fixtures
- Running the test suite
- Submitting security findings

---

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

## Links

- [Architecture](ARCHITECTURE.md) — Full pipeline design with Mermaid diagrams
- [Detector Catalog](docs/DETECTOR_CATALOG.md) — All 128+ detector descriptions
- [Threat Model](docs/THREAT_MODEL.md) — Security threat model
- [Competitive Matrix](docs/COMPETITIVE_FEATURE_MATRIX.md) — vs Slither, Aderyn, Mythril, Olympix
- [Security Policy](SECURITY.md) — Responsible disclosure

---

<p align="center">
  <sub>Built with Rust | Designed for Solidity/EVM security | August 2026</sub>
</p>
