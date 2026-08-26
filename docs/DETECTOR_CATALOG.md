# Sentinel Detector Catalog

This catalog outlines the planned detectors for the Sentinel smart contract security analyzer.

> **Note:** Due to the extensive list of 100+ planned detectors, this document highlights a representative selection across the 15 categories. The full implementation will include all detectors as specified in the rule schema.

## 1. Reentrancy

### REENTRANCY-001: Basic Reentrancy
- **Severity:** Critical
- **Confidence:** High
- **Description:** Detects state modifications after external calls, which can allow an attacker to re-enter the contract and manipulate state before it is updated.
- **Detection Approach:** Data flow analysis identifying state writes following an external call without a reentrancy guard.
- **CWE/SWC Mapping:** CWE-841, SWC-107
- **Example Vulnerable Code:**
  ```solidity
  function withdraw(uint amount) public {
      require(balances[msg.sender] >= amount);
      (bool success, ) = msg.sender.call{value: amount}("");
      require(success);
      balances[msg.sender] -= amount; // State update after call
  }
  ```
- **Example Safe Code:**
  ```solidity
  function withdraw(uint amount) public {
      require(balances[msg.sender] >= amount);
      balances[msg.sender] -= amount; // State update before call
      (bool success, ) = msg.sender.call{value: amount}("");
      require(success);
  }
  ```
- **Remediation:** Follow the Checks-Effects-Interactions pattern or use `ReentrancyGuard`.

## 2. Access Control

### ACCESS-001: Unprotected Selfdestruct
- **Severity:** Critical
- **Confidence:** High
- **Description:** The `selfdestruct` (or `suicide`) function is callable by anyone, allowing an attacker to destroy the contract and potentially steal funds.
- **Detection Approach:** AST traversal searching for `selfdestruct` calls not enclosed in access control modifiers (e.g., `onlyOwner`).
- **CWE/SWC Mapping:** CWE-284, SWC-106
- **Remediation:** Restrict access to authorized administrators only.

## 3. Arithmetic

### ARITH-001: Integer Overflow/Underflow (Pre-0.8.0)
- **Severity:** High
- **Confidence:** High
- **Description:** Arithmetic operations without overflow protection in Solidity versions < 0.8.0.
- **Detection Approach:** Version check combined with AST search for `+`, `-`, `*` without SafeMath.
- **CWE/SWC Mapping:** CWE-190, SWC-101
- **Remediation:** Use SafeMath library or upgrade to Solidity ^0.8.0.

## 4. Oracle

### ORACLE-001: Spot Price Manipulation
- **Severity:** Critical
- **Confidence:** Medium
- **Description:** Reliance on spot prices from low-liquidity AMMs (e.g., reading `getReserves()` directly) which are vulnerable to flash loan manipulation.
- **Detection Approach:** Identification of AMM interactions used directly in value calculations or logic branches.
- **Remediation:** Use decentralized oracles like Chainlink or TWAPs.

## 5. Proxy/Upgradeability

### PROXY-001: Uninitialized Implementation
- **Severity:** High
- **Confidence:** High
- **Description:** Proxy implementation contracts left uninitialized can be taken over by attackers.
- **Detection Approach:** Searching for missing `_disableInitializers()` in the constructor of implementation contracts.
- **Remediation:** Call `_disableInitializers()` in the implementation's constructor.

## 6. Token

### TOKEN-001: Fee-on-Transfer Token Incompatibility
- **Severity:** Medium
- **Confidence:** Low
- **Description:** Contract assumes the amount transferred out equals the amount received, which fails for fee-on-transfer tokens.
- **Detection Approach:** Analyzing state changes based on transfer amounts without checking balances before and after.
- **Remediation:** Calculate the actual amount received by comparing balances before and after the transfer.

## 7. Signature

### SIG-001: Signature Replay Attack
- **Severity:** High
- **Confidence:** High
- **Description:** Signatures can be reused across different transactions or contracts if nonces and chain IDs are not included.
- **Detection Approach:** Checking for `ecrecover` usage without validating a nonce and `block.chainid`.
- **Remediation:** Implement EIP-712 and track nonces.

## 8. DeFi/Economic

### DEFI-001: Flash Loan Attack Vulnerability
- **Severity:** Critical
- **Confidence:** Medium
- **Description:** Contract logic relies on single-block state that can be heavily skewed using flash loans.
- **Detection Approach:** Identifying critical calculations based on easily manipulable state variables within the same block.
- **Remediation:** Implement delay mechanisms, use TWAPs, or rely on robust external oracles.

## 9. Flash Loan

### FLASH-001: Unprotected Flash Loan Callback
- **Severity:** Critical
- **Confidence:** High
- **Description:** Flash loan callback functions that can be called by unauthorized addresses.
- **Detection Approach:** Checking access control on known flash loan callback signatures (e.g., `executeOperation`).
- **Remediation:** Ensure the callback is only accessible by the flash loan provider.

## 10. Compiler

### COMPILER-001: Outdated Compiler Version
- **Severity:** Informational
- **Confidence:** High
- **Description:** Using an outdated compiler version with known bugs.
- **Detection Approach:** Parsing the `pragma solidity` directive.
- **Remediation:** Upgrade to a recent, stable version of the Solidity compiler.

## 11. DoS/Gas

### DOS-001: Unbounded Loop
- **Severity:** Medium
- **Confidence:** Medium
- **Description:** Loops that iterate over dynamic arrays without limits can exceed the block gas limit, causing a Denial of Service.
- **Detection Approach:** Identifying `for` or `while` loops bound by dynamic array lengths or user input.
- **Remediation:** Implement pagination or bound the loop iterations.

## 12. Cross-Chain/L2

### XCHAIN-001: L2 Sequencer Downtime Unhandled
- **Severity:** Medium
- **Confidence:** Low
- **Description:** Failing to check the L2 sequencer status when relying on cross-chain data (e.g., Chainlink feeds on L2).
- **Detection Approach:** Checking if L2 oracle reads include a sequencer uptime check.
- **Remediation:** Integrate the Chainlink sequencer uptime feed.

## 13. MEV

### MEV-001: Lack of Slippage Protection
- **Severity:** High
- **Confidence:** High
- **Description:** Swaps or liquidations executed without minimum return parameters, making them vulnerable to sandwich attacks.
- **Detection Approach:** Identifying DEX router calls missing `amountOutMin` or similar parameters.
- **Remediation:** Always enforce strict slippage tolerance based on user input.

## 14. Governance

### GOV-001: Immediate Execution (No Timelock)
- **Severity:** Medium
- **Confidence:** High
- **Description:** Governance proposals that can be executed immediately upon passing, giving users no time to react.
- **Detection Approach:** Analyzing the execution flow of governance modules.
- **Remediation:** Implement a timelock delay for governance actions.

## 15. Dependencies

### DEP-001: Vulnerable Dependency
- **Severity:** High
- **Confidence:** High
- **Description:** Project depends on a package with known vulnerabilities (e.g., older OpenZeppelin contracts).
- **Detection Approach:** Analyzing package.json or similar dependency manifests against a vulnerability database.
- **Remediation:** Update dependencies to secure versions.
