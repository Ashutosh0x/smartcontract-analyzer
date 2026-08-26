# Smart Contract Security Patterns (2026 Edition)

A comprehensive guide to smart contract security patterns as of August 2026.

## Modern Vulnerability Patterns (2025-2026)

### EIP-1153 Transient Storage State Poisoning
- **Description**: With EIP-1153 (`TSTORE`/`TLOAD`), transient storage is cleared at the end of the transaction, not the call. If contracts don't properly clear transient storage after use, subsequent calls in the same transaction can read stale or maliciously crafted state.
- **Vulnerable Code**:
  ```solidity
  contract VulnerableLock {
      function lock() internal { require(uint256(tload(0)) == 0); tstore(0, 1); }
      function unlock() internal { /* forgot to clear in some paths */ }
  }
  ```
- **Attack Scenario**: Attacker exploits a path where `unlock` isn't called or state isn't reset, then calls another contract in the same transaction that relies on that transient state.
- **Secure Code**: Always reset transient storage to 0 at the end of the execution flow using `defer` patterns or strict try/finally blocks.
- **Detection**: Check if `tstore` is used without a guaranteed matching reset `tstore(x, 0)` in all execution branches.

### EIP-7702 Delegation-Based Account Hijacking
- **Description**: EIP-7702 allows EOAs to temporarily act as smart contracts. If an EOA delegates to a malicious or vulnerable contract, the attacker can hijack the EOA's state or assets.
- **Vulnerable Code**: N/A (Protocol level delegation)
- **Attack Scenario**: Phishing attacks trick users into signing a 7702 authorization tuple that points to a malicious implementation, granting full control over the EOA.
- **Secure Code**: Wallets must simulate and strictly whitelist delegation targets.
- **Detection**: Monitor EIP-7702 authorization signatures in transaction payloads.

### Asymmetric Rounding in Multi-Asset Pools (Balancer-style)
- **Description**: Precision loss in complex AMM pool math (e.g., Balancer weighted pools) during extreme market conditions or with tokens having different decimals.
- **Attack Scenario**: Attacker repeatedly deposits and withdraws tiny amounts, exploiting rounding down on protocol balances and rounding up on user shares.
- **Detection**: Fuzzing with extreme input ranges and differential testing against formal models.

### ERC-7579 Module Confusion Attacks
- **Description**: ERC-7579 modular smart accounts can be compromised if modules (validators, executors, fallbacks) have overlapping storage or misconfigured access controls.
- **Vulnerable Code**: Executor module altering state reserved for validators.
- **Attack Scenario**: Attacker installs a malicious module that bypasses the primary validator by abusing fallback functions.

### Cross-chain DVN Compromise Patterns
- **Description**: Decentralized Verifier Networks (like LayerZero v2) compromised or misconfigured to accept fraudulent cross-chain messages.
- **Attack Scenario**: Attacker compromises the configured DVN threshold, spoofing a massive deposit on a source chain and minting tokens on the destination chain.

### ERC-4626 Inflation/Donation Attacks (with OZ Virtual Shares Mitigation)
- **Description**: Classic vault inflation where an attacker donates assets to an empty vault, inflating the share price to cause rounding errors for subsequent depositors.
- **Secure Code**: Use OpenZeppelin's virtual shares offset.
  ```solidity
  // OZ mitigation automatically adds virtual assets and shares to prevent 1 wei exploits.
  ```

### Account Abstraction (ERC-4337) Bundler Griefing
- **Description**: Malicious paymasters or accounts that consume massive gas during validation but revert, grieving the bundler.

### L2 Sequencer Downtime Exploitation
- **Description**: Exploiting L2 oracle staleness during sequencer outages.

---

## Classic Patterns (Still Relevant)

### Reentrancy
- **Description**: Attacker re-enters a contract before state updates.
- **Detection**: Checks-Effects-Interactions pattern enforcement.

### Oracle Manipulation
- **Description**: Spot price manipulation via flash loans.
- **Secure Code**: Use TWAP or decentralized oracles (Chainlink) with staleness checks.

### Flash Loan Patterns
- **Description**: Borrowing massive liquidity to imbalance pools.

### Governance Attacks
- **Description**: Borrowing voting power to pass malicious proposals.

### Proxy/Upgrade Vulnerabilities
- **Description**: Uninitialized logic contracts, storage collisions.

### Signature Replay
- **Description**: Reusing signatures across transactions or chains (missing EIP-712 domain separators or nonces).

### Integer Overflow (Unchecked Blocks)
- **Description**: Using `unchecked` improperly for gas optimization leading to under/overflows.
