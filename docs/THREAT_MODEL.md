# Sentinel Threat Model

This document outlines the threat model for smart contracts analyzed by Sentinel. It provides a structured approach to understanding potential vulnerabilities, attackers, and mitigation strategies within the DeFi and web3 ecosystem.

## 1. Assets at Risk
- **Smart Contract Funds:** Ether, ERC20 tokens, NFTs, and other native or bridged assets held by the contract.
- **Governance Control:** Voting power, admin privileges, and the ability to execute arbitrary upgrades or parameter changes.
- **Oracle Data:** Price feeds, randomness, and cross-chain messaging data that drive contract logic.
- **User Balances:** Accounting state representing user deposits, rewards, and debt.
- **Protocol Reputation:** Trust in the system, which can be irreparably damaged by a hack or even a close call.

## 2. Threat Actors
- **External Attackers:** Anonymous actors seeking financial gain through exploits, flash loans, or market manipulation.
- **Insiders:** Rogue developers, compromised admin keys, or disgruntled team members with elevated privileges.
- **MEV Bots:** Automated searchers that exploit front-running, back-running, and sandwich attack opportunities for profit.
- **Flash Loan Attackers:** Actors who borrow massive capital to manipulate markets, exploit price discrepancies, or execute complex atomic attacks.
- **Governance Attackers:** Entities that accumulate or borrow sufficient voting power to pass malicious proposals.

## 3. Attack Surfaces
- **Public/External Functions:** Any function callable by external users or contracts.
- **Proxy Upgrade Paths:** The mechanism by which implementation contracts are updated.
- **Oracle Dependencies:** External data sources (e.g., Chainlink, Uniswap TWAP) relied upon for critical logic.
- **Bridge Messages:** Cross-chain communication channels and the logic handling inbound/outbound messages.
- **Admin Keys/Multisigs:** The wallets or contracts holding privileged roles (e.g., `owner`, `pauser`).

## 4. Attack Trees for Major Vulnerability Classes

### Reentrancy
1. Attacker calls vulnerable function.
2. Function transfers funds or interacts with attacker contract before updating state.
3. Attacker contract fallback/receive function is triggered.
4. Fallback function calls back into the vulnerable function.
5. State is manipulated, leading to unauthorized extraction of funds.

### Oracle Manipulation
1. Attacker identifies a contract relying on a spot price from a low-liquidity DEX.
2. Attacker uses a flash loan to drastically skew the ratio in the DEX pool.
3. Attacker interacts with the vulnerable contract, which reads the manipulated price.
4. Contract logic executes under false assumptions (e.g., under-collateralized borrowing).
5. Attacker repays flash loan and pockets the difference.

### Governance Takeover
1. Attacker acquires voting power (via flash loan or market purchase).
2. Attacker proposes a malicious upgrade or parameter change.
3. Attacker votes to approve the proposal.
4. Time lock (if any) expires.
5. Proposal is executed, transferring funds or control to the attacker.

### Proxy Exploitation
1. Implementation contract is left uninitialized.
2. Attacker calls `initialize()` on the implementation directly.
3. Attacker gains control of the implementation and potentially executes a `selfdestruct`.
4. Proxy is rendered useless, and funds may be locked or stolen.

## 5. Trust Boundaries in DeFi Protocols
- **User vs. Protocol:** Users interact with the protocol but should not be able to manipulate internal state beyond their own accounts.
- **Protocol vs. External Contracts:** The protocol interacts with other DeFi components (e.g., DEXs, lending pools) and must assume they can be malicious or compromised.
- **Protocol vs. Oracles:** The protocol trusts oracles for accurate data but must implement safeguards against manipulation or downtime.
- **Implementation vs. Proxy:** The proxy relies on the implementation for logic, while the implementation relies on the proxy's storage.

## 6. Threat Scenarios with Likelihood and Impact Ratings

| Scenario | Likelihood | Impact | Overall Risk |
| :--- | :---: | :---: | :---: |
| Reentrancy draining all funds | Medium | Critical | **High** |
| Flash loan oracle manipulation | High | Critical | **Critical** |
| Compromised admin private key | Low | Critical | **High** |
| Front-running user transactions | High | Medium | **High** |
| Uninitialized proxy implementation | Low | High | **Medium** |
| Denial of service via block gas limit | Medium | Low | **Low** |

## 7. Mitigation Strategies Mapped to Each Threat

| Threat | Mitigation Strategy |
| :--- | :--- |
| Reentrancy | Use Checks-Effects-Interactions pattern, `ReentrancyGuard`. |
| Oracle Manipulation | Use decentralized oracles (Chainlink), TWAP, multiple sources. |
| Admin Compromise | Use multi-sig wallets, timelocks, limit admin capabilities. |
| Flash Loans | Use internal accounting, delay critical actions across blocks. |
| Front-running/MEV | Implement slippage limits, commit-reveal schemes, MEV protection. |
| Proxy Exploitation | Ensure implementation is initialized, avoid `selfdestruct`. |
