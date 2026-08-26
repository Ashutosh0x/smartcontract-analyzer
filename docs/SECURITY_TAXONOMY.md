# Security Taxonomy

This document maps Sentinel's internal detector IDs to standardized vulnerability classifications including CWE, SWC, and OWASP Smart Contract Top 10.

## 1. Reentrancy

| Detector ID | Description | CWE | SWC | OWASP |
|-------------|-------------|-----|-----|-------|
| REENTRANCY-001 | Classic Reentrancy | [CWE-841](https://cwe.mitre.org/data/definitions/841.html) | SWC-107 | SC01:2023 |
| REENTRANCY-002 | Cross-Function Reentrancy | CWE-841 | SWC-107 | SC01:2023 |
| REENTRANCY-003 | Read-Only Reentrancy | CWE-841 | SWC-107 | SC01:2023 |

## 2. Oracle & Price Manipulation

| Detector ID | Description | CWE | SWC | OWASP |
|-------------|-------------|-----|-----|-------|
| ORACLE-001 | Spot Price Manipulation | CWE-682 | N/A | SC09:2023 |
| ORACLE-002 | Stale Oracle Data | CWE-362 | N/A | SC09:2023 |
| ORACLE-003 | Decimal Mismatch | CWE-1339 | N/A | SC09:2023 |

## 3. Upgradability & Proxies

| Detector ID | Description | CWE | SWC | OWASP |
|-------------|-------------|-----|-----|-------|
| PROXY-001 | Uninitialized Implementation | CWE-459 | N/A | SC02:2023 |
| PROXY-002 | Storage Collision | CWE-119 | SWC-124 | SC02:2023 |
| PROXY-003 | UUPS Authorization Bypass | CWE-285 | N/A | SC02:2023 |

## 4. Tokens

| Detector ID | Description | CWE | SWC | OWASP |
|-------------|-------------|-----|-----|-------|
| TOKEN-001 | Fee-on-Transfer Support | CWE-682 | N/A | SC07:2023 |
| TOKEN-002 | ERC777 Hooks Reentrancy | CWE-841 | SWC-107 | SC01:2023 |
| TOKEN-003 | Missing SafeERC20 | CWE-754 | SWC-104 | SC08:2023 |

## 5. Accounting & Math

| Detector ID | Description | CWE | SWC | OWASP |
|-------------|-------------|-----|-----|-------|
| ACCOUNTING-001 | Share Inflation / Donation | CWE-682 | N/A | SC07:2023 |
| ACCOUNTING-002 | Precision Loss | CWE-1339| SWC-101 | SC07:2023 |

## 6. Signatures & Cryptography

| Detector ID | Description | CWE | SWC | OWASP |
|-------------|-------------|-----|-----|-------|
| SIGNATURE-001 | Signature Replay | CWE-294 | SWC-121 | SC03:2023 |
| SIGNATURE-002 | encodePacked Collision | CWE-295 | SWC-133 | SC03:2023 |
