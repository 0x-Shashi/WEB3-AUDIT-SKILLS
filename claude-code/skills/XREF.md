# Cross-Reference Index (XREF)

Master lookup table mapping vulnerabilities → patterns → exploits → fixes.

---

## How to Use XREF

This file is your **quick navigation tool**. When you encounter a vulnerability, exploit, or pattern name:

1. **Search for the term** (Ctrl+F)
2. **Find the row** in the table
3. **See all related resources** in one glance
4. **Load linked files** for details

---

## Quick Lookup Tables

### By Vulnerability Type

| Vulnerability | Severity | Pattern File | Anti-Pattern | Attack Tree | Real Exploit | Fix Priority |
|---------------|----------|--------------|--------------|-------------|--------------|--------------|
| **ORACLE VULNERABILITIES** |
| Spot Price Manipulation | Critical | [oracle-patterns.md#spot-price](patterns/oracle-patterns.md) | [oracle-anti-patterns.md#1](anti-patterns/oracle-anti-patterns.md) | [lending-tree [A2]](attack-trees/lending-attack-tree.md) | Harvest 2020 ($24M), Cream 2021 ($130M) | Immediate |
| Stale Oracle Price | High | [oracle-patterns.md#staleness](patterns/oracle-patterns.md) | [oracle-anti-patterns.md#2](anti-patterns/oracle-anti-patterns.md) | [lending-tree [A1]](attack-trees/lending-attack-tree.md) | Venus 2021, Inverse 2022 ($1.2M) | High |
| Zero/Negative Price | Critical | [oracle-patterns.md#validation](patterns/oracle-patterns.md) | [oracle-anti-patterns.md#3](anti-patterns/oracle-anti-patterns.md) | [lending-tree [A3][A4]](attack-trees/lending-attack-tree.md) | Venus 2021 | Immediate |
| Single Oracle (No Fallback) | Medium | [oracle-patterns.md#fallback](patterns/oracle-patterns.md) | [oracle-anti-patterns.md#4](anti-patterns/oracle-anti-patterns.md) | [lending-tree [A]](attack-trees/lending-attack-tree.md) | Synthetix 2020, bZx 2020 | Medium |
| LP Token Price via balanceOf | Critical | [defi-vault-patterns.md#lp-pricing](patterns/defi-vault-patterns.md) | [oracle-anti-patterns.md#5](anti-patterns/oracle-anti-patterns.md) | [lending-tree [A2]](attack-trees/lending-attack-tree.md) | Warp 2020 ($7.7M) | Immediate |
| Oracle tx.origin Auth | Medium | [access-control-patterns.md#tx-origin](patterns/access-control-patterns.md) | [oracle-anti-patterns.md#6](anti-patterns/oracle-anti-patterns.md) | - | - | Medium |
| No Oracle Deviation Check | High | [oracle-patterns.md#multi-oracle](patterns/oracle-patterns.md) | [oracle-anti-patterns.md#7](anti-patterns/oracle-anti-patterns.md) | [lending-tree [A5]](attack-trees/lending-attack-tree.md) | - | High |
| **ACCESS CONTROL** |
| Unprotected Initialize | Critical | [access-control-patterns.md#initialization](patterns/access-control-patterns.md) | [access-control-anti-patterns.md#1](anti-patterns/access-control-anti-patterns.md) | [lending-tree [F1]](attack-trees/lending-attack-tree.md), [bridge-tree [E2]](attack-trees/bridge-attack-tree.md) | Parity 2017 ($150M), Nomad 2022 ($190M) | Immediate |
| Missing Function Modifiers | Critical | [access-control-patterns.md#modifiers](patterns/access-control-patterns.md) | [access-control-anti-patterns.md#2](anti-patterns/access-control-anti-patterns.md) | [lending-tree [F2]](attack-trees/lending-attack-tree.md) | Poly Network 2021 ($610M) | Immediate |
| tx.origin Authentication | High | [access-control-patterns.md#tx-origin](patterns/access-control-patterns.md) | [access-control-anti-patterns.md#3](anti-patterns/access-control-anti-patterns.md) | [lending-tree [F3]](attack-trees/lending-attack-tree.md) | THORChain 2021 ($8M) | High |
| Inconsistent Access Control | Medium | [access-control-patterns.md#consistency](patterns/access-control-patterns.md) | [access-control-anti-patterns.md#4](anti-patterns/access-control-anti-patterns.md) | - | - | Medium |
| Hardcoded Validator Addresses | High | [bridge-patterns.md#validator-rotation](patterns/bridge-patterns.md) | [access-control-anti-patterns.md#5](anti-patterns/access-control-anti-patterns.md) | [bridge-tree [A5]](attack-trees/bridge-attack-tree.md) | Ronin 2022 ($625M) | High |
| No Timelock on Admin | High | [governance-patterns.md#timelock](patterns/governance-patterns.md) | [access-control-anti-patterns.md#6](anti-patterns/access-control-anti-patterns.md) | [dex-tree [G1]](attack-trees/dex-attack-tree.md) | Multiple rug pulls | High |
| Weak Modifier (Incomplete Check) | Critical | [access-control-patterns.md#modifiers](patterns/access-control-patterns.md) | [access-control-anti-patterns.md#7](anti-patterns/access-control-anti-patterns.md) | - | - | High |
| **REENTRANCY** |
| State After External Call | Critical | [reentrancy-patterns.md#cei](patterns/reentrancy-patterns.md) | [reentrancy-anti-patterns.md#1](anti-patterns/reentrancy-anti-patterns.md) | [lending-tree [D1]](attack-trees/lending-attack-tree.md) | The DAO 2016 ($60M), Lendf 2020 ($25M) | Immediate |
| Missing nonReentrant Guard | Critical | [reentrancy-patterns.md#guard](patterns/reentrancy-patterns.md) | [reentrancy-anti-patterns.md#2](anti-patterns/reentrancy-anti-patterns.md) | [lending-tree [D2]](attack-trees/lending-attack-tree.md) | Radiant 2024 ($4.5M) | Immediate |
| Read-Only Reentrancy | High | [reentrancy-patterns.md#read-only](patterns/reentrancy-patterns.md) | [reentrancy-anti-patterns.md#3](anti-patterns/reentrancy-anti-patterns.md) | [lending-tree [D3]](attack-trees/lending-attack-tree.md) | Sentiment 2023 ($1M) | High |
| ERC777 Callback Reentrancy | Critical | [token-patterns.md#erc777](patterns/token-patterns.md) | [reentrancy-anti-patterns.md#4](anti-patterns/reentrancy-anti-patterns.md) | [lending-tree [D4]](attack-trees/lending-attack-tree.md) | Lendf 2020 ($25M) | Immediate |
| Callback Parameter Reentrancy | High | [reentrancy-patterns.md#callback](patterns/reentrancy-patterns.md) | [reentrancy-anti-patterns.md#5](anti-patterns/reentrancy-anti-patterns.md) | - | - | High |
| Delegatecall Reentrancy | Critical | [delegatecall-patterns.md#reentrancy](patterns/delegatecall-patterns.md) | [reentrancy-anti-patterns.md#6](anti-patterns/reentrancy-anti-patterns.md) | - | - | High |
| Ignoring Transfer Return Value | Medium | [erc20-patterns.md#safe-transfer](patterns/erc20-patterns.md) | [reentrancy-anti-patterns.md#7](anti-patterns/reentrancy-anti-patterns.md) | - | - | Medium |
| **LENDING SPECIFIC** |
| First Depositor Attack | Critical | [defi-vault-patterns.md#first-depositor](patterns/defi-vault-patterns.md) | - | [lending-tree [C1]](attack-trees/lending-attack-tree.md), [vault-tree [A1]](attack-trees/vault-attack-tree.md) | Yearn 2023 ($11M) | Immediate |
| Self-Liquidation | High | [lending-pool-patterns.md#self-liquidation](patterns/lending-pool-patterns.md) | - | [lending-tree [B1]](attack-trees/lending-attack-tree.md) | - | High |
| Liquidation DoS | Critical | [dos-patterns.md#liquidation](patterns/dos-patterns.md) | - | [lending-tree [B2]](attack-trees/lending-attack-tree.md) | Euler 2023 ($197M) | Immediate |
| Flash Loan Governance | Critical | [governance-patterns.md#flash-loan-voting](patterns/governance-patterns.md) | - | [lending-tree [E1]](attack-trees/lending-attack-tree.md) | - | High |
| Interest Rate Manipulation | Medium | [lending-pool-patterns.md#interest-rate](patterns/lending-pool-patterns.md) | - | [lending-tree [C3]](attack-trees/lending-attack-tree.md) | - | Medium |
| **DEX/AMM SPECIFIC** |
| First LP Inflation Attack | Critical | [defi-vault-patterns.md#first-depositor](patterns/defi-vault-patterns.md) | - | [dex-tree [B1]](attack-trees/dex-attack-tree.md) | Multiple | Immediate |
| LP Token Reentrancy | Critical | [reentrancy-patterns.md#lp-tokens](patterns/reentrancy-patterns.md) | - | [dex-tree [B2]](attack-trees/dex-attack-tree.md) | - | Immediate |
| K-Value Manipulation | Critical | [dex-patterns.md#k-value](patterns/dex-patterns.md) | - | [dex-tree [C2]](attack-trees/dex-attack-tree.md) | - | Immediate |
| Fee-on-Transfer Token | High | [token-patterns.md#fee-on-transfer](patterns/token-patterns.md) | - | [dex-tree [C3]](attack-trees/dex-attack-tree.md) | Multiple | High |
| Flash Swap Reentrancy | Critical | [reentrancy-patterns.md#flash-swap](patterns/reentrancy-patterns.md) | - | [dex-tree [C5]](attack-trees/dex-attack-tree.md) | - | Immediate |
| Sandwich Attack | Medium | [mev-patterns.md#sandwich](patterns/mev-patterns.md) | - | [dex-tree [C1]](attack-trees/dex-attack-tree.md) | Constant MEV | Low |
| JIT Liquidity | Medium | [mev-patterns.md#jit-liquidity](patterns/mev-patterns.md) | - | [dex-tree [D2]](attack-trees/dex-attack-tree.md) | - | Low |
| **BRIDGE SPECIFIC** |
| Signature Replay | Critical | [signature-patterns.md#replay](patterns/signature-patterns.md) | - | [bridge-tree [A1]](attack-trees/bridge-attack-tree.md) | Multiple | Immediate |
| Cross-Chain Replay | Critical | [signature-patterns.md#chain-id](patterns/signature-patterns.md) | - | [bridge-tree [A2]](attack-trees/bridge-attack-tree.md) | - | Immediate |
| Signature Malleability | High | [signature-patterns.md#malleability](patterns/signature-patterns.md) | - | [bridge-tree [A3]](attack-trees/bridge-attack-tree.md) | - | High |
| Validator Threshold Too Low | Critical | [bridge-patterns.md#validator-threshold](patterns/bridge-patterns.md) | - | [bridge-tree [A4]](attack-trees/bridge-attack-tree.md) | - | Immediate |
| Validator Key Compromise | Critical | [bridge-patterns.md#key-management](patterns/bridge-patterns.md) | - | [bridge-tree [A5]](attack-trees/bridge-attack-tree.md) | Ronin 2022 ($625M), Harmony 2022 ($100M) | N/A (Operational) |
| Missing Signature Verification | Critical | [signature-patterns.md#verification](patterns/signature-patterns.md) | - | [bridge-tree [A6]](attack-trees/bridge-attack-tree.md) | Wormhole 2022 ($326M) | Immediate |
| Bridge Race Condition | Critical | [bridge-patterns.md#confirmation-depth](patterns/bridge-patterns.md) | - | [bridge-tree [B1]](attack-trees/bridge-attack-tree.md) | - | Immediate |
| Reorg Attack | High | [bridge-patterns.md#reorg-safety](patterns/bridge-patterns.md) | - | [bridge-tree [B2]](attack-trees/bridge-attack-tree.md) | - | High |
| Decimal Mismatch | Critical | [bridge-patterns.md#decimal-handling](patterns/bridge-patterns.md) | - | [bridge-tree [C5]](attack-trees/bridge-attack-tree.md) | Multiple edge cases | Immediate |
| Mint Without Lock | Critical | [bridge-patterns.md#mint-verification](patterns/bridge-patterns.md) | - | [bridge-tree [C1]](attack-trees/bridge-attack-tree.md) | - | Immediate |
| **VAULT SPECIFIC** |
| Donation Attack | High | [defi-vault-patterns.md#donation-attack](patterns/defi-vault-patterns.md) | - | [vault-tree [A2]](attack-trees/vault-attack-tree.md) | - | High |
| Rounding Down Attack | Medium | [erc4626-patterns.md#rounding](patterns/erc4626-patterns.md) | - | [vault-tree [A3]](attack-trees/vault-attack-tree.md) | - | Medium |
| Malicious Strategy | Critical | [strategy-patterns.md#validation](patterns/strategy-patterns.md) | - | [vault-tree [B2]](attack-trees/vault-attack-tree.md) | Rari 2022 ($80M) | Immediate |
| Strategy Reentrancy | Critical | [reentrancy-patterns.md#strategy](patterns/reentrancy-patterns.md) | - | [vault-tree [B1]](attack-trees/vault-attack-tree.md) | - | Immediate |
| ERC4626 Preview Mismatch | Medium | [erc4626-patterns.md#preview-accuracy](patterns/erc4626-patterns.md) | - | [vault-tree [E1]](attack-trees/vault-attack-tree.md) | - | Medium |
| Flash Loan Reward Farming | High | [flash-loan-patterns.md#reward-farming](patterns/flash-loan-patterns.md) | - | [vault-tree [H2]](attack-trees/vault-attack-tree.md) | Multiple | High |

---

## By Real Exploit

| Exploit Name | Year | Loss | Vulnerability | Pattern Reference | Anti-Pattern | Attack Tree |
|--------------|------|------|---------------|-------------------|--------------|-------------|
| **2023-2024** |
| Yearn Finance | 2023 | $11M | First depositor attack | [defi-vault-patterns.md#first-depositor](patterns/defi-vault-patterns.md) | - | [vault-tree [A1]](attack-trees/vault-attack-tree.md) |
| Radiant Capital | 2024 | $4.5M | Cross-function reentrancy | [reentrancy-patterns.md#cross-function](patterns/reentrancy-patterns.md) | - | [lending-tree [D2]](attack-trees/lending-attack-tree.md) |
| Sentiment | 2023 | $1M | Read-only reentrancy | [reentrancy-patterns.md#read-only](patterns/reentrancy-patterns.md) | [reentrancy-anti-patterns.md#3](anti-patterns/reentrancy-anti-patterns.md) | [lending-tree [D3]](attack-trees/lending-attack-tree.md) |
| Euler Finance | 2023 | $197M | Liquidation DoS | [dos-patterns.md#liquidation](patterns/dos-patterns.md) | - | [lending-tree [B2]](attack-trees/lending-attack-tree.md) |
| **2022** |
| Nomad Bridge | 2022 | $190M | Unprotected init | [access-control-patterns.md#initialization](patterns/access-control-patterns.md) | [access-control-anti-patterns.md#1](anti-patterns/access-control-anti-patterns.md) | [bridge-tree [E2]](attack-trees/bridge-attack-tree.md) |
| Ronin Bridge | 2022 | $625M | Validator key compromise | [bridge-patterns.md#key-management](patterns/bridge-patterns.md) | - | [bridge-tree [A5]](attack-trees/bridge-attack-tree.md) |
| Wormhole | 2022 | $326M | Missing signature verification | [signature-patterns.md#verification](patterns/signature-patterns.md) | - | [bridge-tree [A6]](attack-trees/bridge-attack-tree.md) |
| Harmony Horizon | 2022 | $100M | Validator key compromise | [bridge-patterns.md#key-management](patterns/bridge-patterns.md) | - | [bridge-tree [A5]](attack-trees/bridge-attack-tree.md) |
| Rari Capital | 2022 | $80M | Malicious strategy | [strategy-patterns.md#validation](patterns/strategy-patterns.md) | - | [vault-tree [B2]](attack-trees/vault-attack-tree.md) |
| Inverse Finance | 2022 | $1.2M | Stale oracle | [oracle-patterns.md#staleness](patterns/oracle-patterns.md) | [oracle-anti-patterns.md#2](anti-patterns/oracle-anti-patterns.md) | [lending-tree [A1]](attack-trees/lending-attack-tree.md) |
| **2021** |
| Poly Network | 2021 | $610M | Missing access control | [access-control-patterns.md#modifiers](patterns/access-control-patterns.md) | [access-control-anti-patterns.md#2](anti-patterns/access-control-anti-patterns.md) | [bridge-tree [E5]](attack-trees/bridge-attack-tree.md) |
| Cream Finance | 2021 | $130M | Spot price manipulation | [oracle-patterns.md#spot-price](patterns/oracle-patterns.md) | [oracle-anti-patterns.md#1](anti-patterns/oracle-anti-patterns.md) | [lending-tree [A2]](attack-trees/lending-attack-tree.md) |
| THORChain | 2021 | $8M | tx.origin auth | [access-control-patterns.md#tx-origin](patterns/access-control-patterns.md) | [access-control-anti-patterns.md#3](anti-patterns/access-control-anti-patterns.md) | - |
| Venus Protocol | 2021 | N/A | Stale price, zero price | [oracle-patterns.md#validation](patterns/oracle-patterns.md) | [oracle-anti-patterns.md#2,#3](anti-patterns/oracle-anti-patterns.md) | [lending-tree [A1][A3]](attack-trees/lending-attack-tree.md) |
| Grim Finance | 2021 | $30M | Reentrancy | [reentrancy-patterns.md#cei](patterns/reentrancy-patterns.md) | [reentrancy-anti-patterns.md#1](anti-patterns/reentrancy-anti-patterns.md) | - |
| Beefy Finance | 2021 | $11M | Strategy loss | [strategy-patterns.md#loss-cap](patterns/strategy-patterns.md) | - | [vault-tree [B3]](attack-trees/vault-attack-tree.md) |
| **2020** |
| Lendf.Me | 2020 | $25M | ERC777 reentrancy | [token-patterns.md#erc777](patterns/token-patterns.md) | [reentrancy-anti-patterns.md#4](anti-patterns/reentrancy-anti-patterns.md) | [lending-tree [D4]](attack-trees/lending-attack-tree.md) |
| Harvest Finance | 2020 | $24M | Spot price + arbitrage | [oracle-patterns.md#spot-price](patterns/oracle-patterns.md) | [oracle-anti-patterns.md#1](anti-patterns/oracle-anti-patterns.md) | [dex-tree [A1]](attack-trees/dex-attack-tree.md) |
| Warp Finance | 2020 | $7.7M | LP balanceOf pricing | [defi-vault-patterns.md#lp-pricing](patterns/defi-vault-patterns.md) | [oracle-anti-patterns.md#5](anti-patterns/oracle-anti-patterns.md) | [lending-tree [A2]](attack-trees/lending-attack-tree.md) |
| bZx | 2020 | $8M | Oracle manipulation | [oracle-patterns.md#manipulation](patterns/oracle-patterns.md) | - | - |
| Synthetix | 2020 | DoS | Oracle failure | - | [oracle-anti-patterns.md#4](anti-patterns/oracle-anti-patterns.md) | - |
| **2016-2017** |
| The DAO | 2016 | $60M | Classic reentrancy | [reentrancy-patterns.md#cei](patterns/reentrancy-patterns.md) | [reentrancy-anti-patterns.md#1](anti-patterns/reentrancy-anti-patterns.md) | [lending-tree [D1]](attack-trees/lending-attack-tree.md) |
| Parity Wallet | 2017 | $150M | Unprotected init | [access-control-patterns.md#initialization](patterns/access-control-patterns.md) | [access-control-anti-patterns.md#1](anti-patterns/access-control-anti-patterns.md) | - |

---

## By Protocol Type

### Lending Protocols

**Critical Vulnerabilities:**
- Oracle manipulation (spot price, stale, zero)
- First depositor attack
- Liquidation DoS
- Reentrancy (classic, cross-function, ERC777)
- Flash loan governance

**Primary References:**
- Attack Tree: [lending-attack-tree.md](attack-trees/lending-attack-tree.md)
- Patterns: [lending-pool-patterns.md](patterns/lending-pool-patterns.md)
- Checklist: [checklists/comprehensive-checklist.md](checklists/comprehensive-checklist.md)

---

### DEX/AMM

**Critical Vulnerabilities:**
- Spot price oracle
- First LP inflation
- K-value manipulation
- Flash swap reentrancy
- Fee-on-transfer tokens

**Primary References:**
- Attack Tree: [dex-attack-tree.md](attack-trees/dex-attack-tree.md)
- Patterns: [dex-patterns.md](patterns/dex-patterns.md)
- Anti-Patterns: [oracle-anti-patterns.md](anti-patterns/oracle-anti-patterns.md)

---

### Bridges

**Critical Vulnerabilities:**
- Signature replay/malleability
- Missing signature verification
- Validator compromise
- Unprotected initialization
- Decimal mismatch

**Primary References:**
- Attack Tree: [bridge-attack-tree.md](attack-trees/bridge-attack-tree.md)
- Patterns: [bridge-patterns.md](patterns/bridge-patterns.md), [signature-patterns.md](patterns/signature-patterns.md)
- Anti-Patterns: [access-control-anti-patterns.md](anti-patterns/access-control-anti-patterns.md)

---

### Vaults/Yield Aggregators

**Critical Vulnerabilities:**
- First depositor attack
- Malicious strategy
- Strategy reentrancy
- Donation attack
- Flash loan reward farming

**Primary References:**
- Attack Tree: [vault-attack-tree.md](attack-trees/vault-attack-tree.md)
- Patterns: [defi-vault-patterns.md](patterns/defi-vault-patterns.md), [erc4626-patterns.md](patterns/erc4626-patterns.md)
- Anti-Patterns: [reentrancy-anti-patterns.md](anti-patterns/reentrancy-anti-patterns.md)

---

## Quick Search

**For Auditors:**
```
"I found [vulnerability name]" → Search this file → See all references
```

**For Developers:**
```
"How do I prevent [attack]?" → Search this file → Pattern file link
```

**For Incident Response:**
```
"[Protocol] was exploited" → Search this file → See similar incidents
```

---

## Navigation Tips

1. **Use Ctrl+F** to find any term instantly
2. **Click links** to jump to detailed files
3. **Check "By Protocol Type"** for comprehensive coverage
4. **Reference "By Severity"** for prioritization

---

**Last Updated:** 2024
**Version:** 1.0
