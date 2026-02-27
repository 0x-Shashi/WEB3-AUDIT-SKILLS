# Cross-Reference Index (XREF)

Master lookup table mapping vulnerabilities → patterns → exploits → fixes.

---

## Table of Contents

- [How to Use XREF](#how-to-use-xref)
- [Quick Lookup Tables](#quick-lookup-tables)
  - [By Vulnerability Type](#by-vulnerability-type)
    - Oracle Vulnerabilities
    - Access Control
    - Reentrancy
    - Lending Specific
    - DEX/AMM Specific
    - Bridge Specific
    - Vault Specific
    - Governance Specific
    - Stablecoin Specific
    - NFT Lending Specific
    - Liquid Staking Specific
    - Perpetuals Specific
    - Options Specific
    - Intent-Based DEX Specific
    - Insurance Protocol Specific
    - Math/Precision Specific
    - Signature/Cryptography Specific
    - Token Handling
    - Flash Loan Attacks
    - Solana Program Specific
    - Solana Confidential Transfer
- [By Real Exploit](#by-real-exploit)
  - 2023-2024 Exploits
  - 2022 Exploits
  - 2021 Exploits
  - 2020 Exploits
  - 2016-2017 Exploits
- [By Protocol Type](#by-protocol-type)
  - [Lending Protocols](#lending-protocols)
  - [DEX/AMM](#dexamm)
  - [Bridges](#bridges)
  - [Vaults/Yield Aggregators](#vaultsyield-aggregators)
  - [Governance/DAOs](#governancedaos)
  - [Stablecoins](#stablecoins)
  - [NFT Lending](#nft-lending)
  - [Liquid Staking](#liquid-staking-new)
  - [Perpetuals](#perpetuals-new)
  - [Options](#options-new)
  - [Intent-Based DEX](#intent-based-dex-new)
  - [Insurance Protocols](#insurance-protocols-new)
  - [Solana Programs](#solana-programs-new)
- [Methodology Templates](#methodology-templates-new)
- [Cross-Chain Reference](#cross-chain-reference)
- [Quick Search](#quick-search)
- [Navigation Tips](#navigation-tips)

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
| **GOVERNANCE SPECIFIC** |
| Flash Loan Governance Voting | Critical | [governance-patterns.md#flash-loan-voting](patterns/governance-patterns.md) | [governance-anti-patterns.md#2](anti-patterns/governance-anti-patterns.md) | [governance-tree [A1]](attack-trees/governance-attack-tree.md) | Beanstalk 2022 ($182M) | Immediate |
| No Timelock on Critical Changes | Critical | [governance-patterns.md#timelock](patterns/governance-patterns.md) | [governance-anti-patterns.md#1](anti-patterns/governance-anti-patterns.md) | [governance-tree [C]](attack-trees/governance-attack-tree.md) | Tornado Cash 2023 | Immediate |
| Low Quorum Requirements | High | [governance-patterns.md#quorum](patterns/governance-patterns.md) | [governance-anti-patterns.md#3](anti-patterns/governance-anti-patterns.md) | [governance-tree [D]](attack-trees/governance-attack-tree.md) | Multiple DAOs | High |
| Proposal Spam DoS | Medium | [governance-patterns.md#proposal-threshold](patterns/governance-patterns.md) | [governance-anti-patterns.md#4](anti-patterns/governance-anti-patterns.md) | [governance-tree [B3]](attack-trees/governance-attack-tree.md) | - | Medium |
| Hidden Malicious Code in Proposal | Critical | [governance-patterns.md#transparency](patterns/governance-patterns.md) | [governance-anti-patterns.md#5](anti-patterns/governance-anti-patterns.md) | [governance-tree [E1]](attack-trees/governance-attack-tree.md) | Tornado Cash 2023 | Immediate |
| Vote Buying Off-Chain | High | [governance-patterns.md#vote-integrity](patterns/governance-patterns.md) | [governance-anti-patterns.md#6](anti-patterns/governance-anti-patterns.md) | [governance-tree [A5]](attack-trees/governance-attack-tree.md) | Curve Wars | Medium |
| Arbitrary Call in Governance | Critical | [governance-patterns.md#function-whitelist](patterns/governance-patterns.md) | [governance-anti-patterns.md#7](anti-patterns/governance-anti-patterns.md) | [governance-tree [E3]](attack-trees/governance-attack-tree.md) | Multiple protocols | Immediate |
| **STABLECOIN SPECIFIC** |
| Death Spiral (Algorithmic) | Critical | [stablecoin-patterns.md#death-spiral](patterns/stablecoin-patterns.md) | - | [stablecoin-tree [A1]](attack-trees/stablecoin-attack-tree.md) | Terra/Luna 2022 ($40B) | N/A (Design) |
| Bank Run on Collateral | High | [stablecoin-patterns.md#bank-run](patterns/stablecoin-patterns.md) | - | [stablecoin-tree [A2]](attack-trees/stablecoin-attack-tree.md) | USDC Depeg 2023 | High |
| Stablecoin Oracle Manipulation | Critical | [oracle-patterns.md#stablecoin](patterns/oracle-patterns.md) | - | [stablecoin-tree [A3]](attack-trees/stablecoin-attack-tree.md) | - | Immediate |
| Reserve Accounting Error | Critical | [stablecoin-patterns.md#reserve-accounting](patterns/stablecoin-patterns.md) | - | [stablecoin-tree [B1]](attack-trees/stablecoin-attack-tree.md) | Beanstalk 2022 (partial) | Immediate |
| Infinite Minting | Critical | [stablecoin-patterns.md#infinite-mint](patterns/stablecoin-patterns.md) | - | [stablecoin-tree [C1]](attack-trees/stablecoin-attack-tree.md) | - | Immediate |
| Cascade Liquidation | Critical | [lending-pool-patterns.md#liquidation-cascade](patterns/lending-pool-patterns.md) | - | [stablecoin-tree [E1]](attack-trees/stablecoin-attack-tree.md) | - | Immediate |
| Stablecoin Governance Attack | High | [governance-patterns.md#stablecoin](patterns/governance-patterns.md) | - | [stablecoin-tree [F1]](attack-trees/stablecoin-attack-tree.md) | - | High |
| **NFT LENDING SPECIFIC** |
| NFT Floor Price Manipulation | Critical | [oracle-patterns.md#nft-floor](patterns/oracle-patterns.md) | - | [nft-tree [A1]](attack-trees/nft-lending-attack-tree.md) | JPEG'd 2023 ($11.6M) | Immediate |
| Wash Trading Valuation | High | [nft-patterns.md#wash-trading](patterns/nft-patterns.md) | - | [nft-tree [A2]](attack-trees/nft-lending-attack-tree.md) | Wasabi 2023 | High |
| NFT Metadata Mutation | Critical | [nft-patterns.md#metadata-mutation](patterns/nft-patterns.md) | - | [nft-tree [B1]](attack-trees/nft-lending-attack-tree.md) | - | Immediate |
| Counterfeit NFT Deposit | Critical | [nft-patterns.md#counterfeit](patterns/nft-patterns.md) | - | [nft-tree [D1]](attack-trees/nft-lending-attack-tree.md) | - | Immediate |
| Malicious NFT Contract | Critical | [nft-patterns.md#malicious-contract](patterns/nft-patterns.md) | - | [nft-tree [D2]](attack-trees/nft-lending-attack-tree.md) | - | Immediate |
| NFT Liquidation Front-Running | Medium | [mev-patterns.md#nft-liquidation](patterns/mev-patterns.md) | - | [nft-tree [C1]](attack-trees/nft-lending-attack-tree.md) | - | Medium |
| NFT Pool Drain | Critical | [nft-patterns.md#pool-drain](patterns/nft-patterns.md) | - | [nft-tree [F1]](attack-trees/nft-lending-attack-tree.md) | - | Immediate |
| **LIQUID STAKING SPECIFIC** |
| Exchange Rate Oracle Attack | Critical | [oracle-patterns.md#exchange-rate](patterns/oracle-patterns.md) | - | [liquid-staking-tree [A1]](attack-trees/liquid-staking-attack-tree.md) | Lido 2023 (caught) | Immediate |
| Withdrawal Queue Manipulation | High | [withdrawal-patterns.md#queue](patterns/withdrawal-patterns.md) | - | [liquid-staking-tree [B1]](attack-trees/liquid-staking-attack-tree.md) | stETH Depeg 2022 | High |
| Malicious Validator Registration | Critical | [staking-patterns.md#validator-registration](patterns/staking-patterns.md) | - | [liquid-staking-tree [C1]](attack-trees/liquid-staking-attack-tree.md) | - | Immediate |
| Slashing Event Exploitation | High | [staking-patterns.md#slashing](patterns/staking-patterns.md) | - | [liquid-staking-tree [C2]](attack-trees/liquid-staking-attack-tree.md) | - | High |
| Rebasing Token Accounting | Critical | [token-patterns.md#rebasing](patterns/token-patterns.md) | - | [liquid-staking-tree [D1]](attack-trees/liquid-staking-attack-tree.md) | Multiple | Immediate |
| Reward Timing Manipulation | Medium | [staking-patterns.md#reward-timing](patterns/staking-patterns.md) | - | [liquid-staking-tree [E1]](attack-trees/liquid-staking-attack-tree.md) | - | Medium |
| Restaking Double-Count | Critical | [restaking-patterns.md#double-count](patterns/restaking-patterns.md) | - | [liquid-staking-tree [G3]](attack-trees/liquid-staking-attack-tree.md) | - | Immediate |
| **PERPETUALS SPECIFIC** |
| Index Price Manipulation | Critical | [oracle-patterns.md#index-price](patterns/oracle-patterns.md) | - | [perpetuals-tree [A1]](attack-trees/perpetuals-attack-tree.md) | Mango Markets 2022 ($114M) | Immediate |
| Funding Rate Manipulation | High | [perpetuals-patterns.md#funding-manipulation](patterns/perpetuals-patterns.md) | - | [perpetuals-tree [B1]](attack-trees/perpetuals-attack-tree.md) | Perp Protocol 2022 ($1M+) | High |
| Forced Liquidation Attack | Critical | [liquidation-patterns.md#forced](patterns/liquidation-patterns.md) | - | [perpetuals-tree [C1]](attack-trees/perpetuals-attack-tree.md) | Mango Markets 2022 | Immediate |
| Liquidation Cascade | Critical | [liquidation-patterns.md#cascade](patterns/liquidation-patterns.md) | - | [perpetuals-tree [C2]](attack-trees/perpetuals-attack-tree.md) | - | Immediate |
| Position Size Manipulation | Critical | [perpetuals-patterns.md#position-limits](patterns/perpetuals-patterns.md) | - | [perpetuals-tree [D1]](attack-trees/perpetuals-attack-tree.md) | Mango Markets 2022 | Immediate |
| LP Token Extraction | Critical | [perpetuals-patterns.md#lp-extraction](patterns/perpetuals-patterns.md) | - | [perpetuals-tree [E2]](attack-trees/perpetuals-attack-tree.md) | GMX 2022 ($565K) | Immediate |
| Insurance Fund Drain | Critical | [perpetuals-patterns.md#insurance](patterns/perpetuals-patterns.md) | - | [perpetuals-tree [G1]](attack-trees/perpetuals-attack-tree.md) | - | Immediate |
| **OPTIONS SPECIFIC** |
| Underlying Price Manipulation | Critical | [oracle-patterns.md#spot-price](patterns/oracle-patterns.md) | - | [options-tree [A1]](attack-trees/options-attack-tree.md) | - | Immediate |
| IV Manipulation | High | [options-patterns.md#iv-manipulation](patterns/options-patterns.md) | - | [options-tree [A2]](attack-trees/options-attack-tree.md) | Hegic 2021 | High |
| Settlement Price Manipulation | Critical | [options-patterns.md#settlement-price](patterns/options-patterns.md) | - | [options-tree [B2]](attack-trees/options-attack-tree.md) | - | Immediate |
| Vault Share Inflation | Critical | [vault-patterns.md#share-inflation](patterns/vault-patterns.md) | - | [options-tree [C1]](attack-trees/options-attack-tree.md) | - | Immediate |
| Exercise Timing Attack | High | [options-patterns.md#exercise-timing](patterns/options-patterns.md) | - | [options-tree [B1]](attack-trees/options-attack-tree.md) | Opyn 2020 ($371K) | High |
| Strategy Gaming (DOV) | High | [options-patterns.md#strategy-gaming](patterns/options-patterns.md) | - | [options-tree [C5]](attack-trees/options-attack-tree.md) | Ribbon 2022 | High |
| Gamma Squeeze | High | [options-patterns.md#gamma-squeeze](patterns/options-patterns.md) | - | [options-tree [D2]](attack-trees/options-attack-tree.md) | - | High |
| **INTENT-BASED DEX SPECIFIC** |
| Solver Sandwich Attack | Critical | [intent-patterns.md#solver-mev](patterns/intent-patterns.md) | - | [intent-tree [A1]](attack-trees/intent-based-attack-tree.md) | CoW Protocol 2023 | Immediate |
| Solver Collusion | High | [intent-patterns.md#solver-collusion](patterns/intent-patterns.md) | - | [intent-tree [A3]](attack-trees/intent-based-attack-tree.md) | - | High |
| Intent Signature Replay | Critical | [signature-patterns.md#replay](patterns/signature-patterns.md) | [signature-anti-patterns.md#SIG-AP-16](anti-patterns/signature-anti-patterns.md) | [intent-tree [B1]](attack-trees/intent-based-attack-tree.md) | - | Immediate |
| Permit2 Allowance Drain | Critical | [permit-patterns.md#permit2](patterns/permit-patterns.md) | [signature-anti-patterns.md#SIG-AP-24](anti-patterns/signature-anti-patterns.md) | [intent-tree [B5]](attack-trees/intent-based-attack-tree.md) | Socket Bridge 2024 ($3.3M) | Immediate |
| Order Validation Bypass | Critical | [intent-patterns.md#order-validation](patterns/intent-patterns.md) | - | [intent-tree [C1]](attack-trees/intent-based-attack-tree.md) | - | Immediate |
| Dutch Auction Gaming | High | [intent-patterns.md#dutch-auction](patterns/intent-patterns.md) | - | [intent-tree [E1]](attack-trees/intent-based-attack-tree.md) | - | High |
| Cross-Chain Intent Replay | Critical | [bridge-patterns.md#cross-chain](patterns/bridge-patterns.md) | [signature-anti-patterns.md#SIG-AP-18](anti-patterns/signature-anti-patterns.md) | [intent-tree [F2]](attack-trees/intent-based-attack-tree.md) | - | Immediate |
| **INSURANCE PROTOCOL SPECIFIC** |
| Front-Run Exploit with Cover | Critical | [insurance-patterns.md#cover-timing](patterns/insurance-patterns.md) | - | [insurance-tree [A1]](attack-trees/insurance-attack-tree.md) | - | Immediate |
| Cover Stacking Attack | High | [insurance-patterns.md#cover-stacking](patterns/insurance-patterns.md) | - | [insurance-tree [A4]](attack-trees/insurance-attack-tree.md) | - | High |
| Fraudulent Claims Attack | Critical | [insurance-patterns.md#claims-validation](patterns/insurance-patterns.md) | - | [insurance-tree [B1]](attack-trees/insurance-attack-tree.md) | - | Immediate |
| Parametric Trigger Manipulation | Critical | [oracle-patterns.md#parametric](patterns/oracle-patterns.md) | - | [insurance-tree [B5]](attack-trees/insurance-attack-tree.md) | - | Immediate |
| Capital Pool Drain | Critical | [insurance-patterns.md#capital-pool](patterns/insurance-patterns.md) | - | [insurance-tree [C1]](attack-trees/insurance-attack-tree.md) | Cover Protocol 2020 | Immediate |
| NXM Token Manipulation | High | [insurance-patterns.md#token-economics](patterns/insurance-patterns.md) | - | [insurance-tree [F1]](attack-trees/insurance-attack-tree.md) | - | High |
| **VAULT-SPECIFIC (EXPANDED)** |
| First Depositor Inflation | Critical | [vault-patterns.md#first-depositor](patterns/vault-patterns.md) | [vault-anti-patterns.md#VAULT-AP-01](anti-patterns/vault-specific-anti-patterns.md) | [vault-tree [A1]](attack-trees/vault-attack-tree.md) | Yearn 2023 ($11M) | Immediate |
| Rounding Direction Exploit | High | [erc4626-patterns.md#rounding](patterns/erc4626-patterns.md) | [vault-anti-patterns.md#VAULT-AP-02](anti-patterns/vault-specific-anti-patterns.md) | [vault-tree [A3]](attack-trees/vault-attack-tree.md) | - | High |
| Harvest Sandwich Attack | Critical | [mev-patterns.md#harvest](patterns/mev-patterns.md) | [vault-anti-patterns.md#VAULT-AP-17](anti-patterns/vault-specific-anti-patterns.md) | [vault-tree [C2]](attack-trees/vault-attack-tree.md) | - | Immediate |
| Fee-on-Transfer Vault Accounting | High | [token-patterns.md#fee-on-transfer](patterns/token-patterns.md) | [vault-anti-patterns.md#VAULT-AP-14](anti-patterns/vault-specific-anti-patterns.md) | - | Multiple | High |
| Strategy Migration Vulnerability | High | [strategy-patterns.md#migration](patterns/strategy-patterns.md) | [vault-anti-patterns.md#VAULT-AP-37](anti-patterns/vault-specific-anti-patterns.md) | [vault-tree [B4]](attack-trees/vault-attack-tree.md) | - | High |
| **MATH/PRECISION SPECIFIC** |
| Unchecked Block Overflow | Critical | [arithmetic-patterns.md#unchecked](patterns/arithmetic-patterns.md) | [math-anti-patterns.md#MATH-AP-01](anti-patterns/math-precision-anti-patterns.md) | - | Multiple 2022-2023 | Immediate |
| Division Before Multiplication | High | [arithmetic-patterns.md#order](patterns/arithmetic-patterns.md) | [math-anti-patterns.md#MATH-AP-17](anti-patterns/math-precision-anti-patterns.md) | - | - | High |
| Incorrect Rounding Direction | High | [arithmetic-patterns.md#rounding](patterns/arithmetic-patterns.md) | [math-anti-patterns.md#MATH-AP-09](anti-patterns/math-precision-anti-patterns.md) | [vault-tree [A3]](attack-trees/vault-attack-tree.md) | - | High |
| WAD/RAY Mixing | Critical | [fixed-point-patterns.md#wad-ray](patterns/fixed-point-patterns.md) | [math-anti-patterns.md#MATH-AP-25](anti-patterns/math-precision-anti-patterns.md) | - | - | Immediate |
| Decimal Mismatch | Critical | [token-patterns.md#decimals](patterns/token-patterns.md) | [math-anti-patterns.md#MATH-AP-20](anti-patterns/math-precision-anti-patterns.md) | [bridge-tree [C5]](attack-trees/bridge-attack-tree.md) | Multiple | Immediate |
| Type Casting Overflow | High | [arithmetic-patterns.md#casting](patterns/arithmetic-patterns.md) | [math-anti-patterns.md#MATH-AP-04](anti-patterns/math-precision-anti-patterns.md) | - | - | High |
| **SIGNATURE/CRYPTOGRAPHY SPECIFIC** |
| ecrecover Zero Address | Critical | [signature-patterns.md#ecrecover](patterns/signature-patterns.md) | [signature-anti-patterns.md#SIG-AP-01](anti-patterns/signature-anti-patterns.md) | - | Multiple | Immediate |
| Signature Malleability | High | [signature-patterns.md#malleability](patterns/signature-patterns.md) | [signature-anti-patterns.md#SIG-AP-02](anti-patterns/signature-anti-patterns.md) | [bridge-tree [A3]](attack-trees/bridge-attack-tree.md) | - | High |
| Missing EIP-712 Domain | Critical | [signature-patterns.md#eip712](patterns/signature-patterns.md) | [signature-anti-patterns.md#SIG-AP-08](anti-patterns/signature-anti-patterns.md) | - | - | Immediate |
| Nonce Not Incremented | Critical | [signature-patterns.md#nonce](patterns/signature-patterns.md) | [signature-anti-patterns.md#SIG-AP-17](anti-patterns/signature-anti-patterns.md) | [intent-tree [B1]](attack-trees/intent-based-attack-tree.md) | - | Immediate |
| Permit Front-Running | High | [permit-patterns.md#front-run](patterns/permit-patterns.md) | [signature-anti-patterns.md#SIG-AP-23](anti-patterns/signature-anti-patterns.md) | - | - | High |
| Multi-Sig Threshold Bypass | Critical | [multisig-patterns.md#threshold](patterns/multisig-patterns.md) | [signature-anti-patterns.md#SIG-AP-30](anti-patterns/signature-anti-patterns.md) | - | - | Immediate |
| No Key Rotation | Medium | [key-management-patterns.md#rotation](patterns/key-management-patterns.md) | [signature-anti-patterns.md#SIG-AP-39](anti-patterns/signature-anti-patterns.md) | - | - | Medium |
| **DEX-SPECIFIC (EXPANDED)** |
| Incorrect Invariant Calculation | Critical | [amm-patterns.md#invariant](patterns/amm-patterns.md) | [dex-anti-patterns.md#DEX-AP-01](anti-patterns/dex-specific-anti-patterns.md) | [dex-tree [C2]](attack-trees/dex-attack-tree.md) | Uranium ($57M), Belt ($6.2M) | Immediate |
| Swap Reentrancy | Critical | [reentrancy-patterns.md#swap](patterns/reentrancy-patterns.md) | [dex-anti-patterns.md#DEX-AP-02](anti-patterns/dex-specific-anti-patterns.md) | [dex-tree [B2]](attack-trees/dex-attack-tree.md) | Curve (read-only) | Immediate |
| No Slippage Protection | Critical | [slippage-patterns.md#protection](patterns/slippage-patterns.md) | [dex-anti-patterns.md#DEX-AP-09](anti-patterns/dex-specific-anti-patterns.md) | [dex-tree [C1]](attack-trees/dex-attack-tree.md) | Constant MEV | Immediate |
| Sandwich Vulnerability | Critical | [mev-patterns.md#sandwich](patterns/mev-patterns.md) | [dex-anti-patterns.md#DEX-AP-17](anti-patterns/dex-specific-anti-patterns.md) | [dex-tree [C1]](attack-trees/dex-attack-tree.md) | Constant MEV | High |
| JIT Liquidity Attack | High | [mev-patterns.md#jit-liquidity](patterns/mev-patterns.md) | [dex-anti-patterns.md#DEX-AP-18](anti-patterns/dex-specific-anti-patterns.md) | [dex-tree [D2]](attack-trees/dex-attack-tree.md) | - | High |
| LP Share Inflation | Critical | [vault-patterns.md#first-depositor](patterns/vault-patterns.md) | [dex-anti-patterns.md#DEX-AP-24](anti-patterns/dex-specific-anti-patterns.md) | [dex-tree [B1]](attack-trees/dex-attack-tree.md) | Multiple | Immediate |
| Spot Price Oracle | Critical | [oracle-patterns.md#spot-price](patterns/oracle-patterns.md) | [dex-anti-patterns.md#DEX-AP-37](anti-patterns/dex-specific-anti-patterns.md) | [dex-tree [A1]](attack-trees/dex-attack-tree.md) | Dozens | Immediate |
| Router Auth Bypass | Critical | [access-control-patterns.md#router](patterns/access-control-patterns.md) | [dex-anti-patterns.md#DEX-AP-43](anti-patterns/dex-specific-anti-patterns.md) | - | - | Immediate |
| **BRIDGE-SPECIFIC (EXPANDED)** |
| Missing Signature Verification | Critical | [signature-patterns.md#verification](patterns/signature-patterns.md) | [bridge-anti-patterns.md#BRIDGE-AP-01](anti-patterns/bridge-specific-anti-patterns.md) | [bridge-tree [A6]](attack-trees/bridge-attack-tree.md) | Ronin ($625M), Wormhole ($320M) | Immediate |
| Signature Replay | Critical | [signature-patterns.md#replay](patterns/signature-patterns.md) | [bridge-anti-patterns.md#BRIDGE-AP-02](anti-patterns/bridge-specific-anti-patterns.md) | [bridge-tree [A1]](attack-trees/bridge-attack-tree.md) | Multiple | Immediate |
| Cross-Chain Replay | Critical | [signature-patterns.md#chain-id](patterns/signature-patterns.md) | [bridge-anti-patterns.md#BRIDGE-AP-03](anti-patterns/bridge-specific-anti-patterns.md) | [bridge-tree [A2]](attack-trees/bridge-attack-tree.md) | Nomad ($190M) | Immediate |
| Insufficient Threshold | Critical | [bridge-patterns.md#validator-threshold](patterns/bridge-patterns.md) | [bridge-anti-patterns.md#BRIDGE-AP-04](anti-patterns/bridge-specific-anti-patterns.md) | [bridge-tree [A4]](attack-trees/bridge-attack-tree.md) | - | Immediate |
| Arbitrary Message Execution | Critical | [bridge-patterns.md#message-validation](patterns/bridge-patterns.md) | [bridge-anti-patterns.md#BRIDGE-AP-09](anti-patterns/bridge-specific-anti-patterns.md) | [bridge-tree [D1]](attack-trees/bridge-attack-tree.md) | - | Immediate |
| Source Chain Spoofing | Critical | [bridge-patterns.md#chain-verification](patterns/bridge-patterns.md) | [bridge-anti-patterns.md#BRIDGE-AP-12](anti-patterns/bridge-specific-anti-patterns.md) | [bridge-tree [B]](attack-trees/bridge-attack-tree.md) | - | Immediate |
| Insufficient Confirmations | Critical | [bridge-patterns.md#confirmation-depth](patterns/bridge-patterns.md) | [bridge-anti-patterns.md#BRIDGE-AP-23](anti-patterns/bridge-specific-anti-patterns.md) | [bridge-tree [B1]](attack-trees/bridge-attack-tree.md) | - | Immediate |
| No Fraud Proofs (Optimistic) | Critical | [bridge-patterns.md#fraud-proofs](patterns/bridge-patterns.md) | [bridge-anti-patterns.md#BRIDGE-AP-25](anti-patterns/bridge-specific-anti-patterns.md) | [bridge-tree [B3]](attack-trees/bridge-attack-tree.md) | - | Immediate |
| Mint Without Lock Verification | Critical | [bridge-patterns.md#mint-verification](patterns/bridge-patterns.md) | [bridge-anti-patterns.md#BRIDGE-AP-29](anti-patterns/bridge-specific-anti-patterns.md) | [bridge-tree [C1]](attack-trees/bridge-attack-tree.md) | - | Immediate |
| First Depositor Attack (Bridge LP) | Critical | [vault-patterns.md#first-depositor](patterns/vault-patterns.md) | [bridge-anti-patterns.md#BRIDGE-AP-40](anti-patterns/bridge-specific-anti-patterns.md) | - | - | Immediate |
| **TOKEN HANDLING** |
| Fee-on-Transfer Token | High | [token-patterns.md#fee-on-transfer](patterns/token-patterns.md) | [token-anti-patterns.md#1](anti-patterns/token-anti-patterns.md) | [dex-tree [C3]](attack-trees/dex-attack-tree.md) | Balancer 2021 ($500K+) | High |
| Rebasing Token Accounting | Critical | [token-patterns.md#rebasing](patterns/token-patterns.md) | [token-anti-patterns.md#2](anti-patterns/token-anti-patterns.md) | - | Rari 2021 ($11M partial) | Immediate |
| ERC777 Reentrancy | Critical | [token-patterns.md#erc777](patterns/token-patterns.md) | [token-anti-patterns.md#3](anti-patterns/token-anti-patterns.md) | [lending-tree [D4]](attack-trees/lending-attack-tree.md) | Imbtc 2020 ($300K) | Immediate |
| Approval Race Condition | Medium | [token-patterns.md#approval-race](patterns/token-patterns.md) | [token-anti-patterns.md#4](anti-patterns/token-anti-patterns.md) | - | Theoretical | Medium |
| Deflationary Token Math | Medium | [token-patterns.md#deflationary](patterns/token-patterns.md) | [token-anti-patterns.md#5](anti-patterns/token-anti-patterns.md) | - | Multiple farms | Medium |
| Token Return Value Not Checked | High | [erc20-patterns.md#safe-transfer](patterns/erc20-patterns.md) | [token-anti-patterns.md#7](anti-patterns/token-anti-patterns.md) | - | Multiple protocols | High |
| **FLASH LOAN ATTACKS** |
| Flash Loan Oracle Manipulation | Critical | [oracle-patterns.md#flash-loan](patterns/oracle-patterns.md) | [flash-loan-anti-patterns.md#2](anti-patterns/flash-loan-anti-patterns.md) | [dex-tree [A1]](attack-trees/dex-attack-tree.md) | bZx 2020 ($954K), Harvest 2020 ($34M) | Immediate |
| Flash Loan Interest Rate Manipulation | High | [lending-pool-patterns.md#interest-rate](patterns/lending-pool-patterns.md) | [flash-loan-anti-patterns.md#3](anti-patterns/flash-loan-anti-patterns.md) | - | Inverse Finance 2022 ($15.6M) | High |
| Flash Loan Reward Farming Exploit | High | [flash-loan-patterns.md#reward-farming](patterns/flash-loan-patterns.md) | [flash-loan-anti-patterns.md#4](anti-patterns/flash-loan-anti-patterns.md) | - | Multiple farms | High |
| Flash Loan Collateral Inflation | Critical | [lending-pool-patterns.md#collateral](patterns/lending-pool-patterns.md) | [flash-loan-anti-patterns.md#5](anti-patterns/flash-loan-anti-patterns.md) | [lending-tree [C2]](attack-trees/lending-attack-tree.md) | Cream Finance 2021 ($130M) | Immediate |
| Flash Loan Arbitrage Drain | Critical | [flash-loan-patterns.md#arbitrage](patterns/flash-loan-patterns.md) | [flash-loan-anti-patterns.md#6](anti-patterns/flash-loan-anti-patterns.md) | - | Warp Finance 2020 ($7.7M), Alpha Homora 2021 ($37M) | Immediate |
| Flash Loan Cascade Liquidation | Critical | [lending-pool-patterns.md#liquidation-cascade](patterns/lending-pool-patterns.md) | [flash-loan-anti-patterns.md#7](anti-patterns/flash-loan-anti-patterns.md) | [stablecoin-tree [E1]](attack-trees/stablecoin-attack-tree.md) | Venus Protocol 2021 ($200M) | Immediate |
| **SOLANA PROGRAM SPECIFIC** |
| Missing Owner Check | Critical | [solana-patterns.md#owner-check](solana-scanner/resources/solana-patterns.md) | [account-validation.md#owner](solana-scanner/resources/account-validation.md) | - | Cashio 2022 ($48M) | Immediate |
| Missing Signer Check | Critical | [solana-patterns.md#signer-check](solana-scanner/resources/solana-patterns.md) | [account-validation.md#signer](solana-scanner/resources/account-validation.md) | - | Wormhole 2022 ($326M) | Immediate |
| PDA Seed Manipulation | Critical | [solana-patterns.md#pda-seeds](solana-scanner/resources/solana-patterns.md) | [account-validation.md#pda](solana-scanner/resources/account-validation.md) | - | Crema Finance 2022 ($8.8M) | Immediate |
| Account Type Cosplay | Critical | [solana-patterns.md#type-cosplay](solana-scanner/resources/solana-patterns.md) | [anchor-security.md#constraints](solana-scanner/resources/anchor-security.md) | - | Common in native programs | Immediate |
| Arbitrary CPI | Critical | [solana-patterns.md#arbitrary-cpi](solana-scanner/resources/solana-patterns.md) | [anchor-security.md#cpi](solana-scanner/resources/anchor-security.md) | - | Multiple protocols | Immediate |
| Reinitialization Attack | Critical | [solana-patterns.md#reinit](solana-scanner/resources/solana-patterns.md) | [anchor-security.md#init](solana-scanner/resources/anchor-security.md) | - | - | Immediate |
| Account Revival (Closing) | High | [solana-patterns.md#revival](solana-scanner/resources/solana-patterns.md) | [pinocchio-security.md#closing](solana-scanner/resources/pinocchio-security.md) | - | - | High |
| Duplicate Mutable Accounts | High | [solana-patterns.md#duplicate-accounts](solana-scanner/resources/solana-patterns.md) | - | - | - | High |
| Integer Overflow (Solana) | High | [solana-patterns.md#overflow](solana-scanner/resources/solana-patterns.md) | - | - | - | High |
| TryFrom Validation Bypass | Critical | [pinocchio-security.md#tryfrom](solana-scanner/resources/pinocchio-security.md) | - | - | Pinocchio-specific | Immediate |
| Token-2022 Discriminator Mismatch | High | [pinocchio-security.md#token2022](solana-scanner/resources/pinocchio-security.md) | - | - | SPL Token-2022 | High |
| Zero-Copy Alignment Unsafety | High | [pinocchio-security.md#zerocopy](solana-scanner/resources/pinocchio-security.md) | - | - | - | High |
| **SOLANA CONFIDENTIAL TRANSFER** |
| ElGamal Key Derivation Bypass | Critical | [confidential-transfer-patterns.md#CT-01](patterns/confidential-transfer-patterns.md) | - | - | Token-2022 Confidential | Immediate |
| Pending Balance DoS | High | [confidential-transfer-patterns.md#CT-02](patterns/confidential-transfer-patterns.md) | - | - | - | High |
| Proof Verification Bypass | Critical | [confidential-transfer-patterns.md#CT-03](patterns/confidential-transfer-patterns.md) | - | - | - | Immediate |
| Auditor Key Compromise | High | [confidential-transfer-patterns.md#CT-04](patterns/confidential-transfer-patterns.md) | - | - | - | High |
| Balance Type Confusion | Critical | [confidential-transfer-patterns.md#CT-05](patterns/confidential-transfer-patterns.md) | - | - | - | Immediate |
| Multi-Tx Atomicity Gap | High | [confidential-transfer-patterns.md#CT-06](patterns/confidential-transfer-patterns.md) | - | - | - | High |
| Key Compromise / Rotation | Medium | [confidential-transfer-patterns.md#CT-07](patterns/confidential-transfer-patterns.md) | - | - | - | Medium |

---

## By Real Exploit

| Exploit Name | Year | Loss | Vulnerability | Pattern Reference | Anti-Pattern | Attack Tree |
|--------------|------|------|---------------|-------------------|--------------|-------------|
| **2023-2024** |
| JPEG'd Exploit | 2023 | $11.6M | NFT floor manipulation | [oracle-patterns.md#nft-floor](patterns/oracle-patterns.md) | - | [nft-tree [A1]](attack-trees/nft-lending-attack-tree.md) |
| Wasabi Floor Manipulation | 2023 | Undisclosed | Wash trading | [nft-patterns.md#wash-trading](patterns/nft-patterns.md) | - | [nft-tree [A2]](attack-trees/nft-lending-attack-tree.md) |
| Tornado Cash Governance | 2023 | N/A | Hidden malicious code | [governance-patterns.md#transparency](patterns/governance-patterns.md) | [governance-anti-patterns.md#5](anti-patterns/governance-anti-patterns.md) | [governance-tree [E1]](attack-trees/governance-attack-tree.md) |
| USDC Depeg | 2023 | Temporary | Bank run + FUD | [stablecoin-patterns.md#bank-run](patterns/stablecoin-patterns.md) | - | [stablecoin-tree [A2][A6]](attack-trees/stablecoin-attack-tree.md) |
| Yearn Finance | 2023 | $11M | First depositor attack | [defi-vault-patterns.md#first-depositor](patterns/defi-vault-patterns.md) | - | [vault-tree [A1]](attack-trees/vault-attack-tree.md) |
| Radiant Capital | 2024 | $4.5M | Cross-function reentrancy | [reentrancy-patterns.md#cross-function](patterns/reentrancy-patterns.md) | - | [lending-tree [D2]](attack-trees/lending-attack-tree.md) |
| Sentiment | 2023 | $1M | Read-only reentrancy | [reentrancy-patterns.md#read-only](patterns/reentrancy-patterns.md) | [reentrancy-anti-patterns.md#3](anti-patterns/reentrancy-anti-patterns.md) | [lending-tree [D3]](attack-trees/lending-attack-tree.md) |
| Euler Finance | 2023 | $197M | Liquidation DoS | [dos-patterns.md#liquidation](patterns/dos-patterns.md) | - | [lending-tree [B2]](attack-trees/lending-attack-tree.md) |
| **2022** |
| Terra/Luna Collapse | 2022 | $40B | Death spiral (algorithmic) | [stablecoin-patterns.md#death-spiral](patterns/stablecoin-patterns.md) | - | [stablecoin-tree [A1]](attack-trees/stablecoin-attack-tree.md) |
| Beanstalk | 2022 | $182M | Flash loan governance | [governance-patterns.md#flash-loan-voting](patterns/governance-patterns.md) | [governance-anti-patterns.md#2](anti-patterns/governance-anti-patterns.md) | [governance-tree [A1]](attack-trees/governance-attack-tree.md) |
| BendDAO Crisis | 2022 | Near-collapse | Floor crash + bank run | [nft-patterns.md#floor-crash](patterns/nft-patterns.md) | - | [nft-tree [C2][F4]](attack-trees/nft-lending-attack-tree.md) |
| Iron Finance | 2021 | $2B | Death spiral (TITAN) | [stablecoin-patterns.md#death-spiral](patterns/stablecoin-patterns.md) | - | [stablecoin-tree [A1]](attack-trees/stablecoin-attack-tree.md) |
| Inverse Finance | 2022 | $15.6M | Interest rate manipulation | [lending-pool-patterns.md#interest-rate](patterns/lending-pool-patterns.md) | [flash-loan-anti-patterns.md#3](anti-patterns/flash-loan-anti-patterns.md) | - |
| Nomad Bridge | 2022 | $190M | Unprotected init | [access-control-patterns.md#initialization](patterns/access-control-patterns.md) | [access-control-anti-patterns.md#1](anti-patterns/access-control-anti-patterns.md) | [bridge-tree [E2]](attack-trees/bridge-attack-tree.md) |
| Ronin Bridge | 2022 | $625M | Validator key compromise | [bridge-patterns.md#key-management](patterns/bridge-patterns.md) | - | [bridge-tree [A5]](attack-trees/bridge-attack-tree.md) |
| Wormhole (Solana) | 2022 | $326M | Missing signer verification | [solana-patterns.md#signer-check](solana-scanner/resources/solana-patterns.md) | [account-validation.md#signer](solana-scanner/resources/account-validation.md) | - |
| Cashio (Solana) | 2022 | $48M | Missing owner check, fake account injection | [solana-patterns.md#owner-check](solana-scanner/resources/solana-patterns.md) | [account-validation.md#owner](solana-scanner/resources/account-validation.md) | - |
| Mango Markets (Solana) | 2022 | $116M | Oracle/price manipulation | [solana-scanner/SKILL.md](solana-scanner/SKILL.md) | - | - |
| Crema Finance (Solana) | 2022 | $8.8M | PDA seed manipulation, fake tick account | [solana-patterns.md#pda-seeds](solana-scanner/resources/solana-patterns.md) | [account-validation.md#pda](solana-scanner/resources/account-validation.md) | - |
| Harmony Horizon | 2022 | $100M | Validator key compromise | [bridge-patterns.md#key-management](patterns/bridge-patterns.md) | - | [bridge-tree [A5]](attack-trees/bridge-attack-tree.md) |
| Rari Capital | 2022 | $80M | Malicious strategy | [strategy-patterns.md#validation](patterns/strategy-patterns.md) | - | [vault-tree [B2]](attack-trees/vault-attack-tree.md) |
| Inverse Finance | 2022 | $1.2M | Stale oracle | [oracle-patterns.md#staleness](patterns/oracle-patterns.md) | [oracle-anti-patterns.md#2](anti-patterns/oracle-anti-patterns.md) | [lending-tree [A1]](attack-trees/lending-attack-tree.md) |
| **2021** |
| Alpha Homora | 2021 | $37M | Flash loan arbitrage | [flash-loan-patterns.md#arbitrage](patterns/flash-loan-patterns.md) | [flash-loan-anti-patterns.md#6](anti-patterns/flash-loan-anti-patterns.md) | - |
| Venus Protocol | 2021 | $200M | Flash loan cascade liquidation | [lending-pool-patterns.md#liquidation-cascade](patterns/lending-pool-patterns.md) | [flash-loan-anti-patterns.md#7](anti-patterns/flash-loan-anti-patterns.md) | [stablecoin-tree [E1]](attack-trees/stablecoin-attack-tree.md) |
| Build Finance | 2021 | N/A | Flash loan governance | [governance-patterns.md#flash-loan-voting](patterns/governance-patterns.md) | [governance-anti-patterns.md#2](anti-patterns/governance-anti-patterns.md) | [governance-tree [A1]](attack-trees/governance-attack-tree.md) |
| Balancer (Deflationary) | 2021 | $500K+ | Fee-on-transfer token | [token-patterns.md#fee-on-transfer](patterns/token-patterns.md) | [token-anti-patterns.md#1](anti-patterns/token-anti-patterns.md) | - |
| Poly Network | 2021 | $610M | Missing access control | [access-control-patterns.md#modifiers](patterns/access-control-patterns.md) | [access-control-anti-patterns.md#2](anti-patterns/access-control-anti-patterns.md) | [bridge-tree [E5]](attack-trees/bridge-attack-tree.md) |
| Cream Finance | 2021 | $130M | Spot price manipulation | [oracle-patterns.md#spot-price](patterns/oracle-patterns.md) | [oracle-anti-patterns.md#1](anti-patterns/oracle-anti-patterns.md) | [lending-tree [A2]](attack-trees/lending-attack-tree.md) |
| THORChain | 2021 | $8M | tx.origin auth | [access-control-patterns.md#tx-origin](patterns/access-control-patterns.md) | [access-control-anti-patterns.md#3](anti-patterns/access-control-anti-patterns.md) | - |
| Venus Protocol | 2021 | N/A | Stale price, zero price | [oracle-patterns.md#validation](patterns/oracle-patterns.md) | [oracle-anti-patterns.md#2,#3](anti-patterns/oracle-anti-patterns.md) | [lending-tree [A1][A3]](attack-trees/lending-attack-tree.md) |
| Grim Finance | 2021 | $30M | Reentrancy | [reentrancy-patterns.md#cei](patterns/reentrancy-patterns.md) | [reentrancy-anti-patterns.md#1](anti-patterns/reentrancy-anti-patterns.md) | - |
| Beefy Finance | 2021 | $11M | Strategy loss | [strategy-patterns.md#loss-cap](patterns/strategy-patterns.md) | - | [vault-tree [B3]](attack-trees/vault-attack-tree.md) |
| **2020** |
| Imbtc | 2020 | $300K | ERC777 reentrancy | [token-patterns.md#erc777](patterns/token-patterns.md) | [token-anti-patterns.md#3](anti-patterns/token-anti-patterns.md) | - |
| bZx (Multiple) | 2020 | $954K | Flash loan oracle manipulation | [oracle-patterns.md#flash-loan](patterns/oracle-patterns.md) | [flash-loan-anti-patterns.md#2](anti-patterns/flash-loan-anti-patterns.md) | - |
| Harvest Finance | 2020 | $34M | Flash loan oracle manipulation | [oracle-patterns.md#spot-price](patterns/oracle-patterns.md) | [flash-loan-anti-patterns.md#2](anti-patterns/flash-loan-anti-patterns.md) | [dex-tree [A1]](attack-trees/dex-attack-tree.md) |
| Lendf.Me | 2020 | $25M | ERC777 reentrancy | [token-patterns.md#erc777](patterns/token-patterns.md) | [reentrancy-anti-patterns.md#4](anti-patterns/reentrancy-anti-patterns.md) | [lending-tree [D4]](attack-trees/lending-attack-tree.md) |
| Harvest Finance | 2020 | $24M | Spot price + arbitrage | [oracle-patterns.md#spot-price](patterns/oracle-patterns.md) | [oracle-anti-patterns.md#1](anti-patterns/oracle-anti-patterns.md) | [dex-tree [A1]](attack-trees/dex-attack-tree.md) |
| Warp Finance | 2020 | $7.7M | LP balanceOf pricing | [defi-vault-patterns.md#lp-pricing](patterns/defi-vault-patterns.md) | [oracle-anti-patterns.md#5](anti-patterns/oracle-anti-patterns.md) | [lending-tree [A2]](attack-trees/lending-attack-tree.md) |
| bZx | 2020 | $8M | Oracle manipulation | [oracle-patterns.md#manipulation](patterns/oracle-patterns.md) | - | - |
| Synthetix | 2020 | DoS | Oracle failure | - | [oracle-anti-patterns.md#4](anti-patterns/oracle-anti-patterns.md) | - |
| Warp Finance | 2020 | $7.7M | Flash loan arbitrage | [flash-loan-patterns.md#arbitrage](patterns/flash-loan-patterns.md) | [flash-loan-anti-patterns.md#6](anti-patterns/flash-loan-anti-patterns.md) | - |
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

### Governance/DAOs

**Critical Vulnerabilities:**
- Flash loan governance voting
- No timelock on critical changes
- Hidden malicious code in proposals
- Arbitrary call execution
- Low quorum requirements

**Primary References:**
- Attack Tree: [governance-attack-tree.md](attack-trees/governance-attack-tree.md)
- Patterns: [governance-patterns.md](patterns/governance-patterns.md)
- Anti-Patterns: [governance-anti-patterns.md](anti-patterns/governance-anti-patterns.md), [flash-loan-anti-patterns.md](anti-patterns/flash-loan-anti-patterns.md)

---

### Stablecoins

**Critical Vulnerabilities:**
- Death spiral (algorithmic)
- Reserve drain/accounting errors
- Infinite minting
- Cascade liquidation
- Oracle manipulation

**Primary References:**
- Attack Tree: [stablecoin-attack-tree.md](attack-trees/stablecoin-attack-tree.md)
- Patterns: [stablecoin-patterns.md](patterns/stablecoin-patterns.md), [oracle-patterns.md](patterns/oracle-patterns.md)
- Related: [lending-pool-patterns.md](patterns/lending-pool-patterns.md)

---

### NFT Lending

**Critical Vulnerabilities:**
- NFT floor price manipulation
- Counterfeit NFT deposits
- Metadata mutation
- Malicious NFT contracts
- Pool drain via over-valuation

**Primary References:**
- Attack Tree: [nft-lending-attack-tree.md](attack-trees/nft-lending-attack-tree.md)
- Patterns: [nft-patterns.md](patterns/nft-patterns.md), [oracle-patterns.md](patterns/oracle-patterns.md)
- Related: [lending-pool-patterns.md](patterns/lending-pool-patterns.md)

---

### Liquid Staking (NEW)

**Critical Vulnerabilities:**
- Exchange rate oracle manipulation
- Withdrawal queue manipulation/DoS
- Malicious validator registration
- Rebasing token accounting errors
- Slashing event exploitation
- Restaking double-count risks

**Primary References:**
- Attack Tree: [liquid-staking-attack-tree.md](attack-trees/liquid-staking-attack-tree.md)
- Patterns: [staking-patterns.md](patterns/staking-patterns.md), [oracle-patterns.md](patterns/oracle-patterns.md)
- Anti-Patterns: [token-anti-patterns.md](anti-patterns/token-anti-patterns.md)
- Related: [governance-patterns.md](patterns/governance-patterns.md)

---

### Perpetuals (NEW)

**Critical Vulnerabilities:**
- Index/mark price manipulation
- Funding rate manipulation
- Forced liquidation attacks
- Liquidation cascade
- Position size manipulation
- LP token extraction
- Insurance fund drain

**Primary References:**
- Attack Tree: [perpetuals-attack-tree.md](attack-trees/perpetuals-attack-tree.md)
- Patterns: [perpetuals-patterns.md](patterns/perpetuals-patterns.md), [liquidation-patterns.md](patterns/liquidation-patterns.md)
- Anti-Patterns: [oracle-anti-patterns.md](anti-patterns/oracle-anti-patterns.md)
- Related: [dex-patterns.md](patterns/dex-patterns.md)

---

### Options (NEW)

**Critical Vulnerabilities:**
- Underlying/settlement price manipulation
- IV manipulation
- Vault share inflation (DOVs)
- Exercise timing attacks
- Strategy gaming (predictable vaults)
- Gamma squeeze attacks
- Collateral ratio manipulation

**Primary References:**
- Attack Tree: [options-attack-tree.md](attack-trees/options-attack-tree.md)
- Patterns: [options-patterns.md](patterns/options-patterns.md), [vault-patterns.md](patterns/vault-patterns.md)
- Anti-Patterns: [oracle-anti-patterns.md](anti-patterns/oracle-anti-patterns.md)
- Related: [perpetuals-patterns.md](patterns/perpetuals-patterns.md)

---

### Intent-Based DEX (NEW)

**Critical Vulnerabilities:**
- Solver MEV/sandwich attacks
- Solver collusion
- Intent signature replay
- Permit2 allowance drain
- Order validation bypass
- Dutch auction gaming
- Cross-chain intent replay
- Settlement layer manipulation

**Primary References:**
- Attack Tree: [intent-based-attack-tree.md](attack-trees/intent-based-attack-tree.md)
- Patterns: [intent-patterns.md](patterns/intent-patterns.md), [permit-patterns.md](patterns/permit-patterns.md)
- Anti-Patterns: [signature-anti-patterns.md](anti-patterns/signature-anti-patterns.md) (40 patterns)
- Related: [dex-patterns.md](patterns/dex-patterns.md), [bridge-patterns.md](patterns/bridge-patterns.md)

---

### Insurance Protocols (NEW)

**Critical Vulnerabilities:**
- Front-run exploit with cover purchase
- Cover stacking attacks
- Fraudulent claims submission
- Parametric trigger manipulation
- Capital pool drain
- Token economics manipulation
- Oracle manipulation for claims

**Primary References:**
- Attack Tree: [insurance-attack-tree.md](attack-trees/insurance-attack-tree.md)
- Patterns: [insurance-patterns.md](patterns/insurance-patterns.md), [oracle-patterns.md](patterns/oracle-patterns.md)
- Anti-Patterns: [governance-anti-patterns.md](anti-patterns/governance-anti-patterns.md)
- Related: [staking-patterns.md](patterns/staking-patterns.md)

---

### Solana Programs (NEW)

**Critical Vulnerabilities:**
- Missing owner/signer validation
- PDA seed manipulation
- Account type cosplay (discriminator bypass)
- Arbitrary cross-program invocation (CPI)
- Reinitialization attacks
- Account revival after closing
- Duplicate mutable accounts
- Integer overflow in token math
- Confidential transfer proof bypass
- ElGamal key derivation bypass

**Primary References:**
- Scanner: [solana-scanner/SKILL.md](solana-scanner/SKILL.md) — 9 vulnerability categories, Anchor + Pinocchio code
- Patterns: [solana-patterns.md](solana-scanner/resources/solana-patterns.md) — Comprehensive vulnerability patterns with code
- Account Validation: [account-validation.md](solana-scanner/resources/account-validation.md) — 5-check validation matrix
- Anchor Security: [anchor-security.md](solana-scanner/resources/anchor-security.md) — Constraint reference + common vulnerabilities
- Pinocchio Security: [pinocchio-security.md](solana-scanner/resources/pinocchio-security.md) — TryFrom, Token-2022, zero-copy safety
- Confidential Transfers: [confidential-transfer-patterns.md](patterns/confidential-transfer-patterns.md) — 7 patterns, ElGamal, proof verification
- Testing: [solana-testing-for-auditors.md](solana-scanner/resources/solana-testing-for-auditors.md) — LiteSVM, Mollusk, Surfpool, PoC examples
- CPI Adversarial: [cpi-adversarial-security.md](solana-scanner/resources/cpi-adversarial-security.md) — 3-layer trust boundaries, identity binding, ABI return validation, 9-gate sequence, nonce discipline

**Key Solana Exploits:**
- Wormhole 2022 ($326M) — Missing signer verification
- Mango Markets 2022 ($116M) — Oracle/price manipulation
- Cashio 2022 ($48M) — Missing owner check, fake account injection
- Crema Finance 2022 ($8.8M) — PDA seed manipulation

---

### DEX/AMM (EXPANDED)

**Critical Vulnerabilities:**
- Spot price oracle (use TWAP)
- First LP inflation attack
- Invariant calculation errors
- Swap reentrancy
- No slippage protection
- Sandwich/MEV attacks
- JIT liquidity attacks
- Router authorization bypass

**Primary References:**
- Attack Tree: [dex-attack-tree.md](attack-trees/dex-attack-tree.md)
- Patterns: [dex-patterns.md](patterns/dex-patterns.md), [amm-patterns.md](patterns/amm-patterns.md)
- Anti-Patterns: [dex-specific-anti-patterns.md](anti-patterns/dex-specific-anti-patterns.md) (47 patterns)
- Related: [mev-patterns.md](patterns/mev-patterns.md)

---

### Bridges (EXPANDED)

**Critical Vulnerabilities:**
- Missing/improper signature verification
- Signature replay (same-chain & cross-chain)
- Insufficient validator threshold
- Arbitrary message execution
- Source chain spoofing
- Insufficient confirmations
- No fraud proofs (optimistic bridges)
- Mint without lock verification
- First depositor attack (bridge LPs)

**Primary References:**
- Attack Tree: [bridge-attack-tree.md](attack-trees/bridge-attack-tree.md)
- Patterns: [bridge-patterns.md](patterns/bridge-patterns.md), [signature-patterns.md](patterns/signature-patterns.md)
- Anti-Patterns: [bridge-specific-anti-patterns.md](anti-patterns/bridge-specific-anti-patterns.md) (45 patterns)
- Related: [access-control-patterns.md](patterns/access-control-patterns.md)

---


## Cross-Chain Reference

**For auditors working across multiple chains:**

- [Cross-Chain Vulnerability Mapping](patterns/cross-chain-vulnerability-mapping.md) — Solana ↔ EVM 1:1 vulnerability equivalences, chain-specific vulns, concept cheat sheet
- [Solana Curated Links](solana-scanner/resources/curated-links.md) — 50+ official Solana security links, audit reports, tools, frameworks, and firms
- [Security Fundamentals](solana-scanner/resources/security-fundamentals.md) — Core Solana security principles, threat model, and best practices
- [Native Security](solana-scanner/resources/native-security.md) — Native Solana (non-Anchor) security patterns and pitfalls
- [Security Checklists](solana-scanner/resources/security-checklists.md) — Audit and client-side checklists for Solana programs
- [Caveats](solana-scanner/resources/caveats.md) — Solana-specific caveats, gotchas, and edge cases for auditors
- [Formal Verification for Auditors](solana-scanner/resources/formal-verification-for-auditors.md) — Kani proof evaluation, classification system, property categories, red flags
- [Proof Strength Evaluation](methodology/proof-strength-evaluation.md) — 6-point methodology for auditing formal verification proof strength (Kani, Certora, Halmos, Move Prover)
- [Audit Session Management](methodology/audit-session-management.md) — 3-file pattern for persistent audit sessions, hook-based workflow gates, coverage tracking

**AI Agent & Payment Security (NEW):**
- [ERC-8004 Agent Security](patterns/erc-8004-agent-security.md) — AI agent registry attacks: identity, reputation gaming, UUPS upgrades, MCP/A2A endpoints
- [x402 Payment Security](patterns/x402-payment-security.md) — HTTP 402 payment protocol: facilitator trust, EIP-3009 replay, cross-chain settlement, MCP integration
- [AI Agent Payment Patterns](patterns/ai-agent-payment-patterns.md) — Agent identity + payment intersection: MCP tool injection, spending controls, prompt injection risks
- [AA ERC-7715 Permission Security](patterns/aa-erc7715-permission-security.md) — Advanced permissions: caveat enforcer attacks, delegation chain validation, counterfactual deployment
- [EIP-7702 Delegation Security](patterns/eip-7702-delegation-security.md) — EOA→smart account delegation: grant scope attacks, private key bypass, chain ID confusion, revocation gaps

**Audit Methodology (NEW — Batch 12):**
- [Verification Discipline](methodology/verification-discipline.md) — Evidence-before-claims: 4-level verification hierarchy, rationalization prevention, severity-to-evidence gate
- [Systematic Root Cause](methodology/systematic-root-cause.md) — 4-phase investigation: root cause → pattern analysis → hypothesis testing → classification, data flow tracing
- [TDD Security Testing](methodology/tdd-security-testing.md) — Red-Green-Refactor for security PoCs: exploit test first, verify fix, permanent regression guard
- [Parallel Audit Agents](methodology/parallel-audit-agents.md) — Multi-agent dispatch: 5 security domains, scope partitioning, finding integration, cross-agent escalation
- [Audit Plan Execution](methodology/audit-plan-execution.md) — Structured execution: task decomposition (1-function-1-task), batch checkpoints, coverage tracking matrix
- [Finding Quality Standards](methodology/finding-quality-standards.md) — Quality scoring: 5-dimension rubric (clarity, PoC, severity, fix, coverage), good vs bad examples, composite scoring

---

## Methodology Templates (NEW)

**Reusable audit methodology templates — how to document, verify, and test security properties for any protocol.**

These templates capture verification methodology, not protocol-specific content. They can be applied to any DeFi protocol on any chain.

| Template | File | Purpose |
|----------|------|---------|
| Admin Key Threat Model | [templates/admin-threat-model.md](templates/admin-threat-model.md) | Document what privileged keys CAN/CANNOT do, with test names |
| Formal Verification Audit | [templates/formal-verification-audit.md](templates/formal-verification-audit.md) | Evaluate proof suites: inventory, classify, map to claims |
| Proof Strength Assessment | [templates/proof-strength-assessment.md](templates/proof-strength-assessment.md) | Grade individual proofs: 6-point analysis, STRONG/WEAK/VACUOUS |
| Trust Boundary Documentation | [templates/trust-boundary-documentation.md](templates/trust-boundary-documentation.md) | Map layered architectures, CPI security, account models |
| Security Properties Checklist | [templates/security-properties-checklist.md](templates/security-properties-checklist.md) | Enumerate, categorize, and verify security invariants |
| Failure Modes & Recovery | [templates/failure-modes-recovery.md](templates/failure-modes-recovery.md) | Document failures, recovery procedures, monitoring |
| State Machine Fuzzer | [templates/state-machine-fuzzer.md](templates/state-machine-fuzzer.md) | Build deterministic integration fuzzers: PRNG, action enum, invariant checker |

**Solana-Specific Resources (methodology-extracted):**

| Resource | File | Purpose |
|----------|------|---------|
| Adversarial Test Design | [solana-scanner/resources/adversarial-test-design.md](solana-scanner/resources/adversarial-test-design.md) | Attack-first test taxonomy, 10-category checklist, conservation invariant pattern |
| CU Worst-Case Design | [solana-scanner/resources/solana-testing-for-auditors.md §7](solana-scanner/resources/solana-testing-for-auditors.md) | 9-level CU escalation framework, benchmark reporting template |
| Verify Module Pattern | [solana-scanner/resources/formal-verification-for-auditors.md §11](solana-scanner/resources/formal-verification-for-auditors.md) | Extract-and-prove: separate decision logic for Kani verification |

**Foundry/Solidity Testing Resources (claude-plugins foundry-solidity merge):**

| Resource | File | Purpose |
|----------|------|---------|
| Foundry Security | [solidity-scanner/resources/foundry-security.md](solidity-scanner/resources/foundry-security.md) | 10 vulnerability categories with concrete Foundry PoC tests, invariant + fork testing examples, pre-audit checklist |
| Foundry Testing | [solidity-scanner/resources/foundry-testing.md](solidity-scanner/resources/foundry-testing.md) | Fuzz testing (bound/assume), invariant handler pattern with ghost variables, fork testing, differential testing, test configuration |
| Foundry Cheatcodes | [solidity-scanner/resources/foundry-cheatcodes.md](solidity-scanner/resources/foundry-cheatcodes.md) | 150+ cheatcodes reference: state manipulation, caller context, expectations, snapshots, cryptography, gas metering, StdStorage, StdInvariant, Cast CLI, Chisel REPL |
| Gas & Security | [solidity-scanner/resources/gas-security.md](solidity-scanner/resources/gas-security.md) | Storage packing, unchecked arithmetic safety, compiler settings, transient storage, EVM opcode costs, Foundry gas profiling |
| Foundry CI/CD | [solidity-scanner/resources/foundry-ci-cd.md](solidity-scanner/resources/foundry-ci-cd.md) | GitHub Actions workflows: build/test/coverage/gas-report pipelines, fork testing with secrets, gas snapshot tracking, matrix testing, deployment workflows |

**When to use each template:**

- **Starting a new audit?** → Admin Threat Model + Trust Boundary + Security Properties
- **Protocol claims "formally verified"?** → Formal Verification Audit + Proof Strength
- **Writing audit report?** → Failure Modes + Security Properties (gap analysis)
- **DeFi perpetuals/derivatives?** → All six templates + State Machine Fuzzer
- **Evaluating test quality?** → Adversarial Test Design + CU Worst-Case
- **Writing Foundry PoC for a finding?** → Foundry Security + Foundry Cheatcodes
- **Setting up CI for a protocol audit?** → Foundry CI/CD + Foundry Testing

**Skill Quality & Authoring Resources (skill-factory merge):**

| Resource | File | Purpose |
|----------|------|---------|
| Quality Scoring | [methodology/quality-scoring.md](methodology/quality-scoring.md) | 10-point Anthropic best practices scoring framework, quality tiers, guarantee loop |
| Skill TDD | [methodology/skill-tdd.md](methodology/skill-tdd.md) | Test-Driven Documentation: pressure test → baseline → write → verify → close loopholes |
| Skill Authoring Guide | [methodology/skill-authoring-guide.md](methodology/skill-authoring-guide.md) | Three creation paths, progressive disclosure, file naming, version tracking, commit standards |
| Quality Check Script | [scripts/quality-check.py](../scripts/quality-check.py) | Automated 10-point scorer for any SKILL.md file (CI-compatible, exit code 0/1) |

**When to use:**

- **Creating a new skill file?** → Skill Authoring Guide + Quality Scoring
- **Evaluating existing skill quality?** → `python scripts/quality-check.py --all`
- **Skill not working as expected?** → Skill TDD (pressure test, find rationalizations)
- **Skill file too large (> 500 lines)?** → Skill Authoring Guide § Progressive Disclosure

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

**Last Updated:** 2026
**Version:** 12.0 (Batch 12 — Audit Methodology+EIP-7702: verification-discipline, systematic-root-cause, tdd-security-testing, parallel-audit-agents, audit-plan-execution, eip-7702-delegation-security, finding-quality-standards)
