# Audit Checklists Index

## Overview

Protocol-type-specific checklists for systematic smart contract auditing. Each checklist focuses on vulnerabilities specific to that protocol category.

## Available Checklists

| Checklist | Target Protocol Type | Items |
|-----------|---------------------|-------|
| [Comprehensive](comprehensive-checklist.md) | General / All protocols | 88 items |
| [DeFi Lending](defi-lending-checklist.md) | Lending/Borrowing (Aave, Compound) | 64 items |
| [DEX/AMM](dex-amm-checklist.md) | Decentralized Exchanges, AMMs | 59 items |
| [Bridge](bridge-checklist.md) | Cross-chain bridges | 59 items |
| [Governance](governance-checklist.md) | DAOs, Voting, Timelocks | 55 items |
| [Staking](staking-checklist.md) | Staking, Yield, Rewards | 57 items |
| [NFT/Gaming](nft-gaming-checklist.md) | NFTs, GameFi, Marketplaces | 58 items |
| [Perpetuals/Derivatives](perpetuals-checklist.md) | Perp DEXes (GMX, dYdX, Synthetix) | 77 items |
| [Options/Structured Products](options-structured-checklist.md) | On-chain options (Lyra, Dopex, Ribbon) | 71 items |
| [Restaking/LRT](restaking-lrt-checklist.md) | Restaking (EigenLayer), Liquid Restaking | 72 items |
| [Intent-Based/Solver](intent-based-checklist.md) | Intent protocols (UniswapX, CoW, Across) | 70 items |
| [Stablecoin/CDP](stablecoin-cdp-checklist.md) | CDP stablecoins (MakerDAO, Liquity) | 70 items |
| [Vault/Yield Aggregator](vault-yield-checklist.md) | ERC-4626 vaults (Yearn, Morpho) | 70 items |
| [Liquid Staking](liquid-staking-checklist.md) | LST protocols (Lido, Rocket Pool) | 72 items |

## How to Use

1. **Start with Comprehensive** - covers universal vulnerabilities
2. **Add protocol-specific checklist** - for the protocol type being audited
3. **Cross-reference chain guide** - for chain-specific items
4. **Check attack chains** - for multi-step exploit scenarios

## Checklist Item Format

Each item uses:
- `[ ]` Unchecked = not yet verified
- `[x]` Checked = verified safe
- `[!]` Flag = potential issue found
- `[N/A]` Not applicable to this protocol

## Severity Tags

- **CRITICAL** - Can lead to total fund loss
- **HIGH** - Significant fund loss or protocol compromise
- **MEDIUM** - Limited fund loss or protocol disruption
- **LOW** - Minor issues, best practices
- **INFO** - Informational, gas optimization
