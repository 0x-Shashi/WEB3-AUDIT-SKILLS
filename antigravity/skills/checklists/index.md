# Audit Checklists Index

## Overview

Protocol-type-specific checklists for systematic smart contract auditing. Each checklist focuses on vulnerabilities specific to that protocol category.

## Available Checklists

| Checklist | Target Protocol Type | Items |
|-----------|---------------------|-------|
| [Comprehensive](comprehensive-checklist.md) | General / All protocols | 100+ items |
| [DeFi Lending](defi-lending-checklist.md) | Lending/Borrowing (Aave, Compound) | 60+ items |
| [DEX/AMM](dex-amm-checklist.md) | Decentralized Exchanges, AMMs | 50+ items |
| [Bridge](bridge-checklist.md) | Cross-chain bridges | 50+ items |
| [Governance](governance-checklist.md) | DAOs, Voting, Timelocks | 40+ items |
| [Staking](staking-checklist.md) | Staking, Yield, Rewards | 45+ items |
| [NFT/Gaming](nft-gaming-checklist.md) | NFTs, GameFi, Marketplaces | 40+ items |

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
