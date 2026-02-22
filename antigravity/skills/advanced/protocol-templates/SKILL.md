# Protocol Templates Skill

## Purpose
Provide structured, protocol-type-specific audit templates that enumerate the exact checks, invariants, and attack vectors relevant to each protocol category. These templates are loaded based on context detection.

## Available Templates

| Template | Protocol Type | Key Focus Areas |
|----------|--------------|-----------------|
| [AMM/DEX](amm-dex-template.md) | Uniswap, Curve, Balancer-style | Price manipulation, LP attacks, MEV |
| [Bridge](bridge-template.md) | Cross-chain bridges | Message verification, replay, accounting |
| [Lending](lending-template.md) | Aave, Compound-style | Oracle, liquidation, interest rates |
| [NFT Marketplace](nft-marketplace-template.md) | OpenSea, Blur-style | Order validation, royalties, signatures |
| [Staking](staking-template.md) | Lido, RocketPool-style | Reward distribution, withdrawal, delegation |

## Template Structure
Each template follows a consistent format:
1. **Protocol Overview**: What the protocol does
2. **Architecture Checklist**: Structural checks
3. **Invariants**: Mathematical properties that must hold
4. **Attack Vectors**: Known exploits for this protocol type
5. **Critical Functions**: Functions requiring deepest review
6. **Integration Risks**: External dependency risks
7. **Economic Considerations**: Game theory and incentive analysis

## Usage
1. Context detection identifies protocol type
2. Appropriate template is loaded
3. Auditor follows template checklist systematically
4. Findings tagged with template category for standardized reporting
