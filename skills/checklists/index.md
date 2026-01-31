# Specialized Checklists Index

> Domain-specific security checklists for auditing different DeFi protocol types.

## Overview

These checklists provide targeted security checks organized by protocol category. Each checklist covers critical vulnerabilities specific to that domain, with code examples and red flags to watch for.

---

## Available Checklists

### Core DeFi Checklists

| Checklist | Focus Area | Key Risks |
|-----------|------------|-----------|
| [DeFi Lending](defi-lending-checklist.md) | Lending/Borrowing Protocols | Collateral, liquidation, oracles, interest rates |
| [DEX/AMM](dex-amm-checklist.md) | Decentralized Exchanges | Price manipulation, MEV, slippage, liquidity |
| [Staking](staking-checklist.md) | Staking Protocols | Rewards, slashing, delegation, liquid staking |
| [Governance](governance-checklist.md) | DAO/Governance | Flash loans, proposals, timelocks, delegation |

### Infrastructure Checklists

| Checklist | Focus Area | Key Risks |
|-----------|------------|-----------|
| [Bridge](bridge-checklist.md) | Cross-Chain Bridges | Message verification, replay, finality, rate limiting |

### Application Checklists

| Checklist | Focus Area | Key Risks |
|-----------|------------|-----------|
| [NFT/Gaming](nft-gaming-checklist.md) | NFTs & GameFi | Randomness, minting, marketplace, royalties |

---

## Usage Guide

### When to Use These Checklists

1. **Initial Audit Scoping** - Identify relevant checklists based on protocol type
2. **Systematic Review** - Work through each check methodically
3. **Finding Documentation** - Reference specific checks when writing reports
4. **Team Collaboration** - Ensure consistent coverage across auditors

### Priority Levels

Each checklist organizes checks by severity:

| Priority | Icon | Description |
|----------|------|-------------|
| Critical | 🔴 | Must check first - highest impact vulnerabilities |
| High | 🟠 | Check early - significant security risks |
| Medium | 🟡 | Standard review - common vulnerabilities |
| Standard | 🟢 | Complete coverage - best practices |

### Integration with Workflow

```
1. Identify protocol type → Select relevant checklist(s)
2. Review Critical/High first → Maximum impact efficiency
3. Document findings with check references
4. Cross-reference with exploit-forensics for real-world examples
```

---

## Related Resources

- [Comprehensive Checklist](comprehensive-checklist.md) - Master checklist covering all categories
- [Exploit Forensics](../exploit-forensics/) - Real-world examples of vulnerabilities
- [Attack Patterns](../patterns/) - Detailed attack vector documentation

---

## Checklist Development

These checklists are continuously updated based on:
- New exploit discoveries
- Emerging attack patterns  
- Community contributions
- Protocol evolution

Last Updated: 2026-01-31
