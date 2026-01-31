---
id: PLAY-INDEX
title: Protocol Integration Playbooks
category: protocol-playbooks
difficulty: intermediate
chains: [ethereum, arbitrum, optimism, polygon, base]
tags: [integration, checklist, playbook]
last_updated: 2026-01-31
---

# Protocol Integration Playbooks

These playbooks summarize secure integration guidance and audit checklists for major protocols.

## Complete Playbook Catalog

| Protocol | Category | Key Risks | Guide |
|----------|----------|-----------|-------|
| Uniswap V3 | DEX/AMM | Tick manipulation, flash loan | [uniswap-v3.md](uniswap-v3.md) |
| **Uniswap V4** | DEX/AMM | Hooks, flash accounting, singleton | [uniswap-v4.md](uniswap-v4.md) |
| Aave V3 | Lending | Oracle manipulation, liquidation | [aave-v3.md](aave-v3.md) |
| **Compound V3** | Lending | Absorb mechanism, single-asset | [compound-v3.md](compound-v3.md) |
| Lido | Staking | Rebasing, oracle lag | [lido.md](lido.md) |
| **Curve** | DEX/Stableswap | Read-only reentrancy, virtual price | [curve.md](curve.md) |
| **GMX** | Perpetuals | Keeper MEV, GLP manipulation | [gmx.md](gmx.md) |
| **Morpho** | Lending Optimizer | P2P matching, oracle per market | [morpho.md](morpho.md) |

## By Protocol Category

### DEX / AMM
- [Uniswap V3](uniswap-v3.md) - Concentrated liquidity AMM
- [Uniswap V4](uniswap-v4.md) - **NEW** - Hooks and singleton architecture
- [Curve](curve.md) - **NEW** - Stableswap and metapools

### Lending / Borrowing
- [Aave V3](aave-v3.md) - Multi-asset lending
- [Compound V3](compound-v3.md) - **NEW** - Single-asset Comet markets
- [Morpho](morpho.md) - **NEW** - P2P optimization layer

### Derivatives / Perpetuals
- [GMX](gmx.md) - **NEW** - Decentralized perpetual exchange

### Staking
- [Lido](lido.md) - Liquid staking

## How to Use

1. **Identify Integration Type** - Which protocol are you integrating with?
2. **Review Common Risks** - Each playbook lists critical security areas
3. **Apply Audit Checklist** - Follow the checklist before production
4. **Map to Pattern Files** - Cross-reference with vulnerability patterns
5. **Check Exploit Forensics** - Learn from real-world exploits

## Integration Risk Matrix

| Integration | Flash Loan Risk | Oracle Risk | Reentrancy Risk |
|-------------|-----------------|-------------|-----------------|
| Uniswap V4 | HIGH | LOW | MEDIUM (hooks) |
| Curve | HIGH | MEDIUM | **CRITICAL** |
| Aave V3 | MEDIUM | HIGH | LOW |
| Compound V3 | LOW | HIGH | LOW |
| GMX | MEDIUM | **CRITICAL** | LOW |
| Morpho | MEDIUM | HIGH | LOW |
