---
id: CHAIN-INDEX
title: Chain-Specific Security Guides Index
category: chain-guides
difficulty: intermediate
tags: [chain-specific, l2, solana, cosmos, zksync, security]
last_updated: 2026-01-31
---

# Chain-Specific Security Guides

Each blockchain has unique security considerations. This section covers chain-specific vulnerabilities, attack vectors, and best practices.

## Available Guides

| Chain | Type | Key Concerns |
|-------|------|--------------|
| [Solana](solana.md) | Alt-L1 | Account validation, PDA security, CPI vulnerabilities |
| [Arbitrum](arbitrum.md) | L2 Optimistic | Sequencer risks, delayed inbox, retryable tickets |
| [Optimism](optimism.md) | L2 Optimistic | Cross-domain messaging, deposit handling |
| [zkSync](zksync.md) | L2 ZK-Rollup | Era-specific opcodes, system contracts |
| [Cosmos](cosmos.md) | App-Chain | IBC security, CosmWasm patterns |

## Common L2 Vulnerabilities

| Vulnerability | Affected Chains | Severity |
|---------------|-----------------|----------|
| Sequencer downtime | Arbitrum, Optimism | HIGH |
| Message replay | All L2s | CRITICAL |
| Delayed finality | Optimistic rollups | MEDIUM |
| Bridging assumptions | All | HIGH |
| Gas price differences | All L2s | MEDIUM |

## Security Model Comparison

| Aspect | Ethereum | Arbitrum | Optimism | zkSync | Solana |
|--------|----------|----------|----------|--------|--------|
| Finality | ~15 min | 7 days* | 7 days* | ~1 hour | ~400ms |
| Sequencer | Decentralized | Centralized | Centralized | Centralized | Decentralized |
| Execution | EVM | ArbOS | OVM | zkEVM | BPF/SVM |
| State Model | Account | Account | Account | Account | Account |

*Challenge period for withdrawals

## How to Use These Guides

1. **Before Deployment** - Review the target chain's security model
2. **During Audit** - Check chain-specific patterns
3. **Cross-Chain Projects** - Review all involved chains
4. **Bridge Interactions** - Pay special attention to message handling
