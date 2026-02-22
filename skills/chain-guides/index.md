# Chain-Specific Security Guides

## Overview

Each chain has unique security considerations based on its VM, consensus mechanism, and ecosystem patterns. These guides help auditors understand chain-specific attack surfaces.

## Chain Index

### EVM-Compatible L2s
| Chain | VM | Key Risk Areas |
|-------|-----|---------------|
| [Arbitrum](arbitrum.md) | EVM (Nitro) | Sequencer centralization, L1-L2 messaging, retryable tickets |
| [Optimism](optimism.md) | EVM (Bedrock) | Cross-domain messaging, output proposals, gas price oracle |
| [Base](base.md) | EVM (OP Stack) | Same as Optimism + Coinbase specifics |
| [Polygon](polygon.md) | EVM | Bridge security, PoS validator set, gas token (MATIC) |
| [Scroll/Linea](scroll-linea.md) | zkEVM | Prover soundness, EVM equivalence gaps, upgrade keys |
| [zkSync](zksync.md) | zkEVM (Era) | Account abstraction, system contracts, EVM differences |

### EVM-Compatible L1s
| Chain | VM | Key Risk Areas |
|-------|-----|---------------|
| [BSC](bsc.md) | EVM | Validator centralization, cross-chain bridge attacks |
| [Avalanche](avalanche.md) | EVM (C-Chain) | Subnet security, Warp messaging, multi-VM |

### Non-EVM Chains
| Chain | Language | Key Risk Areas |
|-------|----------|---------------|
| [Solana](solana.md) | Rust/Anchor | Account model, PDA derivation, CPI exploits |
| [Cosmos](cosmos.md) | Go (CosmWasm/SDK) | IBC security, module interaction, governance |
| [Aptos](aptos.md) | Move | Resource model, ability constraints, module upgrades |
| [Sui](sui.md) | Move (Sui variant) | Object model, shared vs owned objects, dynamic fields |
| [Starknet](starknet.md) | Cairo | Felt arithmetic, storage proofs, sequencer trust |

## How to Use

1. **Before auditing**: Read the chain guide for the target chain
2. **During audit**: Reference chain-specific checklist items
3. **Cross-chain protocols**: Read guides for ALL chains involved
4. **Bridge audits**: Cross-reference source and destination chain guides

## Universal Cross-Chain Risks

- Message replay across chains
- Different finality guarantees
- Gas price / execution cost differences
- Address format collisions
- Nonce management differences
- Native token handling variations
