# Avalanche Security Guide

## Chain Overview

- **Type:** Multi-chain L1 (P-Chain, X-Chain, C-Chain)
- **VM:** EVM (C-Chain), custom VMs on subnets
- **Consensus:** Avalanche Consensus (Snow family)
- **Finality:** ~2 seconds (sub-second for simple txs)
- **Gas Token:** AVAX

## Key Security Considerations

### 1. Multi-Chain Architecture
```
P-Chain: Platform chain (staking, subnet management)
X-Chain: Exchange chain (UTXO-based asset transfers)
C-Chain: Contract chain (EVM, where DeFi lives)
```
- Most smart contract audits focus on C-Chain
- Cross-chain transfers between P/X/C have unique risks
- **Audit check:** If protocol spans multiple chains, verify cross-chain messaging

### 2. Subnets (Avalanche L1s)
- Custom blockchains validated by subset of Avalanche validators
- Can run custom VMs (not just EVM)
- Warp Messaging for cross-subnet communication
- **Audit check:** Subnet validator set may be very small (lower security)

### 3. Warp Messaging (AWM)
```
Avalanche Warp Messaging allows cross-subnet communication:
- Messages signed by source subnet validators
- Destination subnet verifies BLS aggregate signatures
- Threshold of signatures required (configurable)
```

**Critical risks:**
- Subnet with few validators = easier to forge messages
- Threshold configuration affects security guarantees
- Message replay across subnets

### 4. EVM Compatibility (C-Chain)
C-Chain is a modified geth fork:
- Fully EVM-compatible
- Different gas fee mechanism (dynamic fees, burned)
- `PREVRANDAO` not available as on Ethereum (returns 0)
- Contract size limits same as Ethereum
- Precompiles: same as Ethereum + Avalanche-specific

### 5. Avalanche Consensus Properties
- Probabilistic finality (extremely high probability)
- No leader-based block production (no single-block MEV advantages)
- Reduced MEV compared to Ethereum (less structured block building)
- **Audit check:** Protocols should not assume zero MEV

### 6. Gas and Fees
- Dynamic base fee (EIP-1559 style)
- Minimum gas price enforced
- Gas token is AVAX, not ETH
- Base fee can spike during congestion
- All base fees are burned (deflationary)

### 7. Block Properties (C-Chain)
```solidity
block.chainid   // 43114 (C-Chain mainnet)
block.number     // C-Chain block number
block.timestamp  // ~2s block time
block.difficulty // 0 in Snowman consensus
```

## Avalanche-Specific Audit Checklist

- [ ] C-Chain vs subnet deployment identified
- [ ] AVAX is gas token (not ETH)
- [ ] Chain ID 43114 in signatures
- [ ] Subnet validator set size assessed (if subnet deployment)
- [ ] Warp Messaging: signature threshold adequate
- [ ] Cross-subnet replay protection in place
- [ ] block.difficulty returns 0
- [ ] PREVRANDAO not used for randomness
- [ ] Trader Joe / Pangolin integration (main DEXs) validated
- [ ] AAVE/Benqi lending protocol interactions checked

## Common Vulnerabilities on Avalanche

| Vulnerability | Description |
|--------------|-------------|
| Subnet trust | Small validator sets on custom subnets |
| Warp message replay | Cross-subnet message replayed |
| Oracle on C-Chain | Spot price manipulation on Trader Joe |
| Cross-chain bridge | Bridge between C-Chain and other networks |
| Fast finality assumption | Treating probabilistic finality as absolute |
