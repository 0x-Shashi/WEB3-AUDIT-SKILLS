# BSC (BNB Smart Chain) Security Guide

## Chain Overview

- **Type:** EVM-compatible L1
- **VM:** EVM (geth fork)
- **Consensus:** Proof of Staked Authority (PoSA) - 21 validators
- **Finality:** ~3 seconds (single slot), 15 blocks recommended
- **Gas Token:** BNB

## Key Security Considerations

### 1. Validator Centralization
- Only 21 active validators (elected by BNB stake)
- Validators are largely Binance-affiliated or approved
- Lower censorship resistance than Ethereum
- Validator set changes every 24 hours via epoch
- **Audit check:** Protocol must not assume decentralized consensus

### 2. Cross-Chain Bridge (BSC <-> Ethereum/Other)
- Binance Bridge: centralized, operated by Binance
- BSC Token Hub exploit (2022): $570M exploit via proof forgery
- **Audit check:** Bridge message verification is critical

### 3. Token Standards (BEP-20)
```solidity
// BEP-20 is essentially ERC-20 with minor naming differences
// Same vulnerabilities apply:
// - Approval race condition
// - Non-standard return values
// - Deflationary/fee-on-transfer tokens
// - Tokens with blacklists (BUSD)
```

### 4. PancakeSwap Dominance
- PancakeSwap is the primary DEX (Uniswap V2/V3 fork)
- Many BSC protocols integrate PancakeSwap directly
- **Audit check:** Same Uniswap vulnerabilities apply (sandwich, oracle manipulation)

### 5. Gas and Fees
- Gas prices very low (3-5 gwei typical)
- Gas token is BNB (not ETH)
- Low gas makes gas-intensive attacks cheap
- Flashbots/MEV infrastructure less mature than Ethereum

### 6. Block Properties
```solidity
block.chainid   // 56 (BSC mainnet)
block.number     // BSC block number (~3s blocks)
block.timestamp  // Validator-controlled, can vary
block.difficulty // 0 or 1 in PoSA
```

### 7. Common BSC-Specific Attack Patterns
- **Rug pulls:** Significantly more common on BSC due to lower deployment costs
- **Flash loan attacks:** PancakeSwap flash swaps, dYdX flash loans bridged
- **Token impersonation:** Fake tokens deployed with same name/symbol
- **Honey pots:** Tokens that can only be bought, not sold

## BSC-Specific Audit Checklist

- [ ] 21-validator PoSA centralization risks assessed
- [ ] Gas token is BNB (not ETH) - handled correctly
- [ ] Chain ID 56 in all signatures
- [ ] PancakeSwap integration: V2 vs V3 router addresses correct
- [ ] Low gas cost: attack feasibility at low cost
- [ ] Token validation: not trusting token name/symbol
- [ ] Bridge security for cross-chain messaging
- [ ] block.difficulty returns 0 or 1
- [ ] Reentrancy protection (same EVM behavior)
- [ ] Flash loan sources: PancakeSwap, Venus, etc.

## Common Vulnerabilities on BSC

| Vulnerability | Description |
|--------------|-------------|
| BSC Token Hub hack | $570M bridge exploit via forged proof (2022) |
| PancakeSwap oracle | Using spot price instead of TWAP |
| Rug pull patterns | Owner can mint/pause/blacklist without timelock |
| Validator manipulation | 21 validators can theoretically collude |
| Low-cost attacks | Flash loans + low gas = cheap complex attacks |
