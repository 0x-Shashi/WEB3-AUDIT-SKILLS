# Polygon Security Guide

## Chain Overview

- **Type:** Sidechain (PoS) + zkEVM (L2)
- **VM:** EVM-compatible
- **Consensus:** PoS with Heimdall/Bor validators
- **Finality:** ~2 seconds (PoS), checkpoints to Ethereum
- **Gas Token:** POL (formerly MATIC)

## Key Security Considerations

### 1. Polygon PoS Bridge
```
Ethereum → Polygon: ~7-8 minutes (deposit via RootChain)
Polygon → Ethereum: ~30-90 minutes (checkpoint-based exit)
```

**Critical risks:**
- Bridge deposits require waiting for checkpoint
- Exits require Merkle proof from checkpoint
- `RootChain` contract on Ethereum is upgradeable
- Bridge validators are a limited, permissioned set

### 2. Validator Set and Consensus
- ~100 active validators
- Validators selected by MATIC/POL stake amount
- Heimdall layer handles checkpointing to Ethereum
- **Audit check:** Protocol should not assume Polygon has Ethereum-level security

### 3. Reorg Risk
- Polygon PoS has experienced reorgs (up to 150+ blocks)
- Block confirmations needed are higher than Ethereum
- **Critical for:** DEXs, bridges, payment processors

```solidity
// [VULNERABLE] Single block confirmation on Polygon
function confirmDeposit(bytes32 txHash) external {
    require(block.number > depositBlock[txHash] + 1); // Only 1 conf!
}

// [SAFE] Use sufficient confirmations
function confirmDeposit(bytes32 txHash) external {
    require(block.number > depositBlock[txHash] + 256); // 256 blocks
}
```

### 4. Gas Token Differences
- Gas paid in POL (formerly MATIC), not ETH
- Gas prices are very low (often < 50 gwei)
- Low gas enables gas-intensive attacks cheaply
- **Audit check:** Gas-dependent assumptions may break

### 5. Block Properties
```solidity
block.number    // Polygon block number (2s blocks)
block.timestamp // Can have jitter, not as reliable as Ethereum
block.difficulty // Always 0 on Polygon PoS
block.chainid   // 137 (mainnet), 80001 (Mumbai testnet - deprecated)
```

### 6. EVM Differences
- `PUSH0` supported
- `PREVRANDAO` = 0 (not useful for randomness)
- Gas costs generally same as Ethereum but with lower base fee
- Max contract size applies
- `SELFDESTRUCT` deprecated behavior

### 7. Polygon zkEVM
Separate from PoS, the zkEVM has its own considerations:
- Subset of EVM opcodes supported
- Some precompiles may behave differently
- Prover/verifier trust assumptions
- Forced batching for censorship resistance

## Polygon-Specific Audit Checklist

- [ ] Reorg handling: sufficient block confirmations used
- [ ] Bridge interactions: checkpoint delays accounted for
- [ ] Low gas cost: gas-intensive attacks feasible
- [ ] Gas token is POL/MATIC, not ETH
- [ ] `block.difficulty` returns 0 (not usable)
- [ ] Validator set is limited (~100) - different security model
- [ ] Chain ID 137 used in signatures/hashes
- [ ] Checkpoint finality understood for cross-chain operations
- [ ] PREVRANDAO not used for randomness
- [ ] Contract upgradability in bridge contracts considered

## Common Vulnerabilities on Polygon

| Vulnerability | Description |
|--------------|-------------|
| Reorg exploits | Insufficient block confirmations |
| Bridge delay attacks | Exploiting checkpoint timing |
| Gas price manipulation | Very low gas enables cheap attacks |
| Cross-chain replay | Missing chain ID in signatures |
| Randomness issues | PREVRANDAO = 0, block.difficulty = 0 |
