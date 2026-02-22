# Arbitrum Security Guide

## Chain Overview

- **Type:** Optimistic Rollup L2
- **VM:** EVM-compatible (Nitro)
- **Consensus:** Sequencer + fraud proofs
- **Finality:** ~1 week challenge period (L1 finality)
- **Gas Token:** ETH

## Key Security Considerations

### 1. Sequencer Centralization
- Single sequencer orders transactions
- Sequencer can censor/delay transactions (but not forge)
- If sequencer goes down, users can force-include via L1 (delayed inbox)
- **Audit check:** Does protocol handle sequencer downtime gracefully?

### 2. L1 <-> L2 Messaging
```
L1 → L2: Retryable Tickets (auto-redeem or manual)
L2 → L1: Outbox (7-day challenge period)
```

**Critical risks:**
- Retryable tickets can fail and need manual redemption
- L2→L1 messages have 7-day delay (exploitable timing window)
- msg.sender aliasing: L1 contract address is offset by `0x1111000000000000000000000000000000001111`
- Cross-chain message replay if nonce not checked

### 3. Address Aliasing
```solidity
// On Arbitrum, L1 contract addresses are aliased
// L2 address = L1 address + 0x1111000000000000000000000000000000001111
// This prevents L1 contracts from impersonating L2 addresses

// [VULNERABLE] Not checking alias
function receiveFromL1(bytes calldata data) external {
    require(msg.sender == l1ContractAddress); // WRONG on Arbitrum!
}

// [SAFE] Check aliased address
function receiveFromL1(bytes calldata data) external {
    require(msg.sender == applyL1ToL2Alias(l1ContractAddress));
}
```

### 4. Gas and Fees
- L2 gas prices fluctuate independently of L1
- L1 calldata costs passed through as L2 gas
- ArbGasInfo precompile provides gas pricing info
- **Audit check:** Does protocol account for L1+L2 gas cost components?

### 5. Block Properties
```solidity
// DIFFERENT from Ethereum mainnet:
block.number    // Returns Arbitrum L2 block number
block.timestamp // Returns L2 timestamp (can differ from L1)

// To get L1 block number:
ArbSys(100).arbBlockNumber() // L2 block
ArbSys(100).arbBlockHash()   // L2 block hash
```

### 6. Precompiles
Arbitrum has special precompile contracts:
- `ArbSys (0x64)` - system info, L2→L1 messaging
- `ArbRetryableTx (0x6e)` - retryable ticket management
- `ArbGasInfo (0x6c)` - gas pricing
- `ArbAddressTable (0x66)` - address compression
- **Audit check:** Are precompile interactions correct?

## Arbitrum-Specific Audit Checklist

- [ ] Retryable tickets: failure/redemption handling
- [ ] L1→L2 message: address aliasing applied correctly
- [ ] L2→L1 message: 7-day delay impact on protocol logic
- [ ] Sequencer downtime: protocol still functions via delayed inbox
- [ ] Block.number / block.timestamp: aware of L2 semantics
- [ ] Cross-chain replay protection in place
- [ ] Gas estimation accounts for L1 data cost component
- [ ] Precompile interactions validated
- [ ] Force-include via L1 considered for censorship resistance

## Common Vulnerabilities on Arbitrum

| Vulnerability | Description |
|--------------|-------------|
| Retryable ticket dust | Ticket created with insufficient gas, stuck forever |
| Alias bypass | Not applying address offset for L1→L2 calls |
| Timing attacks | Exploiting 7-day L2→L1 delay window |
| Gas estimation | L1 calldata cost not factored into protocol gas limits |
