# Base Security Guide

## Chain Overview

- **Type:** Optimistic Rollup L2 (OP Stack)
- **VM:** EVM-equivalent (Bedrock/Ecotone)
- **Operator:** Coinbase
- **Finality:** ~7 day challenge period
- **Gas Token:** ETH

## Key Security Considerations

### 1. OP Stack Inherited Risks
Base is built on the OP Stack, so ALL Optimism risks apply:
- Cross-domain messaging via `CrossDomainMessenger`
- 7-day withdrawal delay
- `xDomainMessageSender()` required for L1 sender verification
- `PREVRANDAO` is sequencer-controlled (not random)
- L1 data fee component in gas costs
- Same predeploy system contracts at `0x4200...` addresses

**See [Optimism Guide](optimism.md) for full OP Stack security details.**

### 2. Coinbase Sequencer Centralization
- Coinbase operates the sole sequencer
- Sequencer can reorder/censor transactions
- Revenue from sequencing goes to Coinbase
- **Audit check:** Censorship-sensitive protocols should have L1 force-inclusion fallback

### 3. Multi-Chain Protocols (Base + Mainnet + Other L2s)
Base's growth has led to many multi-chain deployments:
- Cross-chain state synchronization issues
- Different gas costs across chains affect protocol economics
- Bridge security between Base and other chains
- **Audit check:** Are chain IDs properly checked? Is replay protection in place?

```solidity
// [VULNERABLE] Missing chain ID in signature
function executeOrder(bytes calldata signature, Order calldata order) external {
    address signer = recoverSigner(abi.encode(order), signature);
    // Same signature works on Base AND Ethereum mainnet!
    require(signer == order.maker);
}

// [SAFE] Include chain ID
function executeOrder(bytes calldata signature, Order calldata order) external {
    address signer = recoverSigner(abi.encode(order, block.chainid), signature);
    require(signer == order.maker);
}
```

### 4. Base-Specific Ecosystem Patterns
- Heavy use of ERC-4337 account abstraction
- Friend.tech-style social protocols (bonding curves)
- Coinbase Smart Wallet integration
- USDC native issuance (not bridged)
- **Audit check:** Account abstraction interactions with protocol

### 5. Gas and Fees (Ecotone)
Post-Ecotone upgrade, Base uses EIP-4844 blobs:
- Significantly lower L1 data costs
- Base fee can be very low (sub-gwei)
- **Audit check:** Protocols using gas price as entropy or timing are vulnerable

## Base-Specific Audit Checklist

- [ ] All Optimism checklist items apply (see [Optimism](optimism.md))
- [ ] Chain ID included in all signatures and hashes
- [ ] Cross-chain replay protection implemented
- [ ] Sequencer censorship impact analyzed
- [ ] Account abstraction (ERC-4337) interactions tested
- [ ] Native USDC vs bridged USDC handling correct
- [ ] Multi-chain deployment: same addresses, different state?
- [ ] Low gas price doesn't break protocol assumptions

## Common Vulnerabilities on Base

| Vulnerability | Description |
|--------------|-------------|
| Cross-chain replay | Signatures valid on multiple chains |
| OP Stack issues | All Optimism vulnerabilities apply |
| Low gas griefing | Ultra-low gas allows cheap spam attacks |
| AA wallet edge cases | ERC-4337 wallets behave differently than EOAs |
| Native vs bridged USDC | Different contract addresses, different behaviors |
