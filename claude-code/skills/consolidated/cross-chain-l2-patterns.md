# Consolidated: Cross-Chain and L2 Patterns

## Overview

Cross-chain and L2 protocols introduce unique attack surfaces around message passing, finality assumptions, and bridge security. This consolidates all cross-chain vulnerability patterns.

---

## L2-Specific Patterns

### 1. Sequencer Centralization
```
Risk: Single sequencer can censor, reorder, or delay transactions
Affected: Arbitrum, Optimism, Base, Scroll, Linea, zkSync, Starknet

Audit Checks:
- [ ] Protocol functions work if sequencer is down (force-include via L1)
- [ ] Sequencer can't extract value via ordering
- [ ] PREVRANDAO not used (sequencer-controlled on L2)
```

### 2. L1<->L2 Message Passing
```solidity
// PATTERN: Correct L1->L2 sender validation

// Arbitrum: Address aliasing
address l2Alias = address(uint160(l1Sender) + uint160(0x1111000000000000000000000000000000001111));
require(msg.sender == l2Alias);

// Optimism/Base: CrossDomainMessenger
require(msg.sender == address(crossDomainMessenger));
require(crossDomainMessenger.xDomainMessageSender() == l1Contract);

// zkSync: Direct (no aliasing)
require(msg.sender == l1Sender); // L1 address passed directly
```

### 3. Finality Differences
```
Chain             | L2 Finality          | L2->L1 Finality
Arbitrum          | Instant (soft)       | 7 days (challenge period)
Optimism/Base     | Instant (soft)       | 7 days (challenge period)
zkSync Era        | Instant (soft)       | ~1 hour (proof time)
Scroll/Linea      | Instant (soft)       | ~20 min (proof time)
Starknet          | Instant (soft)       | ~minutes (proof time)
Polygon PoS       | 2s (reorg possible)  | ~30-90 min (checkpoint)

// [VULNERABLE] Assuming instant finality
function processL2Event(uint256 l2BlockNumber) external {
    require(l2BlockNumber < block.number); // L2 block could be reorged!
}
```

### 4. Gas and Fee Differences
```
L2 Total Fee = L2 Execution Fee + L1 Data Fee

// [VULNERABLE] Hardcoded gas limits for L2
function sendToL2(bytes calldata data) external {
    l2Bridge.sendMessage{gas: 100000}(data); // Gas costs differ on L2!
}

// L1 data costs affect L2 gas:
// - Pre-EIP-4844: calldata-based, expensive
// - Post-EIP-4844: blob-based, cheaper
// - Varies by L2 implementation
```

---

## Bridge Patterns

### 5. Message Verification
```solidity
// [VULNERABLE] No source validation
function onBridgeMessage(bytes calldata data) external {
    // Anyone can call with fake data!
    _processMessage(data);
}

// [SAFE] Validate bridge and source
function onBridgeMessage(bytes calldata data) external {
    require(msg.sender == address(trustedBridge), "Not bridge");
    (address sender, uint256 srcChainId, bytes memory payload) = abi.decode(data, (address, uint256, bytes));
    require(sender == trustedRemoteContract, "Unknown sender");
    require(srcChainId == expectedSourceChain, "Wrong chain");
    _processMessage(payload);
}
```

### 6. Replay Protection
```solidity
// [VULNERABLE] No replay protection
function executeMessage(bytes32 messageHash, bytes calldata data) external {
    require(verifyProof(messageHash), "Invalid proof");
    _execute(data); // Same message can be replayed!
}

// [SAFE] Mark messages as processed
mapping(bytes32 => bool) public processedMessages;

function executeMessage(bytes32 messageHash, bytes calldata data) external {
    require(!processedMessages[messageHash], "Already processed");
    require(verifyProof(messageHash), "Invalid proof");
    processedMessages[messageHash] = true;
    _execute(data);
}
```

### 7. Token Bridge Accounting
```
Lock-and-Mint Pattern:
Source: lock(token, amount) -> Bridge -> Destination: mint(wrappedToken, amount)
Destination: burn(wrappedToken, amount) -> Bridge -> Source: unlock(token, amount)

Invariant: wrappedToken.totalSupply() <= token.balanceOf(bridge)

Risks:
- Phantom minting: minting without corresponding lock
- Double unlock: unlocking same deposit twice
- Decimal mismatch: 18 decimals on source, 6 on destination
```

---

## Cross-Chain Attack Patterns

### 8. Cross-Chain Replay
```solidity
// Attack: Same transaction valid on multiple chains
// Example: EIP-155 not enforced, or missing chainId in signature

// [VULNERABLE]
bytes32 hash = keccak256(abi.encodePacked(to, amount, nonce));
// This hash is identical on Ethereum and Polygon!

// [SAFE] Include chain ID
bytes32 hash = keccak256(abi.encodePacked(to, amount, nonce, block.chainid));
```

### 9. Bridge Validator Compromise
```
Attack: Compromise enough validator keys to forge messages
Examples:
- Ronin: 5 of 9 validators compromised ($624M)
- Harmony: 2 of 5 validators compromised ($100M)

Mitigations:
- Higher validator threshold (e.g., 13 of 19)
- Time-delayed withdrawals for large amounts
- Watchtower/monitoring systems
- Hardware security modules for validator keys
```

### 10. Oracle Divergence Across Chains
```
Risk: Same asset has different prices on different chains
Example: ETH price on Ethereum vs ETH price on Arbitrum
  - If oracle updates are delayed on one chain
  - Attacker arbitrages the price difference through bridge

// [VULNERABLE] Same oracle answer assumed on both chains
// [SAFE] Per-chain oracle validation with staleness checks
```

---

## Real-World Cross-Chain Exploits

| Protocol | Loss | Method | Year |
|----------|------|--------|------|
| Ronin Bridge | $624M | Validator key compromise (5/9) | 2022 |
| Wormhole | $326M | Signature verification bypass | 2022 |
| Nomad | $190M | Message verification flaw | 2022 |
| Harmony Horizon | $100M | Validator key compromise (2/5) | 2022 |
| BSC Token Hub | $570M | Proof verification bug (IAVL) | 2022 |
| Poly Network | $611M | Cross-chain access control bypass | 2021 |

---

## Related Files
- [Bridge Checklist](../checklists/bridge-checklist.md)
- [Chain Guides](../chain-guides/index.md)
- [Bridge Exploit Chain](../attack-chains/bridge-exploit-chain.md)
