---
id: PLAYBOOK-LAYERZERO-V2
title: LayerZero V2 Integration Playbook
category: protocol-playbooks
protocol: layerzero
version: v2
difficulty: advanced
tags: [layerzero, cross-chain, messaging, oft, oapp, bridge]
last_updated: 2026-01-31
---

# LayerZero V2 Integration Playbook

## Protocol Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      LAYERZERO V2                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐              ┌─────────────┐                  │
│  │  Chain A    │              │  Chain B    │                  │
│  │  ┌───────┐  │              │  ┌───────┐  │                  │
│  │  │ OApp  │  │              │  │ OApp  │  │                  │
│  │  └───┬───┘  │              │  └───┬───┘  │                  │
│  │      │      │              │      │      │                  │
│  │  ┌───▼───┐  │              │  ┌───▼───┐  │                  │
│  │  │Endpoint│ │◄────────────►│ │Endpoint│  │                  │
│  │  └───────┘  │              │  └───────┘  │                  │
│  └─────────────┘              └─────────────┘                  │
│         │                            │                          │
│         │    ┌──────────────────┐    │                          │
│         └───►│  Security Stack  │◄───┘                          │
│              │  ┌────────────┐  │                               │
│              │  │   DVNs     │  │  (Decentralized Verifiers)   │
│              │  └────────────┘  │                               │
│              │  ┌────────────┐  │                               │
│              │  │ Executors  │  │  (Message Delivery)          │
│              │  └────────────┘  │                               │
│              └──────────────────┘                               │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Concepts

### 1. V2 Architecture Changes

```solidity
// V1 → V2 Key Differences:

// V1: Monolithic
// - Single Ultra Light Node
// - Relayer + Oracle model
// - Less configurable

// V2: Modular Security Stack
// - Multiple DVNs (Decentralized Verifier Networks)
// - Configurable per pathway
// - Executor separation
// - Horizontal composability
```

### 2. OApp (Omnichain Application)

```solidity
// Base contract for cross-chain applications
// Inherit from OApp to build cross-chain apps

abstract contract OApp is IOAppCore, IOAppReceiver {
    // Endpoint for sending messages
    ILayerZeroEndpointV2 public immutable endpoint;
    
    // Peer addresses on other chains (eid => peer)
    mapping(uint32 => bytes32) public peers;
    
    // Send cross-chain message
    function _lzSend(
        uint32 _dstEid,           // Destination endpoint ID
        bytes memory _message,     // Payload
        bytes memory _options,     // Execution options
        MessagingFee memory _fee,  // Fee (native + lzToken)
        address _refundAddress     // Refund excess fees
    ) internal returns (MessagingReceipt memory);
    
    // Receive cross-chain message (override this)
    function _lzReceive(
        Origin calldata _origin,
        bytes32 _guid,
        bytes calldata _message,
        address _executor,
        bytes calldata _extraData
    ) internal virtual;
}
```

### 3. OFT (Omnichain Fungible Token)

```solidity
// Standard for cross-chain tokens

abstract contract OFT is OFTCore, ERC20 {
    // Send tokens cross-chain
    function send(
        SendParam calldata _sendParam,
        MessagingFee calldata _fee,
        address _refundAddress
    ) external payable returns (MessagingReceipt memory, OFTReceipt memory);
}

// SendParam structure
struct SendParam {
    uint32 dstEid;           // Destination chain
    bytes32 to;              // Recipient (bytes32 for non-EVM)
    uint256 amountLD;        // Amount in local decimals
    uint256 minAmountLD;     // Minimum amount (slippage)
    bytes extraOptions;      // Additional options
    bytes composeMsg;        // Composed message (optional)
    bytes oftCmd;            // OFT command (optional)
}
```

### 4. Security Stack Configuration

```solidity
// V2 allows configuring security per pathway

struct UlnConfig {
    uint64 confirmations;          // Required block confirmations
    uint8 requiredDVNCount;        // How many DVNs must verify
    uint8 optionalDVNCount;        // Optional DVNs
    uint8 optionalDVNThreshold;    // Threshold for optional
    address[] requiredDVNs;        // Must-verify DVN addresses
    address[] optionalDVNs;        // Optional DVN addresses
}

// Example: Require 2 DVNs for Ethereum→Arbitrum
// Different config for Ethereum→BSC
```

---

## Integration Patterns

### Basic OApp Implementation

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { OApp, Origin } from "@layerzerolabs/oapp-evm/contracts/oapp/OApp.sol";
import { MessagingFee } from "@layerzerolabs/oapp-evm/contracts/oapp/OAppSender.sol";

contract CrossChainCounter is OApp {
    uint256 public count;
    
    constructor(address _endpoint, address _owner) OApp(_endpoint, _owner) {}
    
    // Send increment message to another chain
    function incrementOnChain(
        uint32 _dstEid,
        bytes calldata _options
    ) external payable {
        bytes memory payload = abi.encode(count + 1);
        
        _lzSend(
            _dstEid,
            payload,
            _options,
            MessagingFee(msg.value, 0),  // Pay in native token
            payable(msg.sender)
        );
    }
    
    // Receive increment from another chain
    function _lzReceive(
        Origin calldata _origin,
        bytes32 _guid,
        bytes calldata _message,
        address _executor,
        bytes calldata _extraData
    ) internal override {
        uint256 newCount = abi.decode(_message, (uint256));
        count = newCount;
    }
    
    // Quote fee for sending message
    function quote(
        uint32 _dstEid,
        bytes calldata _options
    ) external view returns (MessagingFee memory) {
        bytes memory payload = abi.encode(count + 1);
        return _quote(_dstEid, payload, _options, false);
    }
}
```

### OFT Implementation

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { OFT } from "@layerzerolabs/oft-evm/contracts/OFT.sol";

contract MyToken is OFT {
    constructor(
        string memory _name,
        string memory _symbol,
        address _lzEndpoint,
        address _owner
    ) OFT(_name, _symbol, _lzEndpoint, _owner) {
        // Mint initial supply on deployment chain
        _mint(_owner, 1000000 * 10**18);
    }
}

// For existing tokens, use OFTAdapter
import { OFTAdapter } from "@layerzerolabs/oft-evm/contracts/OFTAdapter.sol";

contract MyTokenAdapter is OFTAdapter {
    constructor(
        address _token,
        address _lzEndpoint,
        address _owner
    ) OFTAdapter(_token, _lzEndpoint, _owner) {}
}
```

### Setting Up Peers

```solidity
// CRITICAL: Must set peers on both chains

// On Chain A (Ethereum, eid = 30101)
myOApp.setPeer(
    30110,  // Arbitrum eid
    bytes32(uint256(uint160(arbitrumContractAddress)))
);

// On Chain B (Arbitrum, eid = 30110)  
myOApp.setPeer(
    30101,  // Ethereum eid
    bytes32(uint256(uint160(ethereumContractAddress)))
);

// SECURITY: Only owner should be able to set peers
// Verify peer addresses carefully - wrong peer = lost funds
```

### Configuring Options

```solidity
import { OptionsBuilder } from "@layerzerolabs/oapp-evm/contracts/oapp/libs/OptionsBuilder.sol";

contract MyOApp is OApp {
    using OptionsBuilder for bytes;
    
    function sendWithGas(uint32 _dstEid, bytes memory _payload) external payable {
        // Build options for execution
        bytes memory options = OptionsBuilder.newOptions()
            .addExecutorLzReceiveOption(200000, 0)  // 200k gas, 0 value
            .addExecutorNativeDropOption(1 ether, receiver);  // Airdrop native
        
        _lzSend(_dstEid, _payload, options, MessagingFee(msg.value, 0), msg.sender);
    }
}
```

---

## Security Considerations

### 1. Peer Configuration Attacks

```solidity
// CRITICAL: Wrong peer = funds sent to wrong address

// Attack scenario:
// 1. Attacker deploys fake contract on destination
// 2. Tricks owner into setting wrong peer
// 3. All cross-chain transfers go to attacker

// Mitigations:
// - Multi-sig for setPeer
// - Timelock on peer changes
// - Verify peer address via multiple channels
// - Use deterministic deployment (CREATE2)

// Safe pattern:
function setPeer(uint32 _eid, bytes32 _peer) external onlyOwner {
    require(_peer != bytes32(0), "Invalid peer");
    // Consider adding timelock
    peers[_eid] = _peer;
}
```

### 2. DVN Trust Assumptions

```solidity
// DVNs verify cross-chain messages
// Compromised DVN = fake messages

// Security levels:
// 1 DVN → Single point of failure
// 2+ DVNs → Higher security

// Check:
// - Which DVNs are required?
// - Are DVNs reputable (Google Cloud, Polyhedra, etc.)?
// - Is DVN set diversified?

// Verify config:
function getUlnConfig(uint32 _eid) external view returns (UlnConfig memory);
```

### 3. Message Ordering

```solidity
// LayerZero V2 does NOT guarantee message ordering by default

// Attack scenario:
// 1. User sends message A (deposit)
// 2. User sends message B (withdraw)
// 3. Message B arrives before A
// 4. Withdraw fails or behaves unexpectedly

// Mitigations:
// - Use nonces for ordering
// - Design for out-of-order messages
// - Use lzCompose for atomic sequences

mapping(uint32 => uint64) public inboundNonce;

function _lzReceive(...) internal override {
    uint64 nonce = abi.decode(_message, (uint64, ...));
    require(nonce == inboundNonce[_origin.srcEid] + 1, "Out of order");
    inboundNonce[_origin.srcEid] = nonce;
}
```

### 4. Gas Estimation Failures

```solidity
// If destination gas is insufficient, message fails

// Attack: Send message with too little gas
// Result: Message stuck, funds potentially locked

// Mitigations:
// - Use quote() to estimate fees
// - Add buffer to gas estimates
// - Implement retry mechanism

function _lzReceive(...) internal override {
    // If this reverts, message is NOT delivered
    // Funds may be stuck!
    
    // Implement try/catch or ensure sufficient gas
}
```

### 5. Composed Message Risks

```solidity
// lzCompose allows chaining actions

// Risk: Composed message can call arbitrary contract
// If not validated, attacker can drain funds

function lzCompose(
    address _from,           // OApp that initiated
    bytes32 _guid,
    bytes calldata _message,
    address _executor,
    bytes calldata _extraData
) external payable {
    // CRITICAL: Validate _from is trusted OApp
    require(_from == trustedOApp, "Untrusted composer");
    
    // CRITICAL: Validate message contents
    (address target, bytes memory data) = abi.decode(_message, (address, bytes));
    require(isAllowedTarget(target), "Invalid target");
}
```

---

## Common Vulnerabilities

### 1. Missing Peer Validation

```solidity
// VULNERABLE: No check on incoming message source
function _lzReceive(Origin calldata _origin, ...) internal override {
    // Missing: verify _origin.sender == peers[_origin.srcEid]
    _processMessage(_message);
}

// SAFE: OApp base class checks this automatically
// But verify your implementation doesn't bypass it
```

### 2. Decimal Conversion Errors

```solidity
// OFT uses "shared decimals" (usually 6) for cross-chain

// VULNERABLE: Wrong decimal handling
function send(..., uint256 amountLD) {
    // amountLD = local decimals (e.g., 18)
    // Must convert to shared decimals (6)
    uint256 amountSD = amountLD / (10 ** (localDecimals - sharedDecimals));
    // Precision loss if not handled correctly!
}

// Check:
// - Rounding direction (round down for safety)
// - Dust amounts (too small to send)
// - Overflow on conversion back
```

### 3. Reentrancy in Receive

```solidity
// _lzReceive can trigger external calls

// VULNERABLE:
function _lzReceive(...) internal override {
    uint256 amount = abi.decode(_message, (uint256));
    balances[user] += amount;
    token.transfer(user, amount);  // Reentrancy point
}

// SAFE: CEI pattern
function _lzReceive(...) internal override nonReentrant {
    uint256 amount = abi.decode(_message, (uint256));
    balances[user] += amount;
    token.transfer(user, amount);
}
```

### 4. Stuck Messages

```solidity
// If _lzReceive reverts, message is NOT retried automatically

// Users need manual intervention to recover

// Mitigation: Implement recovery mechanism
mapping(bytes32 => bytes) public failedMessages;

function _lzReceive(...) internal override {
    try this.processMessage(_message) {
        // Success
    } catch {
        // Store for retry
        failedMessages[_guid] = _message;
        emit MessageFailed(_guid);
    }
}

function retryMessage(bytes32 _guid) external {
    bytes memory message = failedMessages[_guid];
    require(message.length > 0, "No failed message");
    delete failedMessages[_guid];
    processMessage(message);
}
```

---

## Endpoint IDs (Common Chains)

| Chain | Endpoint ID |
|-------|-------------|
| Ethereum | 30101 |
| Arbitrum | 30110 |
| Optimism | 30111 |
| Polygon | 30109 |
| BSC | 30102 |
| Avalanche | 30106 |
| Base | 30184 |
| Solana | 30168 |

---

## Audit Checklist

### OApp Security
```
[ ] Peers set correctly on all chains?
[ ] setPeer protected (onlyOwner + timelock)?
[ ] _lzReceive validates origin?
[ ] Message format well-defined and validated?
[ ] Reentrancy protection on receive?
```

### OFT Security
```
[ ] Decimal conversion correct?
[ ] Slippage protection (minAmountLD)?
[ ] Total supply conserved across chains?
[ ] Adapter locked tokens protected?
[ ] Dust handling appropriate?
```

### Configuration
```
[ ] DVN configuration secure (2+ DVNs)?
[ ] Gas limits appropriate per chain?
[ ] Fee estimation working?
[ ] Executor configured?
```

### Error Handling
```
[ ] Failed message recovery mechanism?
[ ] Events emitted for debugging?
[ ] No funds locked on revert?
[ ] Retry logic implemented?
```

---

## Quick Reference

| Parameter | Typical Value |
|-----------|---------------|
| Shared Decimals | 6 |
| Default Gas Limit | 200,000 |
| Message Expiry | None (queued) |
| DVN Requirement | 1-2 minimum |
| Confirmation Blocks | 15-256 |

---

## Related Resources

- [LayerZero V2 Docs](https://docs.layerzero.network/v2)
- [OApp Examples](https://github.com/LayerZero-Labs/devtools)
- [Endpoint Addresses](https://docs.layerzero.network/v2/deployments/mainnet)
- [DVN Addresses](https://docs.layerzero.network/v2/deployments/dvn-addresses)
