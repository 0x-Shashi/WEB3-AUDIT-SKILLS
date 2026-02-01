---
id: PLAYBOOK-ACROSS
title: Across Protocol Integration Playbook
category: protocol-playbooks
protocol: across
version: v3
difficulty: advanced
tags: [across, bridge, cross-chain, relayer, optimistic, intents]
last_updated: 2026-01-31
---

# Across Protocol Integration Playbook

## Protocol Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     ACROSS PROTOCOL V3                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  User Request                          Relayer Fulfillment      │
│  ┌─────────────┐                       ┌─────────────┐         │
│  │  Origin     │  Intent: Send 1 ETH   │ Destination │         │
│  │  Chain      │  ─────────────────►   │  Chain      │         │
│  │  (Deposit)  │                       │  (Fill)     │         │
│  └──────┬──────┘                       └──────┬──────┘         │
│         │                                     │                 │
│         │         ┌─────────────────┐         │                 │
│         └────────►│    HubPool      │◄────────┘                 │
│                   │   (Ethereum)    │                           │
│                   │   - Liquidity   │                           │
│                   │   - Settlement  │                           │
│                   │   - UMA Oracle  │                           │
│                   └─────────────────┘                           │
│                           │                                     │
│                   ┌───────▼───────┐                             │
│                   │  SpokePool    │ (On each supported chain)   │
│                   │  - Deposits   │                             │
│                   │  - Fills      │                             │
│                   │  - Refunds    │                             │
│                   └───────────────┘                             │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Concepts

### 1. Optimistic Bridge Model

```solidity
// Across uses an "intent-based" optimistic model:

// 1. User deposits on origin chain (creates intent)
// 2. Relayer sees intent, fills on destination (fronts liquidity)
// 3. Relayer claims reimbursement from HubPool later
// 4. UMA oracle verifies fills were valid

// Benefits:
// - Fast fills (relayer fronts funds)
// - Capital efficient (relayers reuse liquidity)
// - Optimistic = cheaper than immediate verification
```

### 2. Core Components

```solidity
// HubPool (Ethereum mainnet)
// - Central liquidity aggregation
// - LP deposits
// - Relayer reimbursements
// - UMA oracle integration

// SpokePool (Each chain)
// - Handles deposits from users
// - Handles fills from relayers
// - Communicates with HubPool

// Relayers
// - Off-chain actors
// - Front liquidity for fast fills
// - Earn fees for service
```

### 3. Deposit Flow

```solidity
struct V3DepositParams {
    address depositor;
    address recipient;
    address inputToken;
    address outputToken;
    uint256 inputAmount;
    uint256 outputAmount;     // After fees (user receives this)
    uint256 destinationChainId;
    address exclusiveRelayer; // Optional: specific relayer only
    uint32 quoteTimestamp;    // For fee calculation
    uint32 fillDeadline;      // Must fill before this
    uint32 exclusivityDeadline;
    bytes message;            // Optional: call data for recipient
}
```

---

## Integration Patterns

### User Deposit (Origin Chain)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISpokePool {
    function depositV3(
        address depositor,
        address recipient,
        address inputToken,
        address outputToken,
        uint256 inputAmount,
        uint256 outputAmount,
        uint256 destinationChainId,
        address exclusiveRelayer,
        uint32 quoteTimestamp,
        uint32 fillDeadline,
        uint32 exclusivityDeadline,
        bytes calldata message
    ) external payable;
    
    function getCurrentTime() external view returns (uint256);
}

contract AcrossIntegration {
    ISpokePool public spokePool;
    
    // Bridge tokens to another chain
    function bridgeTokens(
        address token,
        uint256 amount,
        uint256 destinationChainId,
        address recipient
    ) external {
        // 1. Transfer tokens from user
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        IERC20(token).approve(address(spokePool), amount);
        
        // 2. Calculate output amount (after fees)
        // In production, query the Across API for accurate quote
        uint256 fees = amount * 5 / 10000;  // ~0.05% example
        uint256 outputAmount = amount - fees;
        
        // 3. Set deadlines
        uint32 currentTime = uint32(spokePool.getCurrentTime());
        uint32 fillDeadline = currentTime + 3600;  // 1 hour
        
        // 4. Deposit
        spokePool.depositV3(
            msg.sender,           // depositor (for refunds)
            recipient,            // recipient on destination
            token,                // input token
            token,                // output token (same token)
            amount,               // input amount
            outputAmount,         // output amount (after fees)
            destinationChainId,
            address(0),           // no exclusive relayer
            currentTime,          // quote timestamp
            fillDeadline,
            0,                    // no exclusivity
            ""                    // no message
        );
    }
    
    // Bridge ETH
    function bridgeETH(
        uint256 destinationChainId,
        address recipient
    ) external payable {
        uint256 fees = msg.value * 5 / 10000;
        uint256 outputAmount = msg.value - fees;
        
        uint32 currentTime = uint32(spokePool.getCurrentTime());
        
        spokePool.depositV3{value: msg.value}(
            msg.sender,
            recipient,
            address(0),  // ETH represented as address(0) or WETH
            address(0),
            msg.value,
            outputAmount,
            destinationChainId,
            address(0),
            currentTime,
            currentTime + 3600,
            0,
            ""
        );
    }
}
```

### Relayer Fill (Destination Chain)

```solidity
interface ISpokePool {
    function fillV3Relay(
        V3RelayData calldata relayData,
        uint256 repaymentChainId
    ) external;
}

struct V3RelayData {
    address depositor;
    address recipient;
    address exclusiveRelayer;
    address inputToken;
    address outputToken;
    uint256 inputAmount;
    uint256 outputAmount;
    uint256 originChainId;
    uint32 depositId;
    uint32 fillDeadline;
    uint32 exclusivityDeadline;
    bytes message;
}

contract RelayerBot {
    ISpokePool public spokePool;
    
    // Fill a user's bridge request
    function fillRelay(V3RelayData calldata relay) external {
        // 1. Verify relay is profitable
        require(isProfitable(relay), "Not profitable");
        
        // 2. Transfer output tokens to recipient
        IERC20(relay.outputToken).approve(address(spokePool), relay.outputAmount);
        
        // 3. Execute fill
        spokePool.fillV3Relay(
            relay,
            1  // Repayment on Ethereum (chainId 1)
        );
        
        // 4. Relayer gets reimbursed from HubPool later
    }
}
```

### Cross-Chain Message (with calldata)

```solidity
// Across supports arbitrary message passing

function bridgeWithMessage(
    address token,
    uint256 amount,
    uint256 destinationChainId,
    address targetContract,
    bytes calldata callData
) external {
    IERC20(token).transferFrom(msg.sender, address(this), amount);
    IERC20(token).approve(address(spokePool), amount);
    
    uint32 currentTime = uint32(spokePool.getCurrentTime());
    
    // Message format: target address + calldata
    bytes memory message = abi.encode(targetContract, callData);
    
    spokePool.depositV3(
        msg.sender,
        address(messageHandler),  // Handler contract on destination
        token,
        token,
        amount,
        amount - fees,
        destinationChainId,
        address(0),
        currentTime,
        currentTime + 3600,
        0,
        message  // Include the message
    );
}

// On destination chain:
contract MessageHandler {
    function handleV3AcrossMessage(
        address token,
        uint256 amount,
        address depositor,
        bytes calldata message
    ) external onlySpokePool {
        (address target, bytes memory callData) = abi.decode(message, (address, bytes));
        
        // Transfer tokens and execute call
        IERC20(token).transfer(target, amount);
        (bool success,) = target.call(callData);
        require(success, "Call failed");
    }
}
```

---

## Security Considerations

### 1. Fill Deadline & Expiry

```solidity
// CRITICAL: Deposits have fill deadlines

// If not filled by deadline:
// - User can request refund on origin chain
// - Relayers cannot fill after deadline

// Risk: Deadline too short
// - Network congestion delays relayers
// - User doesn't get filled, must claim refund

// Risk: Deadline too long
// - Capital locked longer
// - Price movements during wait

// Audit check:
// [ ] Reasonable fill deadline (30min - 24hrs)?
// [ ] Refund mechanism works correctly?
// [ ] No way to fill after deadline?
```

### 2. Relayer Front-Running

```solidity
// Multiple relayers compete to fill

// Attack: Front-run other relayers
// - See pending fill transaction
// - Submit own fill with higher gas
// - Steal the fee

// Mitigations in Across:
// 1. Exclusive relayer period
// 2. Relayer reputation system

// Check exclusivity handling:
function fillV3Relay(V3RelayData calldata relay, ...) external {
    if (relay.exclusiveRelayer != address(0)) {
        if (block.timestamp <= relay.exclusivityDeadline) {
            require(msg.sender == relay.exclusiveRelayer, "Exclusive period");
        }
    }
    // ... fill logic
}
```

### 3. Oracle Manipulation (UMA)

```solidity
// Across uses UMA's optimistic oracle for settlement

// Process:
// 1. Relayer submits fill proof
// 2. Challenge period (usually 2 hours)
// 3. If disputed, UMA DVM resolves
// 4. If valid, relayer gets reimbursed

// Risk: Fraudulent fill claims
// - Relayer claims to fill but didn't
// - Must be disputed within window

// Mitigations:
// - Watchers monitor for fraud
// - Bond required for claims
// - Slashing for fraudulent claims
```

### 4. Token Mismatch Attacks

```solidity
// VULNERABLE: Not verifying token addresses match
function handleBridge(
    address inputToken,
    address outputToken,
    uint256 amount
) external {
    // If inputToken != outputToken, verify exchange rate
    // Or ensure they're equivalent (e.g., USDC on different chains)
}

// Across supports same-token bridging
// Cross-token swaps require additional verification
```

### 5. Message Handler Vulnerabilities

```solidity
// VULNERABLE: Unrestricted message handling
function handleMessage(bytes calldata message) external {
    (address target, bytes memory data) = abi.decode(message, (address, bytes));
    target.call(data);  // Arbitrary call!
}

// SAFE: Validate message source and content
function handleMessage(bytes calldata message) external {
    require(msg.sender == spokePool, "Only SpokePool");
    
    (address target, bytes memory data) = abi.decode(message, (address, bytes));
    require(allowedTargets[target], "Invalid target");
    
    // Validate function selector
    bytes4 selector = bytes4(data);
    require(allowedSelectors[selector], "Invalid function");
    
    target.call(data);
}
```

---

## Common Vulnerabilities

### 1. Refund Race Condition

```solidity
// User requests refund while relayer fills

// Timeline:
// T=0: User deposits
// T=1h: Deadline passes
// T=1h+1: User requests refund
// T=1h+1: Relayer fills (on destination)
// Result: User gets both refund AND filled tokens?

// Across prevents this:
// - Refund only available after deadline
// - Fills invalid after deadline
// - Verified at HubPool settlement
```

### 2. Replay Attacks

```solidity
// Each deposit has unique ID

// VULNERABLE: Reusing deposit ID
// Relayer fills same deposit multiple times

// Across mitigation:
mapping(uint256 => mapping(uint256 => uint256)) public fillStatuses;

function fillV3Relay(...) external {
    bytes32 relayHash = hashRelay(relay);
    require(fillStatuses[originChainId][depositId] == 0, "Already filled");
    fillStatuses[originChainId][depositId] = 1;
    // ... fill
}
```

### 3. Fee Calculation Errors

```solidity
// Fees based on:
// - Liquidity utilization
// - Gas costs on destination
// - LP APY requirements

// Risk: Quote stale at execution time
// User gets less than expected

// Safe integration:
function bridge(uint256 amount, uint256 minOutput) external {
    uint256 outputAmount = getQuotedOutput(amount);
    require(outputAmount >= minOutput, "Slippage exceeded");
    
    spokePool.depositV3(..., outputAmount, ...);
}
```

### 4. Liquidity Provider Risks

```solidity
// LPs deposit to HubPool, earn fees

// Risks:
// - Utilization too high = can't withdraw
// - Bridge congestion delays
// - Smart contract risk

// LP should check:
// - Current utilization rate
// - Historical fill times
// - Insurance/coverage fund size
```

---

## Audit Checklist

### Deposit Security
```
[ ] Deposit amount validated (> 0, within limits)?
[ ] Fill deadline reasonable?
[ ] Recipient address validated (not zero)?
[ ] Token addresses verified?
[ ] Slippage protection (minOutput)?
```

### Fill Security
```
[ ] Fill only possible before deadline?
[ ] Relayer can't fill twice?
[ ] Exclusivity period enforced?
[ ] Output amount matches deposit?
[ ] Message handling secure?
```

### Settlement Security
```
[ ] UMA oracle integration correct?
[ ] Challenge period sufficient?
[ ] Bond amounts appropriate?
[ ] Fraud detection working?
```

### Integration Security
```
[ ] Only SpokePool can call handlers?
[ ] Message content validated?
[ ] Reentrancy protection?
[ ] Token approval hygiene?
```

---

## Contract Addresses

| Chain | SpokePool |
|-------|-----------|
| Ethereum | `0x5c7BCd6E7De5423a257D81B442095A1a6ced35C5` |
| Arbitrum | `0xe35e9842fceaCA96570B734083f4a58e8F7C5f2A` |
| Optimism | `0x6f26Bf09B1C792e3228e5467807a900A503c0281` |
| Polygon | `0x9295ee1d8C5b022Be115A2AD3c30C72E34e7F096` |
| Base | `0x09aea4b2242abC8bb4BB78D537A67a245A7bEC64` |

---

## Quick Reference

| Parameter | Typical Value |
|-----------|---------------|
| Fill Deadline | 30 min - 6 hours |
| Exclusivity Period | 0 - 5 minutes |
| Base Fee | 0.04-0.12% |
| Min Deposit | $1-10 |
| Settlement Time | 2-4 hours |

---

## Related Resources

- [Across Docs](https://docs.across.to/)
- [API Reference](https://docs.across.to/reference/overview)
- [Contract Addresses](https://docs.across.to/reference/contracts)
- [Relayer Guide](https://docs.across.to/relayers/overview)
