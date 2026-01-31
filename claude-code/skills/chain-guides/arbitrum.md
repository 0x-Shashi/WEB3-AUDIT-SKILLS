---
id: CHAIN-ARBITRUM
title: Arbitrum Security Guide
category: chain-guides
chain: arbitrum
difficulty: advanced
tags: [arbitrum, l2, optimistic-rollup, sequencer, retryable]
last_updated: 2026-01-31
---

# Arbitrum Security Guide

## Overview

Arbitrum is an optimistic rollup L2 on Ethereum. While it's EVM-compatible, there are critical security differences that auditors must understand.

## Key Differences from Ethereum L1

| Aspect | Ethereum L1 | Arbitrum |
|--------|-------------|----------|
| Block Time | ~12 seconds | ~250ms |
| Finality | ~15 minutes | 7 days (L1 finality) |
| Sequencer | Decentralized | Centralized |
| Gas Pricing | EIP-1559 | L2 gas + L1 calldata |
| Block Number | L1 blocks | Arbitrum blocks (different!) |

## Critical Vulnerability Categories

### 1. Sequencer Downtime/Failure

The Arbitrum sequencer is a single point of failure. If it goes down, user transactions are delayed until the delayed inbox processes them.

```solidity
// VULNERABLE - Assumes constant block production
contract TimeLockedVault {
    mapping(address => uint256) public unlockTime;
    
    function withdraw() external {
        // If sequencer is down, block.timestamp may jump
        require(block.timestamp >= unlockTime[msg.sender], "Still locked");
        // User could be locked out longer than expected
    }
}
```

```solidity
// SECURE - Account for sequencer downtime
contract TimeLockedVault {
    mapping(address => uint256) public unlockTime;
    uint256 public constant GRACE_PERIOD = 1 hours;
    
    function withdraw() external {
        // Add grace period for sequencer issues
        require(
            block.timestamp >= unlockTime[msg.sender] ||
            sequencerDownFor() > GRACE_PERIOD,
            "Still locked"
        );
    }
    
    function sequencerDownFor() internal view returns (uint256) {
        // Check Arbitrum's sequencer uptime feed
        // Implementation varies
    }
}
```

### 2. L1 to L2 Message Handling (Retryable Tickets)

Cross-chain messages from L1 to L2 can fail and need manual retry.

```solidity
// VULNERABLE - Assumes L1->L2 always succeeds
contract L1Bridge {
    function bridgeTokens(uint256 amount) external {
        // Lock tokens on L1
        token.transferFrom(msg.sender, address(this), amount);
        
        // Send message to L2
        // If this fails and isn't retried, tokens are locked forever!
        inbox.createRetryableTicket{value: msg.value}(
            l2Target,
            0,
            maxSubmissionCost,
            msg.sender,  // Refund address
            msg.sender,  // Recipient
            maxGas,
            gasPriceBid,
            abi.encodeCall(L2Bridge.mint, (msg.sender, amount))
        );
    }
}
```

```solidity
// SECURE - Handle failed retryables
contract L1Bridge {
    mapping(bytes32 => PendingDeposit) public pendingDeposits;
    
    function bridgeTokens(uint256 amount) external returns (bytes32 ticketId) {
        token.transferFrom(msg.sender, address(this), amount);
        
        ticketId = inbox.createRetryableTicket{value: msg.value}(...);
        
        // Track pending deposit
        pendingDeposits[ticketId] = PendingDeposit({
            user: msg.sender,
            amount: amount,
            timestamp: block.timestamp
        });
    }
    
    // Allow refund if retryable expired without execution
    function refundExpiredDeposit(bytes32 ticketId) external {
        PendingDeposit memory deposit = pendingDeposits[ticketId];
        require(deposit.amount > 0, "No deposit");
        
        // Check if retryable expired (14 days on Arbitrum)
        require(
            block.timestamp > deposit.timestamp + 14 days,
            "Not expired"
        );
        
        // Verify ticket wasn't redeemed (check L2 state or event)
        require(!wasRedeemed(ticketId), "Already redeemed");
        
        delete pendingDeposits[ticketId];
        token.transfer(deposit.user, deposit.amount);
    }
}
```

### 3. Block Number Discrepancies

Arbitrum has its own block numbers, separate from L1.

```solidity
// VULNERABLE - Mixing block semantics
contract BlockBasedLogic {
    // This is ARBITRUM block number, not L1!
    uint256 public lastL1Block = block.number;
    
    function checkL1Blocks() external view returns (bool) {
        // Wrong! block.number is Arbitrum blocks
        return block.number > lastL1Block + 100;
    }
}
```

```solidity
// SECURE - Use ArbSys for L1 block number
import {ArbSys} from "@arbitrum/nitro-contracts/src/precompiles/ArbSys.sol";

contract BlockBasedLogic {
    ArbSys constant arbSys = ArbSys(address(100));
    
    uint256 public lastL1Block;
    
    function updateL1Block() external {
        // Get actual L1 block number
        lastL1Block = arbSys.arbBlockNumber();
    }
    
    function getL1BlockNumber() external view returns (uint256) {
        return arbSys.arbBlockNumber();
    }
    
    function getL2BlockNumber() external view returns (uint256) {
        return block.number;  // This is L2 block
    }
}
```

### 4. Gas Price Manipulation

Arbitrum gas pricing is different - includes L1 data costs.

```solidity
// VULNERABLE - Using tx.gasprice for logic
contract GasPriceDependent {
    function doSomething() external {
        // tx.gasprice on Arbitrum includes L2 gas + L1 calldata
        // Can be manipulated differently than on L1
        require(tx.gasprice < 100 gwei, "Gas too high");
    }
}
```

### 5. Address Aliasing for L1 -> L2 Messages

When an L1 contract sends a message to L2, its address is aliased.

```solidity
// L1 Contract
contract L1Sender {
    // Address: 0x1234...
    
    function sendToL2() external {
        inbox.createRetryableTicket(...);
        // On L2, msg.sender will be:
        // 0x1234... + 0x1111000000000000000000000000000000001111
        // = ALIASED address
    }
}

// L2 Contract
contract L2Receiver {
    address public expectedL1Sender = 0x1234...;
    
    // VULNERABLE - Doesn't account for aliasing
    function receiveFromL1() external {
        require(msg.sender == expectedL1Sender);  // FAILS!
    }
    
    // SECURE - Apply alias
    function receiveFromL1() external {
        address aliasedSender = applyL1ToL2Alias(expectedL1Sender);
        require(msg.sender == aliasedSender);
    }
    
    function applyL1ToL2Alias(address l1Address) internal pure returns (address) {
        uint160 offset = uint160(0x1111000000000000000000000000000000001111);
        return address(uint160(l1Address) + offset);
    }
}
```

### 6. Sequencer Feed for Oracles

Chainlink on Arbitrum has a sequencer uptime feed that should be checked.

```solidity
// VULNERABLE - No sequencer check
contract PriceFeed {
    function getPrice() external view returns (uint256) {
        (, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
        require(block.timestamp - updatedAt < 1 hours, "Stale");
        return uint256(price);
    }
}

// SECURE - Check sequencer status
contract PriceFeed {
    AggregatorV3Interface public sequencerUptimeFeed;
    uint256 public constant GRACE_PERIOD = 1 hours;
    
    function getPrice() external view returns (uint256) {
        // Check sequencer status
        (, int256 answer, uint256 startedAt, , ) = 
            sequencerUptimeFeed.latestRoundData();
        
        bool isSequencerUp = answer == 0;
        if (!isSequencerUp) {
            revert("Sequencer down");
        }
        
        // Ensure grace period has passed since sequencer came back up
        uint256 timeSinceUp = block.timestamp - startedAt;
        if (timeSinceUp < GRACE_PERIOD) {
            revert("Grace period not passed");
        }
        
        // Now safe to get price
        (, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
        require(block.timestamp - updatedAt < 1 hours, "Stale");
        return uint256(price);
    }
}
```

## Arbitrum-Specific Precompiles

```solidity
// Arbitrum precompiles at address 100
interface ArbSys {
    function arbBlockNumber() external view returns (uint256);
    function arbBlockHash(uint256 blockNum) external view returns (bytes32);
    function arbChainID() external view returns (uint256);
    function sendTxToL1(address destination, bytes calldata data) 
        external payable returns (uint256);
    function withdrawEth(address destination) external payable returns (uint256);
    function isTopLevelCall() external view returns (bool);
}

// Usage
ArbSys constant arbSys = ArbSys(address(100));
uint256 l1BlockNum = arbSys.arbBlockNumber();
```

## Audit Checklist

```
[ ] Sequencer downtime handling
[ ] Retryable ticket failure handling
[ ] L1 vs L2 block number usage
[ ] Address aliasing for L1->L2 calls
[ ] Chainlink sequencer uptime feed check
[ ] Gas price assumptions reviewed
[ ] Withdrawal delay handling (7 days)
[ ] L2 to L1 message verification
[ ] Precompile usage correctness
```

## Common Patterns

### Safe L1 -> L2 Communication
```solidity
// On L1: Send with proper gas and value
inbox.createRetryableTicket{value: submissionFee + executionFee}(
    l2Receiver,
    l2CallValue,
    maxSubmissionCost,
    excessFeeRefundAddress,
    callValueRefundAddress,
    maxGas,
    gasPriceBid,
    data
);
```

### Safe L2 -> L1 Communication
```solidity
// On L2: Send outbox message
uint256 id = arbSys.sendTxToL1(l1Target, data);

// On L1: Execute after challenge period (7 days)
outbox.executeTransaction(proof, index, l2Sender, l1Target, value, data);
```
