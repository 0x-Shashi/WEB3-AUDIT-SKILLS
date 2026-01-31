---
id: CHAIN-OPTIMISM
title: Optimism Security Guide
category: chain-guides
chain: optimism
difficulty: advanced
tags: [optimism, l2, optimistic-rollup, cross-domain, bedrock]
last_updated: 2026-01-31
---

# Optimism Security Guide

## Overview

Optimism is an optimistic rollup L2 on Ethereum. Post-Bedrock upgrade, it shares many similarities with Arbitrum but has its own unique security considerations.

## Key Differences from Ethereum L1

| Aspect | Ethereum L1 | Optimism |
|--------|-------------|----------|
| Block Time | ~12 seconds | ~2 seconds |
| Finality | ~15 minutes | 7 days (challenge period) |
| Sequencer | Decentralized | Centralized |
| EVM Differences | Standard | Minor differences |
| Withdrawals | Instant | 7-day challenge period |

## Critical Vulnerability Categories

### 1. Cross-Domain Messaging

Optimism uses a messenger contract for L1<->L2 communication.

```solidity
// VULNERABLE - No sender verification
contract L2Receiver {
    function processMessage(bytes calldata data) external {
        // Anyone can call this!
        _processData(data);
    }
}

// SECURE - Verify cross-domain sender
import {ICrossDomainMessenger} from "@eth-optimism/contracts/libraries/bridge/ICrossDomainMessenger.sol";

contract L2Receiver {
    ICrossDomainMessenger public messenger;
    address public expectedL1Sender;
    
    function processMessage(bytes calldata data) external {
        // Verify call came from messenger
        require(msg.sender == address(messenger), "Not messenger");
        
        // Verify the L1 sender
        require(
            messenger.xDomainMessageSender() == expectedL1Sender,
            "Invalid sender"
        );
        
        _processData(data);
    }
}
```

### 2. Deposit/Withdrawal Handling

Deposits can fail and need handling.

```solidity
// VULNERABLE - Assumes deposit always works
contract L1Bridge {
    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        
        // What if this message never executes on L2?
        messenger.sendMessage(
            l2Bridge,
            abi.encodeCall(L2Bridge.finalize, (msg.sender, amount)),
            1000000
        );
    }
}

// SECURE - Track deposits and allow refunds
contract L1Bridge {
    mapping(bytes32 => DepositInfo) public deposits;
    
    function deposit(uint256 amount) external returns (bytes32 depositId) {
        token.transferFrom(msg.sender, address(this), amount);
        
        depositId = keccak256(abi.encode(msg.sender, amount, block.timestamp));
        deposits[depositId] = DepositInfo({
            user: msg.sender,
            amount: amount,
            timestamp: block.timestamp,
            finalized: false
        });
        
        messenger.sendMessage(
            l2Bridge,
            abi.encodeCall(L2Bridge.finalize, (depositId, msg.sender, amount)),
            1000000
        );
    }
    
    // Called by L2 to confirm deposit was processed
    function confirmDeposit(bytes32 depositId) external {
        require(msg.sender == address(messenger), "Not messenger");
        require(messenger.xDomainMessageSender() == l2Bridge, "Invalid sender");
        
        deposits[depositId].finalized = true;
    }
    
    // Refund if deposit never confirmed
    function refundStuckDeposit(bytes32 depositId) external {
        DepositInfo storage deposit = deposits[depositId];
        require(!deposit.finalized, "Already finalized");
        require(block.timestamp > deposit.timestamp + 14 days, "Too early");
        require(msg.sender == deposit.user, "Not depositor");
        
        uint256 amount = deposit.amount;
        delete deposits[depositId];
        token.transfer(msg.sender, amount);
    }
}
```

### 3. Block Number and Timestamp Behavior

Optimism has specific rules about block production.

```solidity
// IMPORTANT: Optimism block behavior
// - block.number: L2 block number (not L1!)
// - block.timestamp: L2 timestamp
// - Blocks are produced every 2 seconds
// - Empty blocks are possible

// Getting L1 block info
interface L1Block {
    function number() external view returns (uint64);
    function timestamp() external view returns (uint64);
    function basefee() external view returns (uint256);
    function hash() external view returns (bytes32);
}

L1Block constant l1Block = L1Block(0x4200000000000000000000000000000000000015);

function getL1BlockNumber() external view returns (uint64) {
    return l1Block.number();
}
```

### 4. Gas Handling Differences

```solidity
// Optimism gas considerations:
// 1. L1 data fee (for calldata posted to L1)
// 2. L2 execution fee

// Get the L1 data fee for a transaction
interface GasPriceOracle {
    function getL1Fee(bytes memory _data) external view returns (uint256);
    function gasPrice() external view returns (uint256);
    function l1BaseFee() external view returns (uint256);
    function overhead() external view returns (uint256);
    function scalar() external view returns (uint256);
}

GasPriceOracle constant oracle = GasPriceOracle(0x420000000000000000000000000000000000000F);

function estimateTotalFee(bytes memory txData) external view returns (uint256) {
    uint256 l1Fee = oracle.getL1Fee(txData);
    uint256 l2Fee = gasleft() * tx.gasprice;
    return l1Fee + l2Fee;
}
```

### 5. Sequencer Failures

Similar to Arbitrum, sequencer downtime affects oracle freshness.

```solidity
// SECURE - Check sequencer status for Chainlink
contract OptimismPriceFeed {
    AggregatorV3Interface public sequencerUptimeFeed;
    AggregatorV3Interface public priceFeed;
    uint256 public constant GRACE_PERIOD = 3600;
    
    function getPrice() public view returns (uint256) {
        // Check sequencer is up
        (, int256 answer, uint256 startedAt, , ) = 
            sequencerUptimeFeed.latestRoundData();
        
        if (answer != 0) revert("Sequencer down");
        if (block.timestamp - startedAt < GRACE_PERIOD) {
            revert("Grace period");
        }
        
        // Get price
        (, int256 price, , , ) = priceFeed.latestRoundData();
        return uint256(price);
    }
}
```

### 6. Standard Bridge Risks

The Standard Bridge has specific behaviors to handle.

```solidity
// Standard Bridge address
// L1: 0x99C9fc46f92E8a1c0deC1b1747d010903E884bE1
// L2: 0x4200000000000000000000000000000000000010

// Risks when using Standard Bridge:
// 1. Withdrawals take 7 days
// 2. Custom tokens need proper setup
// 3. ETH and ERC20 have different flows

// SECURE: Check token is properly registered
interface IL2StandardBridge {
    function l1TokenBridge() external view returns (address);
    function withdraw(
        address _l2Token,
        uint256 _amount,
        uint32 _minGasLimit,
        bytes calldata _extraData
    ) external payable;
}
```

## Optimism Predeploys

Optimism has system contracts at specific addresses:

```solidity
// Key predeploy addresses
address constant L2_CROSS_DOMAIN_MESSENGER = 0x4200000000000000000000000000000000000007;
address constant L2_STANDARD_BRIDGE = 0x4200000000000000000000000000000000000010;
address constant SEQUENCER_FEE_VAULT = 0x4200000000000000000000000000000000000011;
address constant L2_TO_L1_MESSAGE_PASSER = 0x4200000000000000000000000000000000000016;
address constant L1_BLOCK_ATTRIBUTES = 0x4200000000000000000000000000000000000015;
address constant GAS_PRICE_ORACLE = 0x420000000000000000000000000000000000000F;
address constant WETH9 = 0x4200000000000000000000000000000000000006;

// These CANNOT be deployed to by users
// They exist at genesis
```

## EVM Differences

```solidity
// Optimism EVM differences:

// 1. COINBASE returns Sequencer Fee Vault
// Not useful for identifying miners

// 2. PREVRANDAO may behave differently
// Don't rely on it for randomness (as usual)

// 3. DIFFICULTY is deprecated
// Returns 0 after Bedrock

// 4. Block gas limit
// Higher than L1 Ethereum
```

## Audit Checklist

```
[ ] Cross-domain messenger sender verification
[ ] Withdrawal handling (7-day delay)
[ ] Failed deposit handling
[ ] L1 vs L2 block/timestamp usage
[ ] Sequencer uptime checks for oracles
[ ] Gas fee estimation (L1 + L2)
[ ] Standard Bridge token compatibility
[ ] Predeploy usage correctness
[ ] No reliance on L1-specific behavior
```

## L1 -> L2 Message Pattern

```solidity
// L1 Side
contract L1Contract {
    ICrossDomainMessenger public messenger;
    
    function sendToL2(address l2Target, bytes calldata data) external {
        messenger.sendMessage(
            l2Target,
            data,
            1000000  // Gas limit for L2 execution
        );
    }
}

// L2 Side
contract L2Contract {
    ICrossDomainMessenger public messenger;
    address public l1Contract;
    
    function receiveFromL1(bytes calldata data) external {
        require(msg.sender == address(messenger));
        require(messenger.xDomainMessageSender() == l1Contract);
        
        // Process data
    }
}
```

## L2 -> L1 Message Pattern

```solidity
// L2 Side
contract L2Contract {
    ICrossDomainMessenger public messenger;
    
    function sendToL1(address l1Target, bytes calldata data) external {
        messenger.sendMessage(
            l1Target,
            data,
            0  // No gas limit needed for L1
        );
    }
}

// L1 Side (after 7 day challenge period)
contract L1Contract {
    ICrossDomainMessenger public messenger;
    address public l2Contract;
    
    function receiveFromL2(bytes calldata data) external {
        require(msg.sender == address(messenger));
        require(messenger.xDomainMessageSender() == l2Contract);
        
        // Process data
    }
}
```
