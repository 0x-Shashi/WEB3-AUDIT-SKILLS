---
id: PLAYBOOK-CHAINLINK
title: Chainlink Integration Playbook
category: protocol-playbooks
protocol: chainlink
difficulty: intermediate
tags: [chainlink, oracle, vrf, ccip, automation, price-feeds]
last_updated: 2026-01-31
---

# Chainlink Integration Playbook

Comprehensive guide for integrating with Chainlink services - the most widely used oracle network.

---

## Protocol Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                      Chainlink Services                          │
├──────────────┬──────────────┬──────────────┬────────────────────┤
│ Price Feeds  │     VRF      │  Automation  │       CCIP         │
│  (Oracles)   │ (Randomness) │  (Keepers)   │  (Cross-Chain)     │
├──────────────┼──────────────┼──────────────┼────────────────────┤
│ • Asset      │ • Provably   │ • Scheduled  │ • Token Transfer   │
│   prices     │   random     │   tasks      │ • Message Passing  │
│ • Aggregated │ • On-chain   │ • Conditional│ • Programmable     │
│ • Decentralized │ verifiable│   execution  │   Token Transfer   │
└──────────────┴──────────────┴──────────────┴────────────────────┘
```

---

## 1. Price Feeds

### Key Contracts

| Feed | Address (Mainnet) | Decimals |
|------|-------------------|----------|
| ETH/USD | `0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419` | 8 |
| BTC/USD | `0xF4030086522a5bEEa4988F8cA5B36dbC97BeE88c` | 8 |
| USDC/USD | `0x8fFfFfd4AfB6115b954Bd326cbe7B4BA576818f6` | 8 |
| LINK/USD | `0x2c1d072e956AFFC0D435Cb7AC38EF18d24d9127c` | 8 |

### Basic Integration

```solidity
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

contract PriceConsumer {
    AggregatorV3Interface internal priceFeed;
    
    constructor(address feedAddress) {
        priceFeed = AggregatorV3Interface(feedAddress);
    }
    
    function getLatestPrice() public view returns (int256 price, uint256 updatedAt) {
        (
            uint80 roundId,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        ) = priceFeed.latestRoundData();
        
        return (answer, updatedAt);
    }
}
```

###  Critical: Proper Price Feed Validation

```solidity
function getValidatedPrice() public view returns (int256) {
    (
        uint80 roundId,
        int256 answer,
        uint256 startedAt,
        uint256 updatedAt,
        uint80 answeredInRound
    ) = priceFeed.latestRoundData();
    
    // Check 1: Price is positive
    require(answer > 0, "Invalid price");
    
    // Check 2: Price is not stale
    require(
        block.timestamp - updatedAt <= MAX_STALENESS,
        "Stale price"
    );
    
    // Check 3: Round is complete
    require(
        answeredInRound >= roundId,
        "Round not complete"
    );
    
    // Check 4: Sequencer is up (L2 only)
    // See L2 Sequencer section below
    
    return answer;
}
```

### L2 Sequencer Uptime Feed

```solidity
// On Arbitrum, Optimism, etc. - check if sequencer is up
contract L2PriceConsumer {
    AggregatorV3Interface internal sequencerFeed;
    AggregatorV3Interface internal priceFeed;
    
    uint256 constant GRACE_PERIOD = 3600;  // 1 hour
    
    function getPrice() external view returns (int256) {
        // Check sequencer status
        (, int256 answer, uint256 startedAt,,) = sequencerFeed.latestRoundData();
        
        bool isSequencerUp = answer == 0;
        require(isSequencerUp, "Sequencer is down");
        
        // Check grace period after sequencer comes back up
        uint256 timeSinceUp = block.timestamp - startedAt;
        require(timeSinceUp > GRACE_PERIOD, "Grace period not over");
        
        // Now safe to get price
        return getValidatedPrice();
    }
}
```

### Common Vulnerabilities

```solidity
// VULNERABLE 1: No staleness check
function badGetPrice() external view returns (int256) {
    (, int256 answer,,,) = priceFeed.latestRoundData();
    return answer;  // Could be hours/days old!
}

// VULNERABLE 2: Wrong decimals
function badCalculation() external view returns (uint256) {
    (, int256 ethPrice,,,) = ethFeed.latestRoundData();  // 8 decimals
    uint256 ethAmount = 1e18;
    return ethAmount * uint256(ethPrice);  // Wrong! Missing decimal adjustment
}

// SECURE: Proper decimal handling
function goodCalculation() external view returns (uint256) {
    (, int256 ethPrice,,,) = ethFeed.latestRoundData();  // 8 decimals
    uint256 ethAmount = 1e18;
    return ethAmount * uint256(ethPrice) / 1e8;  // Correct
}
```

---

## 2. VRF (Verifiable Random Function)

### VRF v2.5 Integration

```solidity
import "@chainlink/contracts/src/v0.8/vrf/VRFConsumerBaseV2Plus.sol";
import "@chainlink/contracts/src/v0.8/vrf/VRFV2PlusClient.sol";

contract VRFConsumer is VRFConsumerBaseV2Plus {
    uint256 public subscriptionId;
    bytes32 public keyHash;
    uint32 public callbackGasLimit = 100000;
    uint16 public requestConfirmations = 3;
    uint32 public numWords = 1;
    
    mapping(uint256 => address) public requestToSender;
    
    constructor(
        uint256 _subscriptionId,
        address _vrfCoordinator,
        bytes32 _keyHash
    ) VRFConsumerBaseV2Plus(_vrfCoordinator) {
        subscriptionId = _subscriptionId;
        keyHash = _keyHash;
    }
    
    function requestRandomness() external returns (uint256 requestId) {
        requestId = s_vrfCoordinator.requestRandomWords(
            VRFV2PlusClient.RandomWordsRequest({
                keyHash: keyHash,
                subId: subscriptionId,
                requestConfirmations: requestConfirmations,
                callbackGasLimit: callbackGasLimit,
                numWords: numWords,
                extraArgs: VRFV2PlusClient._argsToBytes(
                    VRFV2PlusClient.ExtraArgsV1({nativePayment: false})
                )
            })
        );
        
        requestToSender[requestId] = msg.sender;
        return requestId;
    }
    
    function fulfillRandomWords(
        uint256 requestId,
        uint256[] calldata randomWords
    ) internal override {
        address sender = requestToSender[requestId];
        uint256 randomNumber = randomWords[0];
        
        // Use randomNumber for your application
        _processRandomness(sender, randomNumber);
    }
}
```

### VRF Security Checklist

```
[ ] Request confirmations >= 3?
[ ] Callback gas limit sufficient?
[ ] Request-response pattern (not single tx)?
[ ] requestId tracked to prevent replay?
[ ] No sensitive operations before fulfillment?
[ ] Subscription funded with LINK/native?
```

### Common VRF Vulnerabilities

```solidity
// VULNERABLE: Using randomness incorrectly
function fulfillRandomWords(uint256, uint256[] calldata randomWords) internal {
    // BAD: Modulo bias for small ranges
    uint256 winner = randomWords[0] % 3;  // Slightly biased!
    
    // SECURE: Use rejection sampling or expand randomness
    uint256 winner = _uniformRandom(randomWords[0], 3);
}

// VULNERABLE: Re-rolling randomness
function fulfillRandomWords(uint256 requestId, uint256[] calldata randomWords) internal {
    if (randomWords[0] % 10 < 5) {
        requestRandomness();  // BAD: Re-rolling for better outcome
    }
}
```

---

## 3. Automation (Keepers)

### Automation-Compatible Contract

```solidity
import "@chainlink/contracts/src/v0.8/automation/AutomationCompatible.sol";

contract AutomatedContract is AutomationCompatibleInterface {
    uint256 public lastTimeStamp;
    uint256 public interval = 1 hours;
    
    function checkUpkeep(
        bytes calldata /* checkData */
    ) external view override returns (
        bool upkeepNeeded,
        bytes memory performData
    ) {
        upkeepNeeded = (block.timestamp - lastTimeStamp) > interval;
        performData = "";
        return (upkeepNeeded, performData);
    }
    
    function performUpkeep(
        bytes calldata /* performData */
    ) external override {
        // Revalidate conditions (can be called by anyone)
        require(
            (block.timestamp - lastTimeStamp) > interval,
            "Too soon"
        );
        
        lastTimeStamp = block.timestamp;
        
        // Perform the automated task
        _doWork();
    }
}
```

### Automation Security

```solidity
// CRITICAL: performUpkeep can be called by anyone!
// Always revalidate conditions inside performUpkeep

// VULNERABLE: Trusting performData
function performUpkeep(bytes calldata performData) external {
    address user = abi.decode(performData, (address));
    _sendReward(user);  // Attacker can pass any address!
}

// SECURE: Derive data from contract state
function performUpkeep(bytes calldata) external {
    address user = pendingRewardRecipient;  // From contract storage
    require(user != address(0), "No pending");
    delete pendingRewardRecipient;
    _sendReward(user);
}
```

---

## 4. CCIP (Cross-Chain Interoperability Protocol)

### Sending Cross-Chain Messages

```solidity
import "@chainlink/contracts-ccip/src/v0.8/ccip/interfaces/IRouterClient.sol";
import "@chainlink/contracts-ccip/src/v0.8/ccip/libraries/Client.sol";

contract CCIPSender {
    IRouterClient public router;
    
    function sendMessage(
        uint64 destinationChainSelector,
        address receiver,
        bytes memory data
    ) external payable returns (bytes32 messageId) {
        Client.EVM2AnyMessage memory message = Client.EVM2AnyMessage({
            receiver: abi.encode(receiver),
            data: data,
            tokenAmounts: new Client.EVMTokenAmount[](0),
            extraArgs: "",
            feeToken: address(0)  // Pay in native
        });
        
        uint256 fees = router.getFee(destinationChainSelector, message);
        require(msg.value >= fees, "Insufficient fee");
        
        messageId = router.ccipSend{value: fees}(
            destinationChainSelector,
            message
        );
    }
}
```

### Receiving Cross-Chain Messages

```solidity
import "@chainlink/contracts-ccip/src/v0.8/ccip/CCIPReceiver.sol";

contract CCIPReceiver is CCIPReceiver {
    // Allowed source chains and senders
    mapping(uint64 => mapping(address => bool)) public allowedSenders;
    
    constructor(address router) CCIPReceiver(router) {}
    
    function _ccipReceive(
        Client.Any2EVMMessage memory message
    ) internal override {
        uint64 sourceChain = message.sourceChainSelector;
        address sender = abi.decode(message.sender, (address));
        
        // CRITICAL: Validate source
        require(
            allowedSenders[sourceChain][sender],
            "Unauthorized sender"
        );
        
        // Process message
        _processMessage(message.data);
    }
}
```

### CCIP Security Checklist

```
[ ] Source chain validated?
[ ] Source sender validated (not just any contract)?
[ ] Message replay protection?
[ ] Fee calculation correct?
[ ] Token approvals for token transfers?
[ ] Receiver contract handles failures gracefully?
```

---

## Common Pitfalls Summary

### Price Feeds
```
 Not checking staleness
 Not checking answer > 0
 Not checking answeredInRound >= roundId
 Not checking L2 sequencer status
 Wrong decimal handling
 Using deprecated latestAnswer()
```

### VRF
```
 Single-transaction randomness
 Re-requesting on unfavorable outcome
 Not tracking request IDs
 Modulo bias for small ranges
 Insufficient callback gas
```

### Automation
```
 Trusting performData blindly
 Not revalidating conditions in performUpkeep
 Gas-expensive checkUpkeep
 Not handling edge cases
```

### CCIP
```
 Not validating source chain
 Not validating source sender
 Message replay attacks
 Insufficient fee handling
```

---

## Quick Reference

### Price Feed Addresses (Mainnet)

| Pair | Address | Decimals | Heartbeat |
|------|---------|----------|-----------|
| ETH/USD | 0x5f4eC3Df9...5b8419 | 8 | 1 hour |
| BTC/USD | 0xF4030086...BE88c | 8 | 1 hour |
| LINK/USD | 0x2c1d072e...9127c | 8 | 1 hour |
| USDC/USD | 0x8fFfFfd4...818f6 | 8 | 24 hours |

### VRF Coordinators

| Chain | Coordinator |
|-------|-------------|
| Ethereum | 0x271682DEB8C4E0901D1a1550aD2e64D568E69909 |
| Arbitrum | 0x41034678D6C633D8a95c75e1138A360a28bA15d1 |
| Polygon | 0xAE975071Be8F8eE67addBC1A82488F1C24858067 |

### Recommended Staleness Thresholds

| Asset Type | Max Staleness |
|------------|---------------|
| Major pairs (ETH, BTC) | 1 hour |
| Stablecoins | 24 hours |
| Alt tokens | 1 hour |
| L2 assets | 1 hour + grace period |
