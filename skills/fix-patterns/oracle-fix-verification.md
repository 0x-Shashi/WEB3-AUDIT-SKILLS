# Oracle Fix Verification

## Overview

Oracle fixes have a **35% incomplete fix rate**. Most failures come from:
- TWAP window too short
- Missing staleness checks
- Incomplete multi-oracle fallback logic
- Decimals/precision errors

---

## 1. Before/After Code Comparisons

### 1.1 Spot Price Manipulation

**❌ VULNERABLE:**
```solidity
function getPrice() public view returns (uint256) {
    // Spot price from Uniswap - manipulable via flash loan
    (uint112 reserve0, uint112 reserve1, ) = pair.getReserves();
    return uint256(reserve1) * 1e18 / uint256(reserve0);
}
```

**❌ BAD FIX #1: TWAP with tiny window**
```solidity
function getPrice() public view returns (uint256) {
    // 1 block TWAP - still manipulable!
    return oracle.consult(token, 12);  // 12 seconds
}
// Problem: Multi-block manipulation is cheap
```

**❌ BAD FIX #2: TWAP but no staleness check**
```solidity
function getPrice() public view returns (uint256) {
    // 30 min TWAP but could be 3 days old
    (uint256 price, uint256 timestamp) = twapOracle.getPrice();
    return price;  // No staleness check!
}
// Problem: Oracle not updated = stale price
```

**✅ CORRECT FIX:**
```solidity
uint256 public constant TWAP_PERIOD = 30 minutes;
uint256 public constant MAX_STALENESS = 1 hours;
uint256 public constant MAX_DEVIATION = 500; // 5%

function getPrice() public view returns (uint256) {
    // Get TWAP price
    (uint256 twapPrice, uint256 twapTimestamp) = twapOracle.consult(token, TWAP_PERIOD);
    
    // Staleness check
    require(block.timestamp - twapTimestamp <= MAX_STALENESS, "Stale TWAP");
    
    // Cross-reference with Chainlink
    (, int256 chainlinkPrice, , uint256 clTimestamp, ) = chainlinkFeed.latestRoundData();
    require(chainlinkPrice > 0, "Invalid Chainlink price");
    require(block.timestamp - clTimestamp <= MAX_STALENESS, "Stale Chainlink");
    
    // Deviation check
    uint256 clPriceNormalized = uint256(chainlinkPrice) * 1e18 / 10**chainlinkDecimals;
    uint256 deviation = twapPrice > clPriceNormalized 
        ? (twapPrice - clPriceNormalized) * 10000 / clPriceNormalized
        : (clPriceNormalized - twapPrice) * 10000 / twapPrice;
    require(deviation <= MAX_DEVIATION, "Price deviation too high");
    
    return twapPrice;
}
```

---

### 1.2 Chainlink Staleness

**❌ VULNERABLE:**
```solidity
function getLatestPrice() public view returns (uint256) {
    (, int256 price, , , ) = priceFeed.latestRoundData();
    return uint256(price);
}
```

**❌ BAD FIX #1: Only checked price > 0**
```solidity
function getLatestPrice() public view returns (uint256) {
    (, int256 price, , , ) = priceFeed.latestRoundData();
    require(price > 0, "Invalid price");
    return uint256(price);
}
// Problem: No staleness, no round completeness check
```

**❌ BAD FIX #2: Wrong staleness calculation**
```solidity
function getLatestPrice() public view returns (uint256) {
    (uint80 roundId, int256 price, , uint256 updatedAt, uint80 answeredInRound) = 
        priceFeed.latestRoundData();
    
    // Wrong: Using answeredInRound for time comparison
    require(block.timestamp - answeredInRound < 3600, "Stale");
    return uint256(price);
}
// Problem: answeredInRound is a round ID, not timestamp!
```

**✅ CORRECT FIX:**
```solidity
uint256 public constant HEARTBEAT = 3600; // 1 hour for ETH/USD

function getLatestPrice() public view returns (uint256) {
    (
        uint80 roundId,
        int256 price,
        ,
        uint256 updatedAt,
        uint80 answeredInRound
    ) = priceFeed.latestRoundData();
    
    // Validate round completeness
    require(answeredInRound >= roundId, "Stale round");
    
    // Validate price
    require(price > 0, "Invalid price");
    
    // Validate staleness
    require(block.timestamp - updatedAt <= HEARTBEAT, "Stale price");
    
    return uint256(price);
}
```

---

### 1.3 LP Token Price Manipulation

**❌ VULNERABLE:**
```solidity
function getLPTokenPrice() public view returns (uint256) {
    uint256 totalSupply = lpToken.totalSupply();
    (uint112 r0, uint112 r1, ) = pair.getReserves();
    
    // Manipulable via reserve manipulation
    uint256 totalValue = r0 * price0 + r1 * price1;
    return totalValue / totalSupply;
}
```

**❌ BAD FIX: Used fair reserves but wrong formula**
```solidity
function getLPTokenPrice() public view returns (uint256) {
    uint256 totalSupply = lpToken.totalSupply();
    
    // Alpha Homora fair reserve calculation (incomplete)
    uint256 sqrtK = sqrt(uint256(r0) * uint256(r1));
    uint256 px0 = getOraclePrice(token0);
    uint256 px1 = getOraclePrice(token1);
    
    return sqrtK * 2 * sqrt(px0 * px1) / totalSupply;
}
// Problem: Missing decimal normalization
```

**✅ CORRECT FIX: Alpha Homora v2 formula**
```solidity
function getLPTokenPrice() public view returns (uint256) {
    uint256 totalSupply = lpToken.totalSupply();
    (uint112 r0, uint112 r1, ) = pair.getReserves();
    
    // Get oracle prices (normalized to 18 decimals)
    uint256 px0 = getOraclePrice(token0);  // 18 decimals
    uint256 px1 = getOraclePrice(token1);  // 18 decimals
    
    // Fair reserve calculation
    // fairR0 = sqrt(k * px1 / px0)
    // fairR1 = sqrt(k * px0 / px1)
    uint256 k = uint256(r0) * uint256(r1);
    uint256 fairR0 = sqrt(k * px1 / px0);
    uint256 fairR1 = sqrt(k * px0 / px1);
    
    // Fair LP price = (fairR0 * px0 + fairR1 * px1) / totalSupply
    uint256 fairValue = fairR0 * px0 / 1e18 + fairR1 * px1 / 1e18;
    
    // Normalize by LP token decimals
    return fairValue * 1e18 / totalSupply;
}
```

---

## 2. Regression Test Templates

### 2.1 Flash Loan Price Manipulation Test

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/Protocol.sol";

contract OracleManipulationTest is Test {
    Protocol protocol;
    IUniswapV2Pair pair;
    IERC20 token0;
    IERC20 token1;
    
    function setUp() public {
        // Fork mainnet
        vm.createSelectFork("mainnet", 18_000_000);
        
        protocol = Protocol(PROTOCOL_ADDRESS);
        pair = IUniswapV2Pair(PAIR_ADDRESS);
        token0 = IERC20(pair.token0());
        token1 = IERC20(pair.token1());
    }
    
    /// @notice Flash loan manipulation - should fail after fix
    function test_FlashLoanManipulation_ShouldFail() public {
        // Record pre-manipulation price
        uint256 priceBefore = protocol.getPrice();
        
        // Simulate flash loan manipulation
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        
        // Manipulate reserves (swap large amount)
        deal(address(token0), address(this), 1_000_000e18);
        token0.transfer(address(pair), 1_000_000e18);
        pair.swap(0, 500_000e18, address(this), "");
        
        // Try to get manipulated price
        uint256 priceAfter = protocol.getPrice();
        
        // AFTER FIX: Price should not have changed significantly (TWAP)
        // or transaction should revert (circuit breaker)
        uint256 deviation = priceBefore > priceAfter
            ? (priceBefore - priceAfter) * 10000 / priceBefore
            : (priceAfter - priceBefore) * 10000 / priceAfter;
        
        assertLt(deviation, 500, "Price deviation > 5% - manipulation possible");
    }
    
    /// @notice Multi-block manipulation test
    function test_MultiBlockManipulation_ShouldFail() public {
        uint256 priceBefore = protocol.getPrice();
        
        // Manipulate over multiple blocks
        for (uint i = 0; i < 10; i++) {
            // Manipulate and roll block
            _manipulatePrice();
            vm.roll(block.number + 1);
            vm.warp(block.timestamp + 12);
        }
        
        uint256 priceAfter = protocol.getPrice();
        
        // With 30-min TWAP, 10 blocks shouldn't move price much
        uint256 deviation = _calculateDeviation(priceBefore, priceAfter);
        assertLt(deviation, 500, "Multi-block manipulation succeeded");
    }
}
```

### 2.2 Staleness Test

```solidity
contract StalenessTest is Test {
    Protocol protocol;
    MockChainlinkFeed mockFeed;
    
    function setUp() public {
        mockFeed = new MockChainlinkFeed();
        protocol = new Protocol(address(mockFeed));
    }
    
    /// @notice Stale price should revert after fix
    function test_StalePrice_ShouldRevert() public {
        // Set price from 2 hours ago
        mockFeed.setPrice(2000e8);
        mockFeed.setUpdatedAt(block.timestamp - 2 hours);
        
        // Should revert with staleness error
        vm.expectRevert("Stale price");
        protocol.getLatestPrice();
    }
    
    /// @notice Fresh price should work
    function test_FreshPrice_ShouldWork() public {
        mockFeed.setPrice(2000e8);
        mockFeed.setUpdatedAt(block.timestamp - 30 minutes);
        
        uint256 price = protocol.getLatestPrice();
        assertEq(price, 2000e18);
    }
    
    /// @notice Incomplete round should revert
    function test_IncompleteRound_ShouldRevert() public {
        mockFeed.setRoundId(10);
        mockFeed.setAnsweredInRound(9);  // Previous round
        mockFeed.setPrice(2000e8);
        mockFeed.setUpdatedAt(block.timestamp);
        
        vm.expectRevert("Stale round");
        protocol.getLatestPrice();
    }
}
```

---

## 3. Fix Gone Wrong Examples

### 3.1 ❌ Different Heartbeats Not Accounted

```solidity
// Developer used same staleness for all feeds
uint256 constant STALENESS = 1 hours;

function getETHPrice() view returns (uint256) {
    // ETH/USD has 1 hour heartbeat - OK
    require(block.timestamp - updatedAt <= STALENESS);
}

function getBTCPrice() view returns (uint256) {
    // BTC/USD has 1 hour heartbeat - OK
    require(block.timestamp - updatedAt <= STALENESS);
}

function getOBSCUREPrice() view returns (uint256) {
    // OBSCURE/USD has 24 hour heartbeat - BROKEN!
    // Will always revert as "stale" when actually fresh
    require(block.timestamp - updatedAt <= STALENESS);
}
```

### 3.2 ❌ Decimals Mismatch

```solidity
function getPrice() view returns (uint256) {
    (, int256 ethPrice, , , ) = ethFeed.latestRoundData();    // 8 decimals
    (, int256 tokenPrice, , , ) = tokenFeed.latestRoundData(); // 18 decimals
    
    // Direct comparison without normalization!
    return uint256(tokenPrice) / uint256(ethPrice);  // Wrong!
}
```

### 3.3 ❌ L2 Sequencer Not Checked

```solidity
// On Arbitrum/Optimism, must check sequencer status
function getPrice() view returns (uint256) {
    // Missing sequencer uptime check!
    (, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
    require(block.timestamp - updatedAt <= STALENESS);
    return uint256(price);
}
// Problem: After sequencer downtime, prices may be stale but look fresh
```

**✅ CORRECT: L2 Sequencer Check**
```solidity
function getPrice() view returns (uint256) {
    // Check sequencer uptime first
    (, int256 answer, uint256 startedAt, , ) = sequencerFeed.latestRoundData();
    require(answer == 0, "Sequencer down");
    require(block.timestamp - startedAt > GRACE_PERIOD, "Grace period");
    
    // Then get price
    (, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
    require(block.timestamp - updatedAt <= STALENESS);
    return uint256(price);
}
```

### 3.4 ❌ Fallback Oracle Not Tested

```solidity
function getPrice() view returns (uint256) {
    try primaryOracle.getPrice() returns (uint256 price) {
        return price;
    } catch {
        // Fallback never tested - might have different decimals!
        return secondaryOracle.getPrice();
    }
}
```

---

## 4. Verification Checklist

### Pre-Fix Analysis
- [ ] Identify all price sources used
- [ ] Document heartbeat for each Chainlink feed
- [ ] Map decimal precision for each oracle
- [ ] Check if deployed on L2 (sequencer check needed)
- [ ] Identify flash loan attack vectors

### Fix Implementation
- [ ] TWAP window ≥ 30 minutes
- [ ] Staleness check with correct heartbeat per feed
- [ ] Round completeness check (`answeredInRound >= roundId`)
- [ ] Price > 0 validation
- [ ] Decimal normalization between oracles
- [ ] Deviation bounds between multiple oracles
- [ ] L2 sequencer uptime check (if applicable)
- [ ] Fallback oracle with same interface/decimals

### Post-Fix Testing
- [ ] Flash loan manipulation fails
- [ ] Multi-block manipulation fails
- [ ] Stale price reverts
- [ ] Zero/negative price reverts
- [ ] Normal operations work with fresh prices
- [ ] Fallback activates correctly
- [ ] Gas costs acceptable

---

## 5. Oracle Fix Decision Matrix

| Issue | Fix | Test |
|-------|-----|------|
| Spot price manipulation | TWAP ≥ 30 min | Flash loan attack |
| Stale Chainlink | `updatedAt` check | Time warp test |
| Incomplete round | `answeredInRound >= roundId` | Mock incomplete round |
| L2 sequencer down | Sequencer uptime feed | Mock sequencer down |
| LP price manipulation | Fair reserve formula | Reserve manipulation test |
| Multi-oracle deviation | Deviation bounds | Divergent price test |

---

## Related

- [Oracle Anti-Patterns](../patterns/oracle-antipatterns.md)
- [Oracle Attack Tree](../attack-trees/oracle-attack-tree.md)
- [Fix Verification Methodology](../methodology/fix-verification-patterns.md)
