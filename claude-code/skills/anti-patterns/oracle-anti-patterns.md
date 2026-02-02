---
id: ORACLE-ANTI-PATTERNS
title: Oracle Anti-Patterns (What NOT to Do)
category: anti-pattern
triggers:
  - oracle bad code
  - oracle mistakes
  - wrong oracle usage
related_skills:
  - patterns/oracle-patterns.md
  - attack-trees/lending-attack-tree.md
---

# Oracle Anti-Patterns

Examples of **BAD** code patterns for oracle usage. These are real mistakes found in production.

---

## Anti-Pattern #1: Using Spot Price Directly

> **Severity: Critical** | **Estimated Loss: $10M-$150M+** | **Fix Priority: Immediate**

### BAD CODE
```solidity
// ❌ VULNERABLE: Using DEX spot price
function getCollateralValue(address token, uint amount) public view returns (uint) {
    IUniswapV2Pair pair = IUniswapV2Pair(factory.getPair(token, WETH));
    (uint reserve0, uint reserve1,) = pair.getReserves();
    
    // Directly using reserves to calculate price
    uint price = (reserve1 * 1e18) / reserve0;
    return amount * price / 1e18;
}
```

### Why It's Bad
- **Flash loan attack**: Attacker can manipulate reserves within same transaction
- **No resistance**: Single large swap completely changes price
- **No validation**: Doesn't check if reserves are reasonable

### Exploited In
- **Harvest Finance** (2020, $24M) - Flash loan manipulated Curve pool reserves
- **Warp Finance** (2020, $7.7M) - Uniswap LP token spot price manipulation
- **Cream Finance** (2021, $130M) - PriceOracleProxy used spot price

### Attack PoC
```solidity
// Attacker contract
function exploit() external {
    // 1. Flash loan huge amount of tokenA
    flashLoan(tokenA, 100_000 ether);
    
    // 2. Swap to manipulate pool reserves
    uniswap.swap(tokenA, tokenB, 100_000 ether);
    // Now reserve1/reserve0 is inflated
    
    // 3. Use inflated price to borrow
    uint collateralValue = getCollateralValue(tokenA, 1 ether);
    // Value is now 100x actual price
    lending.borrow(collateralValue);
    
    // 4. Repay flash loan
    repayFlashLoan();
    // Profit: Overborrowed at fake price
}
```

### Correct Pattern
```solidity
// ✅ GOOD: Use TWAP oracle with manipulation resistance
function getCollateralValue(address token, uint amount) public view returns (uint) {
    // Option 1: Use Chainlink oracle (external, manipulation-resistant)
    AggregatorV3Interface priceFeed = priceFeeds[token];
    (, int price,,,) = priceFeed.latestRoundData();
    require(price > 0, "Invalid price");
    return amount * uint(price) / 1e8;
    
    // Option 2: Use Uniswap V3 TWAP (time-weighted average)
    // uint32 twapInterval = 1800; // 30 minutes
    // (int24 tick,) = OracleLibrary.consult(pool, twapInterval);
    // uint256 price = OracleLibrary.getQuoteAtTick(tick, amount, token, WETH);
    // return price;
}
```

---

## Anti-Pattern #2: No Staleness Check

> **Severity: High** | **Estimated Loss: $1M-$50M** | **Fix Priority: High**

### BAD CODE
```solidity
// ❌ VULNERABLE: No staleness validation
function getPrice(address token) public view returns (uint) {
    AggregatorV3Interface priceFeed = priceFeeds[token];
    
    (, int price,,,) = priceFeed.latestRoundData();
    
    return uint(price);
}
```

### Why It's Bad
- **Stale price**: If oracle stops updating, uses outdated price
- **No timestamp check**: Doesn't verify when price was last updated
- **Silent failure**: Returns old price as if it's current

### Exploited In
- **Venus Protocol** (2021) - Stale Chainlink price allowed overborrowing
- **Inverse Finance** (2022, $1.2M) - Oracle failure, stale prices exploited

### Attack PoC
```solidity
// When oracle fails/pauses
function exploit() external {
    // Oracle last updated 2 weeks ago, price was $100
    // Current real price is $10
    
    // 1. Buy token at $10 on market
    buyToken(targetToken, 100 ether);
    
    // 2. Deposit as collateral (valued at stale $100 price)
    lending.deposit(targetToken, 100 ether);
    // Protocol thinks collateral worth $10,000
    // Actually worth $1,000
    
    // 3. Borrow maximum at inflated value
    lending.borrow(USDC, 7000e6); // 70% LTV of $10,000
    
    // 4. Default - protocol loses $6,000
}
```

### Correct Pattern
```solidity
// ✅ GOOD: Full staleness validation
function getPrice(address token) public view returns (uint) {
    AggregatorV3Interface priceFeed = priceFeeds[token];
    
    (
        uint80 roundId,
        int price,
        ,
        uint updatedAt,
        uint80 answeredInRound
    ) = priceFeed.latestRoundData();
    
    // Check staleness - price must be recent
    require(updatedAt > 0, "Round not complete");
    require(block.timestamp - updatedAt < MAX_STALENESS, "Stale price");
    
    // Check round completeness
    require(answeredInRound >= roundId, "Stale round");
    
    // Check price validity
    require(price > 0, "Invalid price");
    
    return uint(price);
}
```

---

## Anti-Pattern #3: No Zero/Negative Price Handling
> **Severity: Critical** | **Estimated Loss: $10M-$100M+** | **Fix Priority: Immediate**
### BAD CODE
```solidity
// ❌ VULNERABLE: No zero or negative price check
function getPrice(address token) public view returns (uint) {
    (, int price,,,) = priceFeeds[token].latestRoundData();
    
    // Direct cast, no validation
    return uint(price);
}

function calculateCollateral(uint amount) public view returns (uint) {
    uint price = getPrice(collateralToken);
    
    // Division by price - what if price is 0?
    return amount / price;
}
```

### Why It's Bad
- **Division by zero**: Causes revert or returns type(uint).max
- **Negative cast**: Negative int becomes huge uint (underflow)
- **No bounds**: Doesn't check if price is reasonable

### Exploited In
- **Compound** (Edge case, caught in testing) - Zero price would brick protocol
- **Venus** (2021) - Price oracle returned 0, allowed infinite borrow

### Attack PoC
```solidity
// If oracle returns 0 (paused/broken)
function exploit() external {
    // Oracle returns 0 for token price
    
    // 1. Deposit any collateral
    lending.deposit(collateral, 1 ether);
    
    // 2. Try to borrow
    // calculateCollateral divides by 0
    // Some implementations: returns MAX_UINT
    uint borrowPower = calculateCollateral(1 ether); // = type(uint).max
    
    // 3. Borrow everything
    lending.borrowMax(); // Drains protocol
}

// If oracle returns negative (int overflow)
function exploitNegative() external {
    // Oracle bug returns -1
    // Cast to uint: -1 → 2^256-1
    
    uint price = getPrice(token); // Huge number
    
    // Collateral valued at astronomical amount
    lending.deposit(token, 1 wei);
    lending.borrowAll(); // Infinite borrow power
}
```

### Correct Pattern
```solidity
// ✅ GOOD: Full price validation with bounds
function getPrice(address token) public view returns (uint) {
    (, int price,,,) = priceFeeds[token].latestRoundData();
    
    // Check for zero price
    require(price > 0, "Zero price");
    
    // Check for reasonable bounds (e.g., $0.0001 to $1M per token)
    require(uint(price) >= MIN_PRICE, "Price too low");
    require(uint(price) <= MAX_PRICE, "Price too high");
    
    return uint(price);
}

function calculateCollateral(uint amount) public view returns (uint) {
    uint price = getPrice(collateralToken);
    
    // Safe division - price guaranteed > 0 by getPrice()
    return amount * 1e8 / price; // Assuming 8 decimal price feed
}
```

---

## Anti-Pattern #4: Single Oracle, No Fallback

> **Severity: Medium** | **Estimated Loss: $100K-$10M** | **Fix Priority: Medium**

### BAD CODE
```solidity
// ❌ VULNERABLE: Single point of failure
contract PriceOracle {
    AggregatorV3Interface public priceFeed;
    
    function getPrice() external view returns (uint) {
        (, int price,,,) = priceFeed.latestRoundData();
        return uint(price);
    }
}
```

### Why It's Bad
- **Single point of failure**: If oracle fails, protocol bricked
- **No redundancy**: Can't fall back to alternative source
- **No validation**: Can't detect if oracle is wrong

### Real-World Impact
- **Synthetix** (2020) - Oracle failure, trading halted
- **bZx** (2020, $8M) - Single oracle manipulated via on-chain price

### Attack PoC
```solidity
// If oracle is pausable/upgradeable
function exploit() external {
    // 1. Oracle team pauses feed for maintenance
    // or: Attacker finds upgrade vulnerability
    
    // 2. Protocol continues using last price
    // or: Reverts on all operations (DoS)
    
    // 3a. If stale price used: Exploit stale price
    // 3b. If reverts: DoS all borrows/liquidations
    
    // Either way: Protocol unusable or exploitable
}
```

### Correct Pattern
```solidity
// ✅ GOOD: Multi-oracle with fallback chain
contract ResilientOracle {
    AggregatorV3Interface public primaryOracle;   // Chainlink
    AggregatorV3Interface public secondaryOracle; // Band Protocol
    address public twapPool;                       // Uniswap TWAP
    
    function getPrice(address token) public view returns (uint) {
        // Try primary oracle (Chainlink)
        (bool success1, uint price1) = _tryChainlink(token);
        if (success1) return price1;
        
        // Fallback to secondary oracle
        (bool success2, uint price2) = _trySecondaryOracle(token);
        if (success2) return price2;
        
        // Last resort: TWAP oracle
        (bool success3, uint price3) = _tryTWAP(token);
        if (success3) return price3;
        
        revert("All oracles failed");
    }
    
    function _tryChainlink(address token) internal view returns (bool, uint) {
        try priceFeeds[token].latestRoundData() returns (
            uint80 roundId, int price, , uint updatedAt, uint80 answeredInRound
        ) {
            if (price > 0 && 
                block.timestamp - updatedAt < MAX_STALENESS &&
                answeredInRound >= roundId) {
                return (true, uint(price));
            }
        } catch {}
        return (false, 0);
    }
}
```

---

## Anti-Pattern #5: Using balanceOf for LP Price

> **Severity: Critical** | **Estimated Loss: $5M-$100M+** | **Fix Priority: Immediate**

### BAD CODE
```solidity
// ❌ VULNERABLE: LP token pricing via balanceOf
function getLPTokenPrice(address lpToken) public view returns (uint) {
    IUniswapV2Pair pair = IUniswapV2Pair(lpToken);
    
    uint totalSupply = pair.totalSupply();
    uint balance0 = IERC20(pair.token0()).balanceOf(lpToken);
    uint balance1 = IERC20(pair.token1()).balanceOf(lpToken);
    
    uint value0 = balance0 * getPrice(pair.token0());
    uint value1 = balance1 * getPrice(pair.token1());
    
    // Price per LP token
    return (value0 + value1) / totalSupply;
}
```

### Why It's Bad
- **Donation attack**: Attacker can send tokens directly to pair
- **Inflates balanceOf**: Makes LP tokens appear more valuable
- **Should use reserves**: `getReserves()` is manipulation-resistant

### Exploited In
- **Warp Finance** (2020, $7.7M) - LP token valuation via balanceOf

### Attack PoC
```solidity
function exploit() external {
    // 1. Flash loan large amount of token0
    flashLoan(token0, 1_000_000 ether);
    
    // 2. Donate to LP contract (not swap)
    token0.transfer(address(lpToken), 1_000_000 ether);
    // balanceOf(lpToken) now inflated
    // getReserves() unchanged
    
    // 3. Get LP tokens valued at inflated price
    uint lpPrice = getLPTokenPrice(lpToken); // Huge
    
    // 4. Deposit LP tokens as collateral
    lending.deposit(lpToken, myLPAmount);
    // Valued at inflated price
    
    // 5. Borrow maximum
    lending.borrow(USDC, maxAmount);
    
    // 6. Repay flash loan
    // Profit: Overborrowed using inflated LP value
}
```

### Correct Pattern
```solidity
// ✅ GOOD: Use getReserves() instead of balanceOf()
function getLPTokenPrice(address lpToken) public view returns (uint) {
    IUniswapV2Pair pair = IUniswapV2Pair(lpToken);
    
    uint totalSupply = pair.totalSupply();
    
    // Use getReserves() - not manipulable by donation
    (uint reserve0, uint reserve1,) = pair.getReserves();
    
    uint value0 = reserve0 * getPrice(pair.token0());
    uint value1 = reserve1 * getPrice(pair.token1());
    
    // Price per LP token (donation-resistant)
    return (value0 + value1) / totalSupply;
}

// ✅ EVEN BETTER: Use Alpha Homora fair LP pricing
function getFairLPPrice(address lpToken) public view returns (uint) {
    IUniswapV2Pair pair = IUniswapV2Pair(lpToken);
    (uint r0, uint r1,) = pair.getReserves();
    
    uint p0 = getPrice(pair.token0());
    uint p1 = getPrice(pair.token1());
    
    // Fair LP pricing formula (manipulation-resistant)
    // price = 2 * sqrt(r0 * r1 * p0 * p1) / totalSupply
    uint sqrtK = sqrt(r0 * r1);
    uint sqrtP = sqrt(p0 * p1);
    return 2 * sqrtK * sqrtP / pair.totalSupply();
}
```

---

## Anti-Pattern #6: Trusting tx.origin for Oracle

> **Severity: Medium** | **Estimated Loss: $100K-$5M** | **Fix Priority: Medium**

### BAD CODE
```solidity
// ❌ VULNERABLE: Using tx.origin for auth
contract RestrictedOracle {
    mapping(address => bool) public trustedCallers;
    
    function getPrice() external view returns (uint) {
        require(trustedCallers[tx.origin], "Not trusted");
        return _fetchPrice();
    }
}
```

### Why It's Bad
- **Phishing attack**: Attacker tricks trusted user to call malicious contract
- **msg.sender bypass**: Intermediate contracts bypass tx.origin check
- **Not recommended**: Solidity docs warn against tx.origin

### Attack PoC
```solidity
// Attacker's malicious contract
function phishAdmin() external {
    // Admin (trusted) calls this thinking it's legit
    
    // This contract calls oracle
    uint price = oracle.getPrice();
    // tx.origin = admin (trusted)
    // msg.sender = this contract (malicious)
    
    // Now use price in exploit
}
```

### Correct Pattern
```solidity
// ✅ GOOD: Use msg.sender for authorization
contract SecureOracle {
    mapping(address => bool) public trustedCallers;
    
    function getPrice() external view returns (uint) {
        // Use msg.sender - cannot be phished
        require(trustedCallers[msg.sender], "Not trusted");
        return _fetchPrice();
    }
    
    // Or better: use AccessControl from OpenZeppelin
    // bytes32 public constant READER_ROLE = keccak256("READER");
    // function getPrice() external view onlyRole(READER_ROLE) returns (uint) {
    //     return _fetchPrice();
    // }
}
```

---

## Anti-Pattern #7: No Deviation Check (Multi-Oracle)

> **Severity: High** | **Estimated Loss: $1M-$50M** | **Fix Priority: High**

### BAD CODE
```solidity
// ❌ VULNERABLE: Using average without deviation check
function getPrice() public view returns (uint) {
    uint price1 = oracle1.getPrice();
    uint price2 = oracle2.getPrice();
    uint price3 = oracle3.getPrice();
    
    // Simple average, no deviation check
    return (price1 + price2 + price3) / 3;
}
```

### Why It's Bad
- **Hides manipulation**: One manipulated oracle affects average
- **No outlier detection**: Doesn't catch if one oracle is wrong
- **Silent failure**: Returns "average" of bad data

### Attack PoC
```solidity
function exploit() external {
    // Oracle1: $100 (correct)
    // Oracle2: $100 (correct)
    // Oracle3: $1000 (manipulated by attacker)
    
    uint avgPrice = getPrice(); // = $400
    // Real price: $100
    // Average price: $400 (4x inflated)
    
    // Use inflated price to over-borrow
    lending.deposit(token, 10 ether);
    lending.borrow(USDC, 4000e6); // Based on $400 price
}
```

### Correct Pattern
```solidity
// ✅ GOOD: Check deviation before averaging
function getPrice() public view returns (uint) {
    uint price1 = oracle1.getPrice();
    uint price2 = oracle2.getPrice();
    uint price3 = oracle3.getPrice();
    
    // Check max deviation < 5%
    uint maxPrice = max(price1, price2, price3);
    uint minPrice = min(price1, price2, price3);
    
    require(
        (maxPrice - minPrice) * 100 / minPrice < 5,
        "Oracle deviation too high"
    );
    
    return (price1 + price2 + price3) / 3;
}
```

---

## Quick Reference: Oracle Anti-Patterns

| Anti-Pattern | Severity | Common In | Attack Type |
|--------------|----------|-----------|-------------|
| #1 Spot Price | Critical | DEXs, Lending | Flash loan manipulation |
| #2 No Staleness Check | High | All protocols | Use outdated prices |
| #3 No Zero/Negative Check | Critical | All protocols | Division by zero, underflow |
| #4 Single Oracle | Medium | Smaller protocols | DoS, single point of failure |
| #5 LP balanceOf Pricing | Critical | LP collateral | Donation attack |
| #6 tx.origin Auth | Medium | Restricted oracles | Phishing |
| #7 No Deviation Check | High | Multi-oracle | Manipulation average |

---

## See Also

- **Correct Patterns:** [patterns/oracle-patterns.md](../patterns/oracle-patterns.md)
- **Attack Trees:** [attack-trees/lending-attack-tree.md](../attack-trees/lending-attack-tree.md)
- **Exploits:** Check exploit-forensics/ for real-world examples
