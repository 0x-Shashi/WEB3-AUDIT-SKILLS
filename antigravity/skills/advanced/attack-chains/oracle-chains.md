# Oracle Manipulation Attack Chains

## Overview

Oracles are critical infrastructure. Manipulating price feeds enables:

- Unfair liquidations
- Collateral overvaluation
- Arbitrage extraction
- Protocol insolvency

---

## Chain 1: DEX Price Manipulation + Lending Liquidation

**Components:**
1. Price from DEX reserves
2. Lending protocol using that price
3. Instant liquidation

**Attack Flow:**
```
1. Identify user with healthy position
2. Manipulate DEX price (large swap)
3. User position becomes liquidatable
4. Liquidate user at bad price
5. Reverse DEX manipulation
6. Profit from liquidation bonus
```

**Real Example:** Inverse Finance ($15M)

**Vulnerable Pattern:**
```solidity
// Using Uniswap reserves directly
function getPrice() view returns (uint256) {
    (uint112 r0, uint112 r1,) = IUniswapV2Pair(pair).getReserves();
    return r0 * 1e18 / r1;  // Instantly manipulatable
}
```

**Secure Pattern:**
```solidity
// Using TWAP
function getPrice() view returns (uint256) {
    uint256 price0Cumulative = pair.price0CumulativeLast();
    uint256 timeElapsed = block.timestamp - lastUpdate;
    return (price0Cumulative - lastCumulative) / timeElapsed;
}
```

---

## Chain 2: Stale Oracle + Price Movement + Arbitrage

**Components:**
1. Oracle with infrequent updates
2. Fast-moving market
3. Protocol using stale price

**Attack Flow:**
```
1. Monitor for oracle staleness
2. Wait for significant market move
3. Trade against protocol at stale price
4. Profit from price difference
```

**Real Example:** CREAM (multiple)

**Vulnerable Pattern:**
```solidity
function getPrice() view returns (uint256) {
    return storedPrice;  // No freshness check!
}
```

**Secure Pattern:**
```solidity
function getPrice() view returns (uint256) {
    (uint256 price, uint256 updatedAt) = oracle.latestRoundData();
    require(block.timestamp - updatedAt < MAX_DELAY, "Stale price");
    return price;
}
```

---

## Chain 3: TWAP Manipulation + Extended Attack

**Components:**
1. TWAP oracle (time-weighted)
2. Low liquidity period
3. Patient attacker

**Attack Flow:**
```
1. Over multiple blocks, gradually move TWAP
2. Make small trades each block
3. Eventually TWAP reflects manipulated price
4. Execute main attack using skewed TWAP
5. Profit before TWAP corrects
```

**Detection:**
```solidity
// Check TWAP window length
uint256 constant TWAP_PERIOD = 30 minutes;  // Too short?

// Check liquidity depth
// Low liquidity = easier manipulation
```

**Mitigation:**
- Longer TWAP windows (24h+)
- Liquidity requirements
- Multiple oracle sources

---

## Chain 4: Oracle Frontrunning + MEV

**Components:**
1. Oracle update in mempool
2. MEV bot detection
3. Sandwich attack

**Attack Flow:**
```
1. Monitor mempool for oracle updates
2. Frontrun with position at current price
3. Let oracle update execute
4. Backrun to close position at new price
```

**Mitigation:**
- Private oracle updates (Flashbots)
- Commit-reveal schemes
- MEV-resistant designs

---

## Chain 5: Multi-Oracle Inconsistency

**Components:**
1. Protocol using multiple oracles
2. Oracles update at different times
3. Arbitrage between inconsistent prices

**Attack Flow:**
```
1. Identify oracle price divergence
2. Use cheaper oracle price to borrow
3. Use expensive oracle price to value collateral
4. Extract value from spread
```

**Vulnerable Pattern:**
```solidity
// Different oracles for different operations
function borrow(uint256 amount) {
    uint256 collateralValue = oracleA.getPrice() * collateral;  // Oracle A
    uint256 debtValue = oracleB.getPrice() * amount;  // Oracle B (different!)
}
```

**Secure Pattern:**
```solidity
// Single source of truth
function borrow(uint256 amount) {
    uint256 price = primaryOracle.getPrice();
    uint256 collateralValue = price * collateral;
    uint256 debtValue = price * amount;  // Same oracle
}
```

---

## Chain 6: Oracle Dependency Chain

**Components:**
1. Token A price from Token A/ETH pool
2. Token B price derived from Token A
3. Cascading manipulation

**Attack Flow:**
```
1. Manipulate Token A price
2. Token B price automatically affected
3. Attack protocols using Token B price
4. Cascading effect across DeFi
```

**Real Example:** Warp Finance ($7.7M)

**Detection:**
```solidity
// Check for derived prices
function getTokenBPrice() view returns (uint256) {
    uint256 aPrice = getTokenAPrice();  // Dependency!
    return aPrice * tokenBRatio;
}
```

---

## Chain 7: Chainlink Deviation + Threshold Gaming

**Components:**
1. Chainlink with deviation threshold (e.g., 1%)
2. Price hovering near threshold
3. Gaming the update timing

**Attack Flow:**
```
1. Price at 99.5 (threshold at 100 for update)
2. Build position
3. Push price to 100.5 (triggers update)
4. Profit from the 1% jump
```

**Mitigation:**
- Lower deviation thresholds
- Heartbeat checks
- Multiple oracle aggregation

---

## Oracle Security Checklist

- [ ] What's the oracle source? (DEX, Chainlink, TWAP)
- [ ] Is there a staleness check?
- [ ] What's the manipulation cost?
- [ ] How long is the TWAP window?
- [ ] Are there circuit breakers for extreme moves?
- [ ] Is the oracle decentralized?
- [ ] Are there fallback oracles?
- [ ] Can oracle updates be frontrun?

---

## Oracle Best Practices Matrix

| Oracle Type | Manipulation Resistance | Latency | Cost |
|-------------|------------------------|---------|------|
| Spot DEX | Very Low | Instant | Low |
| 30min TWAP | Medium | 30 min | Low |
| 24h TWAP | High | 24 hour | Low |
| Chainlink | High | Minutes | Medium |
| Multi-Oracle | Very High | Varies | High |

---

## Detection Commands

```bash
# Find oracle usage
grep -rn "getPrice\|latestAnswer\|latestRoundData\|getReserves" --include="*.sol"

# Find staleness checks
grep -rn "updatedAt\|timestamp.*oracle\|stale" --include="*.sol"

# Find price calculations
grep -rn "price.*=.*reserve\|price.*=.*balance" --include="*.sol"

# Find TWAP usage
grep -rn "TWAP\|cumulative.*price\|time.*weighted" --include="*.sol"
```
