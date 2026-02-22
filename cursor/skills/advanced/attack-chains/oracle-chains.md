# Oracle Manipulation Attack Chains

## Chain 1: Spot Price Manipulation
```
Step 1: Flash loan large amount of token A
Step 2: Swap token A → token B in AMM (moves spot price)
Step 3: Interact with victim protocol using manipulated price
Step 4: Extract value (borrow more, buy cheap, inflate collateral)
Step 5: Swap back, repay flash loan
```

### Detection Points
- [ ] Protocol reads `getReserves()` or `getAmountOut()` directly?
- [ ] Any use of `slot0()` (Uniswap V3 current tick)?
- [ ] Spot price used for ANY valuation?
- [ ] Single block price consulted (no TWAP)?

### Real Examples
- **Harvest Finance ($34M)**: Curve pool spot price manipulation
- **Mango Markets ($114M)**: Perp market oracle manipulation
- **Cream Finance ($130M)**: yUSD price manipulation via Curve

## Chain 2: TWAP Manipulation  
```
Step 1: Slowly manipulate AMM price over TWAP window
Step 2: Maintain manipulation across multiple blocks
Step 3: TWAP eventually reflects manipulated price
Step 4: Exploit victim protocol using corrupted TWAP
```

### Detection Points
- [ ] TWAP window length (< 30 min = risky)?
- [ ] TWAP cardinality (number of observations)?
- [ ] Pool liquidity sufficient to resist manipulation?
- [ ] Cost of maintaining manipulation vs profit?
- [ ] Uniswap V3 TWAP uses geometric mean (harder to manipulate)?

## Chain 3: Chainlink Stale Price
```
Step 1: Market crashes rapidly
Step 2: Chainlink heartbeat hasn't updated (deviation threshold not met)
Step 3: Protocol uses stale (higher) price
Step 4: Borrow against inflated collateral value
Step 5: Collateral drops further, protocol left with bad debt
```

### Detection Points
- [ ] `latestRoundData()` return values ALL checked?
  - [ ] `roundId != 0` (valid round)?
  - [ ] `answer > 0` (positive price)?
  - [ ] `updatedAt != 0` (not stale)?
  - [ ] `updatedAt > block.timestamp - MAX_STALENESS`?
  - [ ] `answeredInRound >= roundId` (round completed)?
- [ ] Fallback oracle configured?
- [ ] Circuit breaker for extreme price changes?

### Common Chainlink Mistakes
```solidity
// WRONG — no staleness check
(, int256 price,,,) = priceFeed.latestRoundData();
return uint256(price);

// CORRECT — full validation
(uint80 roundId, int256 price,, uint256 updatedAt, uint80 answeredInRound) = 
    priceFeed.latestRoundData();
require(roundId != 0, "Invalid round");
require(price > 0, "Negative price");
require(updatedAt > block.timestamp - MAX_STALENESS, "Stale price");
require(answeredInRound >= roundId, "Incomplete round");
```

## Chain 4: Oracle Front-Running
```
Step 1: Monitor mempool for oracle price update tx
Step 2: Front-run with position that profits from price change
Step 3: Oracle updates
Step 4: Close position for profit
```

### Detection Points
- [ ] Oracle updates atomic with protocol actions?
- [ ] Commit-reveal scheme for price updates?
- [ ] Private mempool for oracle updates?
- [ ] Price deviation limits per update?

## Chain 5: Multi-Oracle Inconsistency
```
Step 1: Protocol uses Oracle A for deposits, Oracle B for withdrawals
Step 2: Prices diverge between oracles
Step 3: Deposit at favorable Oracle A price
Step 4: Withdraw at favorable Oracle B price
Step 5: Profit from price discrepancy
```

### Detection Points
- [ ] Same oracle used for all operations?
- [ ] If multiple oracles, prices cross-validated?
- [ ] Median or aggregate of multiple sources?
- [ ] Deviation threshold between oracles?

## Chain 6: LP Token Price Manipulation
```
Step 1: Flash loan to deposit massive liquidity into pool
Step 2: LP token price inflates (more reserves backing tokens)
Step 3: Use inflated LP tokens as collateral
Step 4: Borrow against inflated collateral
Step 5: Remove liquidity, repay flash loan
```

### Detection Points
- [ ] LP token pricing uses fair pricing formula?
- [ ] `totalSupply * pricePerShare` vulnerable to donation?
- [ ] Uses Alpha Finance fair LP pricing?
- [ ] Virtual price manipulation resistance?

## Oracle Security Summary
| Oracle Type | Manipulation Cost | Time Required | Defense |
|------------|------------------|---------------|---------|
| Spot AMM | Low (flash loan) | 1 block | Never use spot |
| TWAP (short) | Medium | Minutes | Use 30+ min window |
| TWAP (long) | High | Hours | Good defense |
| Chainlink | Very High | N/A | Check staleness |
| Custom | Varies | Varies | Full audit needed |
