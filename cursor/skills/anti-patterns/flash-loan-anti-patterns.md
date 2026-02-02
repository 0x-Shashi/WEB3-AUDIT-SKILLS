---
id: FLASH-LOAN-ANTI-PATTERNS
title: Flash Loan Anti-Patterns
category: anti-pattern
tags: [flash-loan, oracle, governance, manipulation]
severity_range: High-Critical
real_exploits: $400M+
related_skills:
  - patterns/flash-loan-patterns.md
  - patterns/oracle-patterns.md
  - patterns/governance-patterns.md
---

# Flash Loan Anti-Patterns

Common mistakes that allow flash loans to exploit protocol logic. Total losses from flash loan attacks exceed $400M+.

---

## Anti-Pattern 1: Flash Loan Governance Voting

### Description
Protocol allows flash-borrowed governance tokens to vote on proposals, enabling instant control without long-term stake.

### Vulnerable Code
```solidity
// VULNERABLE
function vote(uint256 proposalId, bool support) external {
    uint256 votes = governanceToken.balanceOf(msg.sender);  // Snapshot at call time!
    require(votes > 0, "No voting power");
    
    proposals[proposalId].votes[support] += votes;
}

function execute(uint256 proposalId) external {
    require(proposals[proposalId].votes[true] > quorum, "Not passed");
    // Execute proposal
}
```

### Why It's Vulnerable
- Flash loan governance tokens
- Vote with massive borrowed balance
- Repay loan in same transaction
- Pass malicious proposal instantly
- No time lock, no stake requirement

### Secure Pattern
```solidity
// SECURE - Snapshot-based voting
mapping(uint256 => uint256) public proposalSnapshots;

function propose(...) external returns (uint256 proposalId) {
    proposalId = proposalCount++;
    proposalSnapshots[proposalId] = block.number;  // Snapshot at proposal
    // Proposal details...
}

function vote(uint256 proposalId, bool support) external {
    uint256 snapshotBlock = proposalSnapshots[proposalId];
    uint256 votes = governanceToken.balanceOfAt(msg.sender, snapshotBlock);
    require(votes > 0, "No voting power at snapshot");
    
    proposals[proposalId].votes[support] += votes;
}
```

### Detection Checklist
- [ ] Voting uses historical snapshot (block N-1 or earlier)
- [ ] Snapshot taken before proposal created
- [ ] Cannot flash loan vote
- [ ] Time delay between snapshot and execution

### Real-World Impact
- **Beanstalk (2022):** $182M via flash loan governance attack
- **Build Finance (2021):** Attacker passed malicious proposal
- **Severity:** Critical (complete protocol takeover)

---

## Anti-Pattern 2: Single-Block Oracle Manipulation

### Description
Protocol reads spot price from DEX within same transaction, allowing flash loan to manipulate price, act on it, and profit.

### Vulnerable Code
```solidity
// VULNERABLE
function liquidate(address user) external {
    // Get current price from Uniswap (spot price!)
    uint256 price = IUniswapV2Pair(pair).getReserves();
    uint256 collateralValue = (collateral * price) / 1e18;
    uint256 debt = debts[user];
    
    require(collateralValue < debt, "Not liquidatable");
    // Liquidate user
}

// ATTACK:
// 1. Flash loan to manipulate Uniswap price
// 2. Call liquidate (sees manipulated price)
// 3. Profit from unfair liquidation
// 4. Repay flash loan
```

### Why It's Vulnerable
- Reads spot price in same transaction
- Flash loan can manipulate DEX reserves
- Protocol acts on manipulated price
- Attacker profits from discrepancy

### Secure Pattern
```solidity
// SECURE - TWAP (Time-Weighted Average Price)
function liquidate(address user) external {
    // Use TWAP over 10+ minutes
    uint256 price = oracle.getTWAP(token0, token1, 600);  // 10 min
    uint256 collateralValue = (collateral * price) / 1e18;
    uint256 debt = debts[user];
    
    require(collateralValue < debt, "Not liquidatable");
    // Liquidate user
}

// OR use Chainlink oracle
uint256 price = priceFeed.latestAnswer();
```

### Detection Checklist
- [ ] Never reads spot price from DEX
- [ ] Uses TWAP (10+ minutes) or external oracle
- [ ] Multiple price sources (Chainlink + Uniswap)
- [ ] Price freshness checks

### Real-World Impact
- **bZx (2020):** $954K via flash loan oracle manipulation (multiple attacks)
- **Harvest Finance (2020):** $34M via Curve pool manipulation
- **Severity:** Critical (fund theft)

---

## Anti-Pattern 3: Flash Loan Interest Rate Manipulation

### Description
Protocol's interest rate depends on utilization ratio, which flash loans can temporarily spike to extract value.

### Vulnerable Code
```solidity
// VULNERABLE
function getInterestRate() public view returns (uint256) {
    uint256 utilization = totalBorrowed * 1e18 / totalSupply;
    // Linear or kinked rate based on utilization
    return baseRate + (utilization * rateSlope);
}

function accrueInterest() external {
    uint256 rate = getInterestRate();
    accruedInterest += totalBorrowed * rate / SECONDS_PER_YEAR;
}

// ATTACK:
// 1. Flash borrow all liquidity → 100% utilization
// 2. Call accrueInterest → Extreme interest accrued
// 3. Rates normalized after repayment
// 4. Borrowers now owe inflated interest
```

### Why It's Vulnerable
- Interest calculated based on current utilization
- Flash borrow spikes utilization to 100%
- Interest accrues at manipulated rate
- Borrowers pay inflated interest

### Secure Pattern
```solidity
// SECURE - Time-weighted utilization OR cap rate changes
uint256 public lastUpdateTimestamp;
uint256 public cumulativeUtilization;

function accrueInterest() external {
    uint256 timeElapsed = block.timestamp - lastUpdateTimestamp;
    require(timeElapsed > 0, "Already updated this block");
    
    // Use time-weighted utilization
    uint256 avgUtilization = cumulativeUtilization / timeElapsed;
    uint256 rate = baseRate + (avgUtilization * rateSlope);
    
    accruedInterest += totalBorrowed * rate * timeElapsed / SECONDS_PER_YEAR;
    
    lastUpdateTimestamp = block.timestamp;
    cumulativeUtilization = 0;
}

// OR cap max rate change per block
uint256 constant MAX_RATE_CHANGE = 0.01e18;  // 1% max change
```

### Detection Checklist
- [ ] Interest not based on single-block utilization
- [ ] Time-weighted utilization or rate smoothing
- [ ] Max rate change per block enforced
- [ ] Flash loan resistance tested

### Real-World Impact
- **Inverse Finance (2022):** $15.6M via interest rate manipulation
- **Severity:** High (value extraction from borrowers)

---

## Anti-Pattern 4: Flash Loan Reward Farming

### Description
Protocol distributes rewards based on current balance/position, allowing flash loans to claim massive rewards unfairly.

### Vulnerable Code
```solidity
// VULNERABLE
function claimRewards() external {
    uint256 balance = staked[msg.sender];
    uint256 totalStaked = totalSupply;
    
    // Rewards based on current balance!
    uint256 reward = (balance * rewardPool) / totalStaked;
    
    rewardToken.transfer(msg.sender, reward);
    rewardPool -= reward;
}

// ATTACK:
// 1. Flash loan tokens
// 2. Stake (inflate balance)
// 3. Claim rewards (massive share due to flash balance)
// 4. Unstake and repay
```

### Why It's Vulnerable
- Rewards calculated on spot balance
- Flash loan inflates balance temporarily
- Attacker gets disproportionate share
- Other users' rewards diluted

### Secure Pattern
```solidity
// SECURE - Time-weighted staking
mapping(address => uint256) public stakeTimestamp;
mapping(address => uint256) public accumulatedTime;

function claimRewards() external {
    // Rewards based on stake duration, not just amount
    uint256 stakeTime = block.timestamp - stakeTimestamp[msg.sender];
    uint256 balance = staked[msg.sender];
    
    uint256 weightedBalance = balance * stakeTime;
    uint256 totalWeighted = totalSupply * averageStakeTime;
    
    uint256 reward = (weightedBalance * rewardPool) / totalWeighted;
    
    rewardToken.transfer(msg.sender, reward);
}

// OR use historical snapshots
uint256 reward = calculateRewardFromSnapshots(msg.sender);
```

### Detection Checklist
- [ ] Rewards based on time-weighted stake
- [ ] Minimum stake duration enforced
- [ ] Historical snapshots for reward calculation
- [ ] Flash loan claim resistance tested

### Real-World Impact
- **Multiple yield farms:** Exploited via flash loan farming
- **Severity:** High (unfair reward distribution)

---

## Anti-Pattern 5: Flash Loan Collateral Inflation

### Description
Protocol values collateral based on its spot balance, allowing flash deposits to inflate collateral value and borrow against it.

### Vulnerable Code
```solidity
// VULNERABLE
function borrow(uint256 amount) external {
    uint256 collateral = collateralToken.balanceOf(msg.sender);
    uint256 maxBorrow = (collateral * price * LTV) / 1e18;
    
    require(amount <= maxBorrow, "Insufficient collateral");
    
    borrowed[msg.sender] += amount;
    lendingToken.transfer(msg.sender, amount);
}

// ATTACK:
// 1. Flash loan collateral token
// 2. Borrow against flash-loaned collateral
// 3. Repay flash loan
// 4. Keep borrowed funds (undercollateralized)
```

### Why It's Vulnerable
- Collateral check uses spot balance
- Flash loan inflates collateral temporarily
- Borrow succeeds with flash collateral
- After repayment, position is undercollateralized

### Secure Pattern
```solidity
// SECURE - Require collateral deposited in protocol
mapping(address => uint256) public depositedCollateral;

function deposit(uint256 amount) external {
    collateralToken.transferFrom(msg.sender, address(this), amount);
    depositedCollateral[msg.sender] += amount;
}

function borrow(uint256 amount) external {
    // Use tracked deposits, not spot balance
    uint256 collateral = depositedCollateral[msg.sender];
    uint256 maxBorrow = (collateral * price * LTV) / 1e18;
    
    require(amount <= maxBorrow, "Insufficient collateral");
    
    borrowed[msg.sender] += amount;
    lendingToken.transfer(msg.sender, amount);
}
```

### Detection Checklist
- [ ] Collateral tracked internally (not spot balance)
- [ ] Deposit required before borrowing
- [ ] Cannot borrow against flash-loaned assets
- [ ] Collateral locked until debt repaid

### Real-World Impact
- **Cream Finance (2021):** $130M+ via flash loan collateral manipulation
- **Severity:** Critical (theft of funds)

---

## Anti-Pattern 6: Flash Loan Arbitrage Drain

### Description
Protocol offers arbitrage opportunities that can be extracted atomically via flash loans, draining reserves.

### Vulnerable Code
```solidity
// VULNERABLE - Price discrepancy between internal and external
function swap(uint256 amountIn) external {
    // Internal price calculation (can diverge from market)
    uint256 amountOut = (amountIn * internalPrice) / 1e18;
    
    tokenIn.transferFrom(msg.sender, address(this), amountIn);
    tokenOut.transfer(msg.sender, amountOut);
}

// ATTACK:
// 1. Flash loan tokenIn
// 2. Swap at favorable internal price
// 3. Sell tokenOut on external market
// 4. Repay flash loan
// 5. Profit from price discrepancy
```

### Why It's Vulnerable
- Protocol price diverges from market
- Flash loan enables capital-free arbitrage
- Reserves drained via repeated swaps
- Protocol becomes insolvent

### Secure Pattern
```solidity
// SECURE - Use external oracle, swap limits
function swap(uint256 amountIn) external {
    // Use Chainlink/TWAP oracle for price
    uint256 marketPrice = oracle.getPrice(tokenIn, tokenOut);
    uint256 amountOut = (amountIn * marketPrice) / 1e18;
    
    // Add swap fee to prevent perfect arbitrage
    uint256 fee = amountOut * SWAP_FEE / 10000;  // 0.3% fee
    amountOut -= fee;
    
    // Daily swap limit per user
    require(dailySwapVolume[msg.sender] + amountIn <= DAILY_LIMIT, "Limit exceeded");
    dailySwapVolume[msg.sender] += amountIn;
    
    tokenIn.transferFrom(msg.sender, address(this), amountIn);
    tokenOut.transfer(msg.sender, amountOut);
}
```

### Detection Checklist
- [ ] External oracle for pricing
- [ ] Swap fees prevent zero-profit arbitrage
- [ ] Volume limits per user/block
- [ ] Slippage protection

### Real-World Impact
- **Warp Finance (2020):** $7.7M via flash loan arbitrage
- **Alpha Homora (2021):** $37M via flash loan manipulation
- **Severity:** Critical (reserve drain)

---

## Anti-Pattern 7: Flash Loan Cascade Liquidation

### Description
Flash loans trigger artificial price crashes, causing cascade liquidations and bad debt.

### Vulnerable Code
```solidity
// VULNERABLE
function liquidate(address user) external {
    // Uses spot price from manipulatable source
    uint256 price = getSpotPrice();
    uint256 collateralValue = userCollateral[user] * price;
    uint256 debt = userDebt[user];
    
    require(collateralValue < debt * LIQUIDATION_THRESHOLD, "Not liquidatable");
    
    // Liquidation logic
}

// ATTACK:
// 1. Flash loan to crash collateral price on DEX
// 2. Liquidate multiple positions (sees crashed price)
// 3. Acquire collateral at discount
// 4. Let price recover
// 5. Repay flash loan with profit
```

### Why It's Vulnerable
- Liquidation uses manipulatable price
- Flash loan creates temporary price crash
- Mass liquidations at unfair prices
- Protocol accumulates bad debt

### Secure Pattern
```solidity
// SECURE - TWAP + circuit breaker
function liquidate(address user) external {
    // Use TWAP to resist manipulation
    uint256 price = oracle.getTWAP(collateralToken, 600);  // 10 min
    
    // Circuit breaker: Prevent liquidations if price changed too fast
    uint256 previousPrice = lastPrice;
    require(
        price > previousPrice * 90 / 100 && 
        price < previousPrice * 110 / 100,
        "Price change too extreme"
    );
    
    uint256 collateralValue = userCollateral[user] * price;
    uint256 debt = userDebt[user];
    
    require(collateralValue < debt * LIQUIDATION_THRESHOLD, "Not liquidatable");
    
    // Liquidation logic
    lastPrice = price;
}
```

### Detection Checklist
- [ ] TWAP or external oracle for liquidations
- [ ] Circuit breaker for extreme price moves
- [ ] Liquidation delay or grace period
- [ ] Bad debt handling mechanism

### Real-World Impact
- **Venus Protocol (2021):** $200M+ bad debt via XVS manipulation
- **Severity:** Critical (bad debt, insolvency)

---

## Comparison Table

| Anti-Pattern | Severity | Attack Cost | Fix Difficulty | Notable Exploit |
|--------------|----------|-------------|----------------|-----------------|
| Governance Voting | Critical | Medium | Medium | Beanstalk ($182M) |
| Oracle Manipulation | Critical | Low | Easy | bZx ($954K) |
| Interest Rate Manipulation | High | Low | Medium | Inverse Finance ($15.6M) |
| Reward Farming | High | Low | Medium | Multiple farms |
| Collateral Inflation | Critical | Low | Easy | Cream Finance ($130M) |
| Arbitrage Drain | Critical | Low | Medium | Warp Finance ($7.7M) |
| Cascade Liquidation | Critical | Medium | Medium | Venus Protocol ($200M) |

---

## Flash Loan Resistance Checklist

```solidity
// Protocol Flash Loan Safety Audit

// 1. Governance
[ ] Voting uses historical snapshots (not current balance)
[ ] Time delay between snapshot and vote execution
[ ] Proposal requires stake/lock-up period

// 2. Oracles
[ ] No spot price reads from DEXes
[ ] TWAP minimum 10 minutes OR external oracle
[ ] Multiple price source validation
[ ] Price deviation checks

// 3. Interest/Rates
[ ] Interest calculated on time-weighted utilization
[ ] Max rate change per block enforced
[ ] No single-block rate spikes possible

// 4. Rewards
[ ] Rewards based on time-weighted stake
[ ] Minimum stake duration required
[ ] Historical snapshots for distribution

// 5. Collateral
[ ] Internal accounting (not spot balances)
[ ] Deposit required before borrowing
[ ] Collateral locked until repayment

// 6. Arbitrage
[ ] External oracle pricing
[ ] Swap fees prevent zero-profit arbitrage
[ ] Volume limits per user/block

// 7. Liquidation
[ ] TWAP or external oracle
[ ] Circuit breaker for extreme moves
[ ] Liquidation delay/grace period
```

---

## Testing Strategy

### Flash Loan Attack Simulation
```solidity
function testFlashLoanAttack() public {
    // 1. Setup
    uint256 flashAmount = 1_000_000e18;
    
    // 2. Simulate flash loan
    token.mint(attacker, flashAmount);
    
    // 3. Attack vector
    vm.startPrank(attacker);
    protocol.exploit();  // Your attack here
    vm.stopPrank();
    
    // 4. Verify no profit
    assertEq(token.balanceOf(attacker), flashAmount);
    
    // 5. Repay simulation
    token.burn(attacker, flashAmount);
}
```

### Test Cases
1. **Governance:** Flash loan vote attempt
2. **Oracle:** Spot price manipulation
3. **Interest:** Utilization spike
4. **Rewards:** Flash stake claim
5. **Collateral:** Flash deposit borrow
6. **Arbitrage:** Price discrepancy exploitation
7. **Liquidation:** Artificial price crash

---

## Mitigation Priority

### Immediate (Critical)
1. Add snapshot-based voting
2. Replace spot price with TWAP/external oracle
3. Track collateral internally (not spot balance)

### Short-term (High)
4. Time-weight interest calculations
5. Add reward vesting/duration requirements
6. Implement liquidation circuit breakers

### Medium-term (Medium)
7. Add swap fees and volume limits
8. Multi-oracle price validation
9. Comprehensive flash loan attack testing

---

## See Also

- **Attack Trees:** [governance-attack-tree.md](../attack-trees/governance-attack-tree.md)
- **Patterns:** [flash-loan-patterns.md](../patterns/flash-loan-patterns.md), [oracle-patterns.md](../patterns/oracle-patterns.md)
- **Related:** [oracle-anti-patterns.md](./oracle-anti-patterns.md), [governance-anti-patterns.md](./governance-anti-patterns.md)

---

**Last Updated:** 2025  
**Version:** 1.0  
**Total Known Losses:** $400M+
