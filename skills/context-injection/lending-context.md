# LENDING PROTOCOL SECURITY CONTEXT
> Ultra-compressed audit context. ~200 lines = 80% coverage.

## ORACLE CRITICAL CHECKS
1. Staleness: `block.timestamp - updatedAt > HEARTBEAT` → stale price exploitation | check heartbeat per feed
2. Zero/Negative: `price <= 0` → division errors, wrong valuations | require(price > 0)
3. Round completeness: `answeredInRound < roundId` → incomplete round | require(answeredInRound >= roundId)
4. L2 Sequencer: sequencer down → stale prices look fresh | check sequencer uptime feed
5. Decimals mismatch: mixing 8/18 decimal feeds → 10^10x errors | normalize all to 18 decimals
6. TWAP window: < 30 min → flash loan manipulable | use >= 30 min TWAP
7. Spot price: `getReserves()` directly → instant manipulation | never use spot for lending

## LIQUIDATION VULNERABILITIES
1. Self-liquidation: user liquidates own position → extract bonus | block msg.sender == borrower
2. Liquidation DoS: gas-expensive loops in liquidation → positions unliquidatable | bound iterations
3. Bonus calculation: `bonus = debt * BONUS_PCT` with rounding → protocol loss | round against liquidator
4. Partial liquidation: close factor too high → over-liquidation | cap at 50% typically
5. Bad debt: underwater positions → socialized losses | reserve fund, insurance
6. Flash loan liquidation: borrow → liquidate → repay in 1 tx → MEV extraction | acceptable but monitor
7. Price manipulation liquidation: manipulate oracle → liquidate healthy positions | use TWAP

## INTEREST RATE ISSUES
1. Utilization > 100%: edge case math → negative rates or overflow | cap utilization at 100%
2. Rate jump manipulation: deposit huge → lower rate → borrow cheap → withdraw | time-weighted rates
3. Accrual rounding: `interest = principal * rate * time / PRECISION` → dust accumulation | round up for protocol
4. Timestamp manipulation: `block.timestamp` in rate calc → miner manipulation | acceptable, bounded
5. Compound frequency: continuous vs discrete → arbitrage opportunity | match market standard

## COLLATERAL MANAGEMENT
1. Deposit reentrancy: ERC777/hooks during deposit → inflate balance | nonReentrant + CEI
2. Withdrawal check: `collateral < borrowed * factor` after withdraw → undercollateralized | check BEFORE transfer
3. Collateral factor: too high (>90%) → rapid liquidation cascades | conservative factors
4. Same-block deposit/borrow: deposit → borrow max → price drops → bad debt | minimum delay or buffer
5. Asset blacklist: collateral token paused → stuck positions | emergency withdrawal mechanism
6. Rebasing tokens: balance changes between calls → accounting mismatch | use wrapped versions

## FIRST DEPOSITOR / SHARE INFLATION
1. Attack: deposit 1 wei → donate 10000 tokens → next depositor gets 0 shares
2. Detection: `shares = assets * totalSupply / totalAssets` when totalSupply small
3. Fix A: Virtual shares/assets (offset) - `shares = assets * (totalSupply + OFFSET) / (totalAssets + OFFSET)`
4. Fix B: Minimum first deposit - require first deposit >= MIN_DEPOSIT (e.g., 1000 wei)
5. Fix C: Dead shares - mint shares to zero address on deployment

## REENTRANCY PATTERNS
1. Withdraw: external call before balance update → drain funds | CEI + nonReentrant
2. Cross-function: withdraw calls transfer, attacker calls borrow → double dip | global reentrancy lock
3. Read-only: during callback, `getSharePrice()` returns stale value → price manipulation | lock view functions
4. Cross-protocol: callback into integrated protocol → manipulate shared state | verify post-conditions

## FLASH LOAN INTEGRATION
1. Protocol has flash loans: check callback validation, fee collection, reentrancy
2. Protocol uses flash loans: can oracle be manipulated in same block?
3. Governance flash loan: borrow → vote → return → proposal passes | snapshot voting

## SUPPLY/BORROW CAPS
1. Missing caps: unlimited minting → infinite leverage attack
2. Cap bypass: cap checked before, not after action → exceed via reentrancy
3. Per-user caps: Sybil attack with multiple addresses → no real limit

## LIQUIDATION MATH
```solidity
// Liquidator repays debt, receives collateral + bonus
debtToRepay = min(userDebt * closeFactor, maxRepayable);
collateralSeized = debtToRepay * liquidationBonus / collateralPrice;
// CHECK: collateralSeized <= userCollateral
// CHECK: protocol remains solvent after seizure
```

## HEALTH FACTOR CALCULATION
```solidity
// healthFactor = (collateralValue * LTV) / borrowedValue
// healthFactor < 1.0 → liquidatable
// CHECKS:
// - All assets use same price precision
// - Summation doesn't overflow
// - Empty positions handled (div by zero)
```

## CRITICAL CODE PATTERNS

### Bad Oracle Usage
```solidity
// [VULNERABLE]
(, int256 price, , , ) = feed.latestRoundData();
return uint256(price);

// [SAFE]
(uint80 roundId, int256 price, , uint256 updatedAt, uint80 answeredInRound) = feed.latestRoundData();
require(price > 0, "Invalid price");
require(answeredInRound >= roundId, "Stale round");
require(block.timestamp - updatedAt <= HEARTBEAT, "Stale price");
```

### Bad Share Calculation
```solidity
// [VULNERABLE] to first depositor attack
shares = assets * totalSupply / totalAssets;

// [SAFE] with virtual offset
shares = assets * (totalSupply + 1e3) / (totalAssets + 1e3);
```

### Bad Withdrawal
```solidity
// [VULNERABLE] to reentrancy
token.transfer(msg.sender, amount);  // External call
balances[msg.sender] -= amount;       // State update after

// [SAFE] CEI pattern
balances[msg.sender] -= amount;       // State update first
token.transfer(msg.sender, amount);   // External call last
```

## CHECKLIST (Quick Scan)
- [ ] Oracle: staleness, zero, decimals, L2 sequencer
- [ ] Liquidation: self-liquidate, DoS, bonus math
- [ ] Interest: utilization bounds, rounding direction
- [ ] Collateral: reentrancy, factor limits, withdrawal checks
- [ ] Shares: first depositor attack, inflation
- [ ] Caps: supply caps, borrow caps, per-user limits
- [ ] Flash loans: callback validation, oracle manipulation
- [ ] Tokens: rebasing, fee-on-transfer, ERC777 hooks

## COMMON FINDINGS BY SEVERITY
**Critical**: Oracle manipulation, reentrancy drain, first depositor
**High**: Liquidation DoS, bad debt accumulation, rate manipulation
**Medium**: Rounding errors, cap bypasses, missing staleness
**Low**: Centralization, minor precision loss, gas optimization
