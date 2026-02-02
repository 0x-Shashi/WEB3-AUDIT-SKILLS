# VAULT / YIELD SECURITY CONTEXT
> Ultra-compressed audit context. ~200 lines = 80% coverage.

## SHARE INFLATION / FIRST DEPOSITOR
1. Attack: deposit 1 wei → donate 1000 tokens → victim deposits 1000 → gets 0 shares
2. Math: `shares = assets * totalSupply / totalAssets` → when totalSupply=1, exploit possible
3. Fix A: Virtual offset `shares = assets * (supply + OFFSET) / (assets + OFFSET)` where OFFSET=1e3
4. Fix B: Minimum deposit: first deposit must be >= MIN_DEPOSIT (e.g., 10000 wei)
5. Fix C: Dead shares: mint 1000 shares to address(0) on deployment
6. Detection: `totalSupply()` can be small while `totalAssets()` is large

## ERC4626 SPECIFIC ISSUES
1. `maxDeposit` returns wrong value → user tx reverts | must reflect actual limit
2. `previewDeposit` inaccurate → user receives wrong shares | must match exactly
3. `convertToAssets` rounds wrong direction → arbitrage | round DOWN for withdraw
4. `convertToShares` rounds wrong direction → arbitrage | round DOWN for deposit
5. Reentrancy in deposit/withdraw → inflate shares | nonReentrant all entry points

## ROUNDING DIRECTION
```solidity
// ALWAYS favor the vault (protocol) over users
deposit:  shares = assets * supply / totalAssets  // Round DOWN (user gets fewer shares)
withdraw: assets = shares * totalAssets / supply  // Round DOWN (user gets fewer assets)
mint:     assets = shares * totalAssets / supply  // Round UP (user pays more)
redeem:   assets = shares * totalAssets / supply  // Round DOWN (user gets fewer assets)
```

## STRATEGY RISKS
1. Strategy rug: strategy has unlimited approval → drains vault | timelocked strategy changes
2. Loss socialization: strategy loses funds → all depositors affected | loss caps, insurance
3. Harvest timing: MEV around harvest → sandwich strategy rewards | private harvest or TWAP
4. Strategy migration: old strategy funds stuck → incomplete migration | complete withdrawal first

## ACCOUNTING MANIPULATION
1. Donation attack: donate to vault → inflate share price → exploit integrations | virtual shares
2. Profit sandwich: deposit before harvest → claim yield → withdraw after | time-weighted deposits
3. Balance vs debt: internal accounting vs actual balance → mismatch | reconciliation checks
4. Fee-on-transfer: vault assumes amount sent = amount received → wrong accounting | measure balance

## FEE VULNERABILITIES
1. Fee-on-deposit: fee applied wrong → user pays too much/little | clear fee calculation
2. Management fee: time-based fee → manipulate via deposit timing | checkpoint-based fee
3. Performance fee: fee on profits → calculate before/after correctly | watermark accounting
4. Fee extraction: attacker deposits → fee accrues → withdraws fee portion | fee on profit not deposits

## WITHDRAWAL ISSUES
1. Insufficient liquidity: not enough assets for withdrawal → revert | queue system or partial
2. Withdrawal queue: unfair queue → first-out or pro-rata | clear fairness rules
3. Instant vs delayed: instant allows timing attacks | consider delay
4. Max withdrawal: `maxWithdraw` lies → tx fails unexpectedly | accurate max calculation

## YIELD SOURCE RISKS
1. Yield source rugs: lending protocol fails → vault loses funds | diversification
2. Yield manipulation: yield source manipulated → vault exploited | monitor yields
3. Compounding frequency: compound too often → gas drain, too rare → lost yield | optimal frequency

## CRITICAL CODE PATTERNS

### Bad Share Calculation (First Depositor)
```solidity
// [VULNERABLE]
function deposit(uint256 assets) external returns (uint256 shares) {
    shares = totalSupply() == 0 ? assets : assets * totalSupply() / totalAssets();
    _mint(msg.sender, shares);
}
// Attacker: deposit 1 wei, donate 10000, victim gets 0 shares

// [SAFE] - Virtual shares
uint256 constant OFFSET = 1e3;
function deposit(uint256 assets) external returns (uint256 shares) {
    shares = assets * (totalSupply() + OFFSET) / (totalAssets() + OFFSET);
    _mint(msg.sender, shares);
}
```

### Bad Rounding
```solidity
// [VULNERABLE] - Rounds in user favor
function withdraw(uint256 shares) external returns (uint256 assets) {
    assets = (shares * totalAssets() + totalSupply() - 1) / totalSupply();  // Round UP
    _burn(msg.sender, shares);
    asset.transfer(msg.sender, assets);
}

// [SAFE] - Rounds in vault favor
function withdraw(uint256 shares) external returns (uint256 assets) {
    assets = shares * totalAssets() / totalSupply();  // Round DOWN
    _burn(msg.sender, shares);
    asset.transfer(msg.sender, assets);
}
```

### Bad Strategy Approval
```solidity
// [VULNERABLE] - Strategy can drain vault
function setStrategy(address newStrategy) external onlyOwner {
    strategy = newStrategy;
    asset.approve(newStrategy, type(uint256).max);  // Unlimited approval!
}

// [SAFE] - Limited and timelocked
function setStrategy(address newStrategy) external onlyOwner {
    require(proposedStrategy == newStrategy, "Not proposed");
    require(block.timestamp >= proposalTime + TIMELOCK, "Too early");
    _withdrawFromOldStrategy();
    strategy = newStrategy;
    asset.approve(newStrategy, 0);  // Clear old approval first
    // Approve only needed amount per deposit
}
```

### Bad Harvest (Sandwich)
```solidity
// [VULNERABLE] - Can be sandwiched
function harvest() external {
    uint256 profit = strategy.harvest();  // Public profit
    totalAssets += profit;  // Attacker deposited before, withdraws after
}

// [SAFE] - Time-weighted
function harvest() external {
    uint256 profit = strategy.harvest();
    // Profit unlocks linearly over 6 hours
    profitUnlockTime = block.timestamp + UNLOCK_DURATION;
    lockedProfit = profit;
}
```

## CHECKLIST (Quick Scan)
- [ ] First depositor: virtual shares or minimum deposit
- [ ] Rounding: favors vault in all cases
- [ ] ERC4626: preview functions accurate
- [ ] Strategy: timelocked changes, limited approval
- [ ] Fees: clear calculation, no extraction attack
- [ ] Withdrawal: sufficient liquidity, accurate max
- [ ] Harvest: MEV protection, time-weighted profit
- [ ] Token handling: fee-on-transfer, rebasing

## COMMON FINDINGS BY SEVERITY
**Critical**: First depositor attack, strategy drain, reentrancy
**High**: Rounding manipulation, donation attack, profit sandwich
**Medium**: Fee calculation errors, withdrawal queue unfairness
**Low**: Preview function inaccuracy, gas optimization
