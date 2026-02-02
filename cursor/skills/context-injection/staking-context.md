# STAKING / REWARDS SECURITY CONTEXT
> Ultra-compressed audit context. ~200 lines = 80% coverage.

## REWARD CALCULATION CRITICAL
1. Division by zero: `reward = total / stakers` when stakers = 0 → revert | handle empty pool
2. Precision loss: `reward = amount * userStake / totalStake` → dust loss | scale up then down
3. Retroactive rewards: stake after reward, claim immediately → steal rewards | snapshot at reward time
4. Flash stake: stake → claim → unstake in same block → free rewards | time-weighted balance

## REWARD DISTRIBUTION PATTERNS
1. Push (iterate): loop over stakers → gas DoS with many stakers | pull pattern instead
2. Pull (claim): user calls claim → requires accurate accounting | preferred pattern
3. Merkle: off-chain calculation, on-chain proof → centralized but gas efficient | verify root securely

### RewardPerToken Pattern
```solidity
// Standard staking reward calculation
rewardPerTokenStored += (reward * 1e18) / totalStaked;
rewards[user] += (balanceOf[user] * (rewardPerTokenStored - userRewardPerTokenPaid[user])) / 1e18;
userRewardPerTokenPaid[user] = rewardPerTokenStored;

// CRITICAL: Update rewardPerTokenStored BEFORE any balance change
```

## TIMING ATTACKS
1. Stake before reward: front-run reward distribution → larger share | snapshot before announce
2. Claim and restake: compound faster than intended → excessive APY | epoch-based rewards
3. Last-second stake: stake 1 block before epoch ends → full epoch reward | pro-rata by time
4. Sandwich reward: stake → reward distributed → unstake → profit | minimum lock period

## WITHDRAWAL VULNERABILITIES
1. No cooldown: instant unstake → time-sensitive attacks | cooldown period
2. Cooldown bypass: transfer staked tokens → avoid cooldown | non-transferable or track per-token
3. Slashing during withdrawal: unbonding funds slashed → user confusion | clear documentation
4. Emergency withdraw: bypasses rewards → but should bypass penalties too? | define clearly

## SLASHING ISSUES
1. Slash more than staked: `balance -= slashAmount` underflows → revert or wrap | cap at balance
2. Slash already withdrawn: user unstaked, then slashed → can't slash | slash before unstake
3. Slash distribution: slashed funds go where? → protocol, burn, or redistribute | define clearly
4. Cascading slash: slash triggers liquidation triggers more slash → death spiral | circuit breaker

## DELEGATION RISKS
1. Delegate to self: circular delegation → infinite rewards | prevent self-delegation
2. Delegate chain: A→B→C→A circular → infinite or stuck | max delegation depth
3. Inactive delegate: delegate stops validating → no rewards | auto-redelegate option
4. Malicious delegate: delegate gets slashed → delegator loses stake | delegate reputation

## COMPOUNDING / RESTAKING
1. Auto-compound griefing: anyone can compound for user → force taxable event | user-only compound
2. Compound rounding: each compound loses dust → significant over time | batch compounds
3. Reward token != stake token: compound requires swap → slippage | handle swap securely

## LOCK PERIODS
1. Lock bypass: transfer locked tokens → circumvent lock | non-transferable during lock
2. Lock extension: new stake extends all locks → user confusion | per-deposit lock tracking
3. Early unlock penalty: penalty too low → everyone unlocks early | significant penalty

## EMERGENCY SCENARIOS
1. Pause: can't stake, but can unstake? → define behavior | typically allow exit
2. Migration: move to v2 → handle locked positions | migration path for all states
3. Token rescue: admin recovers stuck tokens → can take staked tokens? | exclude stake token

## CRITICAL CODE PATTERNS

### Bad Reward Calculation (Retroactive)
```solidity
// ❌ VULNERABLE - Can stake after reward, claim immediately
function distributeReward(uint256 amount) external {
    rewardBalance += amount;
}
function claim() external {
    uint256 reward = rewardBalance * balanceOf[msg.sender] / totalStaked;
    // Attacker stakes large amount, immediately claims
}

// ✅ SAFE - Snapshot at reward time
function distributeReward(uint256 amount) external {
    rewardPerTokenStored += amount * 1e18 / totalStaked;  // Snapshot current stakers
}
```

### Bad Flash Stake Protection
```solidity
// ❌ VULNERABLE - Stake and claim in same block
function stake(uint256 amount) external {
    balances[msg.sender] += amount;
    totalStaked += amount;
}
function claim() external {
    _updateReward(msg.sender);
    uint256 reward = rewards[msg.sender];
    rewards[msg.sender] = 0;
    rewardToken.transfer(msg.sender, reward);
}

// ✅ SAFE - Time-weighted rewards
function claim() external {
    require(lastStakeTime[msg.sender] + MIN_STAKE_DURATION <= block.timestamp, "Too soon");
    // ... rest of claim
}
```

### Bad Withdrawal (Reentrancy)
```solidity
// ❌ VULNERABLE
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    stakingToken.transfer(msg.sender, amount);  // External call first
    balances[msg.sender] -= amount;
    totalStaked -= amount;
}

// ✅ SAFE
function withdraw(uint256 amount) external nonReentrant {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;
    totalStaked -= amount;
    _updateReward(msg.sender);  // Update before transfer
    stakingToken.transfer(msg.sender, amount);
}
```

### Bad Slash Handling
```solidity
// ❌ VULNERABLE - Can underflow
function slash(address user, uint256 amount) external onlySlasher {
    balances[user] -= amount;  // Underflow if amount > balance
}

// ✅ SAFE
function slash(address user, uint256 amount) external onlySlasher {
    uint256 actualSlash = amount > balances[user] ? balances[user] : amount;
    balances[user] -= actualSlash;
    totalStaked -= actualSlash;
    emit Slashed(user, actualSlash);
}
```

## CHECKLIST (Quick Scan)
- [ ] Reward math: precision, division by zero, rounding
- [ ] Timing: flash stake protection, snapshot rewards
- [ ] Withdrawal: cooldown, reentrancy, slashing window
- [ ] Delegation: circular, self-delegation, inactive
- [ ] Slashing: cap at balance, clear distribution
- [ ] Locks: non-transferable, per-deposit tracking
- [ ] Emergency: pause behavior, migration path
- [ ] Compounding: who can trigger, rounding loss

## COMMON FINDINGS BY SEVERITY
**Critical**: Retroactive reward steal, flash stake, reentrancy drain
**High**: Precision loss drain, slash underflow, cooldown bypass
**Medium**: Circular delegation, compound griefing, lock bypass
**Low**: Dust accumulation, rounding direction, event emission
