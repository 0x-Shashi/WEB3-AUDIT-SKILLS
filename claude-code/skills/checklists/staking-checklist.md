---
id: CHECKLIST-STAKING
title: Staking Protocol Audit Checklist
category: checklists
difficulty: intermediate
tags: [staking, rewards, slashing, delegation, liquid-staking]
last_updated: 2026-01-31
---

# Staking Protocol Audit Checklist

Quick-reference checklist for auditing staking protocols, liquid staking, and reward distribution systems.

---

## 🔴 Critical Checks

### Reward Calculation
```
[ ] Can rewards be claimed multiple times?
[ ] Is reward calculation overflow-safe?
[ ] Are rewards diluted by new stakers unfairly?
[ ] Is reward rate updated before stake changes?
[ ] Can rewards be drained by manipulation?
[ ] Are accumulated rewards tracked per user?
```

### Stake Accounting
```
[ ] Can more be unstaked than staked?
[ ] Is total staked accurate after deposits/withdrawals?
[ ] Can stake be duplicated or inflated?
[ ] First staker attack possible?
[ ] Rounding errors favor protocol or user?
```

### Withdrawal Security
```
[ ] Is unstaking cooldown enforced?
[ ] Can cooldown be bypassed?
[ ] Can pending withdrawals be cancelled maliciously?
[ ] Are withdrawal amounts correct?
[ ] Is there a withdrawal queue/limit?
```

---

## 🟠 High Priority Checks

### Slashing
```
[ ] Are slashing conditions clearly defined?
[ ] Can innocent stakers be slashed unfairly?
[ ] Is slashed amount distributed correctly?
[ ] Can slashing be front-run?
[ ] Is there a slashing limit/cap?
[ ] Insurance fund for slashing events?
```

### Delegation
```
[ ] Can delegators lose more than expected?
[ ] Are delegate rewards distributed fairly?
[ ] Can delegation be changed instantly?
[ ] Are undelegation delays enforced?
[ ] Can malicious validator steal delegated funds?
```

### Liquid Staking Tokens
```
[ ] Is exchange rate calculated correctly?
[ ] Can exchange rate be manipulated?
[ ] Rebasing vs non-rebasing handling?
[ ] Are rewards auto-compounded correctly?
[ ] Oracle dependency for exchange rate?
```

---

## 🟡 Medium Priority Checks

### Reward Distribution
```
[ ] Merkle distributor proofs validated?
[ ] Epoch-based vs continuous rewards?
[ ] Can reward token be changed/drained?
[ ] Are unclaimed rewards handled properly?
[ ] Reward vesting schedules enforced?
```

### Lock Periods
```
[ ] Are lock periods enforced on-chain?
[ ] Can locks be extended maliciously?
[ ] Early withdrawal penalties correct?
[ ] Lock-based voting power accurate?
[ ] veToken decay calculated correctly?
```

### Access Control
```
[ ] Who can update reward rates?
[ ] Who can pause staking/unstaking?
[ ] Who can slash validators?
[ ] Who can upgrade contracts?
[ ] Are admin keys secured?
```

---

## 🟢 Standard Checks

### Token Handling
```
[ ] Safe transfer functions used?
[ ] Approval race conditions handled?
[ ] Fee-on-transfer tokens compatible?
[ ] Rebasing tokens compatible?
[ ] Multiple reward token support?
```

### Math & Precision
```
[ ] Rewards per token calculation precise?
[ ] Large stake amounts overflow-safe?
[ ] Small stake amounts underflow-safe?
[ ] Division before multiplication avoided?
[ ] Correct decimal handling?
```

### State Management
```
[ ] Reentrancy protection on stake/unstake?
[ ] All state updated atomically?
[ ] Events emitted for tracking?
[ ] Checkpointing for historical queries?
```

---

## Common Vulnerability Patterns

### 1. Reward Calculation Bug
```solidity
// VULNERABLE: Rewards not updated before stake change
function stake(uint256 amount) external {
    balances[msg.sender] += amount;
    // New staker gets share of all historical rewards!
}

// SECURE: Update rewards first
function stake(uint256 amount) external {
    updateReward(msg.sender);  // Calculate pending rewards first
    balances[msg.sender] += amount;
}
```

### 2. Double Claim Attack
```solidity
// VULNERABLE: No claim tracking
function claimRewards() external {
    uint256 reward = calculateReward(msg.sender);
    rewardToken.transfer(msg.sender, reward);
    // Can be called again!
}

// SECURE: Track claims
function claimRewards() external {
    uint256 reward = calculateReward(msg.sender);
    rewards[msg.sender] = 0;  // Reset before transfer
    rewardToken.transfer(msg.sender, reward);
}
```

### 3. Share Inflation Attack
```solidity
// VULNERABLE: First staker attack
function stake(uint256 amount) external {
    shares = amount * totalShares / totalStaked;
    // If totalShares = 0 and totalStaked = 0, division issues
}

// SECURE: Minimum stake and virtual offset
function stake(uint256 amount) external {
    require(amount >= MIN_STAKE, "Too small");
    shares = amount * (totalShares + 1e18) / (totalStaked + 1e18);
}
```

### 4. Cooldown Bypass
```solidity
// VULNERABLE: Transfer resets cooldown recipient's timer
function transfer(address to, uint256 amount) {
    balances[msg.sender] -= amount;
    balances[to] += amount;
    cooldowns[to] = block.timestamp + COOLDOWN;  // Attacker can reset victim's cooldown
}

// SECURE: Cooldown per position
mapping(address => mapping(uint256 => uint256)) public positionCooldowns;
```

---

## Staking Type-Specific Checks

### Proof of Stake (PoS)
```
[ ] Minimum stake requirement enforced?
[ ] Validator set size limits?
[ ] Block reward distribution fair?
[ ] Jailing conditions clear?
[ ] Unjail process secure?
```

### Liquid Staking (Lido, Rocket Pool Style)
```
[ ] stETH/rETH exchange rate accurate?
[ ] Oracle for exchange rate decentralized?
[ ] Withdrawal queue implemented?
[ ] Validator selection fair?
[ ] Node operator incentives aligned?
```

### Restaking (EigenLayer Style)
```
[ ] Can restaked assets be double-slashed?
[ ] AVS registration secure?
[ ] Withdrawal escrow period sufficient?
[ ] Operator/delegator relationship clear?
[ ] Slashing severity bounded?
```

### veToken (Curve Style)
```
[ ] Lock time decay correct (linear)?
[ ] Maximum lock time enforced?
[ ] Voting power snapshot accurate?
[ ] Can lock be extended?
[ ] Unlock correctly releases all tokens?
```

---

## Integration Points

### With Governance
```
[ ] Staked tokens grant voting power?
[ ] Delegation of voting power separate from stake?
[ ] Snapshot timing for votes correct?
[ ] Can flash loan attack voting?
```

### With Lending
```
[ ] Can staked tokens be used as collateral?
[ ] Liquidation of staked positions handled?
[ ] Interest accrual on staked collateral?
```

### With DEXes
```
[ ] LP token staking rewards correct?
[ ] Impermanent loss considered in rewards?
[ ] LP withdrawal affects staking position?
```

---

## Quick Reference

### Synthetix-Style Reward Formula
```solidity
rewardPerToken = rewardPerToken + (reward * 1e18 / totalStaked)
earned = balance * (rewardPerToken - userRewardPerToken) / 1e18

// Update per user:
userRewardPerToken[user] = rewardPerToken
rewards[user] += earned
```

### veToken Voting Power
```
votingPower = amount * timeRemaining / maxLockTime

// If locked for 4 years: votingPower = amount * 1.0
// If locked for 1 year:  votingPower = amount * 0.25
// Decays linearly as time passes
```

### APR/APY Calculation
```
APR = (rewardsPerYear / totalStaked) * 100%
APY = (1 + APR/n)^n - 1  // n = compounding frequency
```

---

## Red Flags 🚩

- [ ] Rewards updated after stake change (not before)
- [ ] No minimum stake requirement
- [ ] Cooldown can be bypassed via transfers
- [ ] First staker can steal future rewards
- [ ] Slashing has no upper bound
- [ ] Reward rate can be changed retroactively
- [ ] No reentrancy protection
- [ ] Unclaimed rewards can expire/be swept
- [ ] Lock period can be extended by attacker
- [ ] Exchange rate oracle is centralized
