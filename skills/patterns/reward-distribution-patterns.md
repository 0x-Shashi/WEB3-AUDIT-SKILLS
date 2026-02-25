---
id: PAT-REWARD-DISTRIBUTION
title: Reward Distribution Security Patterns
category: defi
severity: high
difficulty: intermediate
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - rewards
  - distribution
  - staking-rewards
  - claim
  - emission
related_patterns:
  - deposit-reward-tokens-patterns
  - staking-patterns
  - precision-loss-patterns
  - rounding-patterns
finding_count: 35
last_updated: 2026-02-24
---
# Reward Distribution Security Patterns

## Overview

**Frequency**: 35 occurrences (0.07% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 3 | 14 | 14 | 4 | 0 |

**Common Sources**: Code4rena, Sherlock, Spearbit

---

## Detection Checklist

- [ ] Verify reward accrual math handles zero total stake and first/last staker edge cases
- [ ] Check that reward rate changes don't retroactively affect unclaimed rewards
- [ ] Review claim timing — can users front-run reward deposits or epoch changes?
- [ ] Analyze dust accumulation from rounding in per-share reward calculations
- [ ] Test reward distribution accuracy with varied stake amounts (1 wei, max uint, etc.)

---

## Key Vulnerability Classes

### 1. Reward Speed Manipulation

When protocol admins can change reward emission rates without access controls or accounting settlement, rewards can be drained.

```solidity
// VULNERABLE: Owner can manipulate reward speed
function changeRewardSpeed(uint256 newSpeed) external onlyOwner {
    rewardSpeed = newSpeed;
    // ⚠ No accrual of pending rewards at old speed
    // ⚠ Combined with vault attach/detach, can drain pool
}
```

**Real-World**: Popcorn — vault owner could attach vault to staking contract, set maximum reward speed, claim all accumulated rewards, effectively draining 99.9% of reward tokens.

### 2. Accumulated Reward Per Share Precision

The standard reward distribution formula (`rewardPerShare += rewardAmount * PRECISION / totalStaked`) is vulnerable when:
- `totalStaked` is very large relative to `rewardAmount` (reward truncates to 0)
- `totalStaked` is very small (extreme `rewardPerShare` values)

```solidity
// Standard Synthetix-style distribution
function updateReward() internal {
    if (totalStaked == 0) return; // ⚠ Rewards during zero-stake period are lost
    
    uint256 reward = (block.timestamp - lastUpdate) * rewardRate;
    rewardPerShareStored += reward * 1e18 / totalStaked;
    // ⚠ If totalStaked = 1e30 and reward = 1e6, result rounds to 0
    //    Rewards are silently lost
    lastUpdate = block.timestamp;
}
```

**Fix**: Use high-precision multipliers (1e36 instead of 1e18), or accumulate rewards until they exceed the precision threshold.

### 3. Claim Timing / Just-in-Time Staking

Users can stake immediately before a reward distribution event and claim a proportional share without contributing over the earning period.

```solidity
// Attack flow:
// 1. Watch for reward distribution tx in mempool
// 2. Front-run: stake large amount (50% of pool)
// 3. Reward distributed: attacker gets 50% of reward
// 4. Back-run: unstake immediately
// 5. Profit: 50% of reward for seconds of staking

// FIX: Time-weighted reward calculation
function earned(address user) public view returns (uint256) {
    uint256 timeWeightedStake = stakes[user] * (block.timestamp - stakeTimestamp[user]);
    return timeWeightedStake * rewardPerShare / totalTimeWeightedStake;
}
```

### 4. Reward Token Accounting Mismatch

When reward tokens are the same as staking tokens, or when multiple reward tokens share accounting logic, double-counting or shortfalls occur.

```solidity
// VULNERABLE: Reward token same as stake token
function notifyRewardAmount(uint256 reward) external {
    rewardRate = reward / duration;
    // ⚠ contract.balanceOf(this) includes both staked tokens AND rewards
    //    Withdrawals may consume reward balance or vice versa
}
```

### 5. Lost Rewards During Zero-Stake Periods

When `totalStaked == 0`, reward accrual produces division-by-zero or is skipped entirely. Rewards emitted during zero-stake periods are permanently lost.

```solidity
// VULNERABLE: Rewards lost when no stakers
function updateReward() internal {
    if (totalStaked == 0) {
        lastUpdate = block.timestamp; // ⚠ Rewards for this period are lost
        return;
    }
    rewardPerShareStored += (block.timestamp - lastUpdate) * rewardRate * 1e18 / totalStaked;
    lastUpdate = block.timestamp;
}
```

**Fix**: Accumulate unsettled rewards and distribute when first staker arrives, or pause emission during zero-stake periods.

---

## Real-World Examples

### Example 1: [H-01] Reward speed manipulation drains reward pool

**Source**: Code4rena
**Protocol**: Popcorn
**Impact**: HIGH

**Details**:

The vault owner could call `changeRewardSpeed()` after attaching a vault to the staking contract. By setting reward speed to maximum and immediately claiming, the owner could drain nearly all reward tokens. The attack required two transactions: one to set speed, one to claim accumulated rewards at the inflated rate.

---

### Example 2: [M-02] Dust rewards accumulate unreachable in contract

**Source**: Sherlock
**Protocol**: Various
**Impact**: MEDIUM

**Details**:

Due to integer division in per-share calculations, small amounts of reward tokens become unreachable. Over time with many distribution cycles, these dust amounts accumulate. In one protocol, ~2% of total rewards were permanently locked due to rounding over 12 months of operation.

```solidity
// Per-user reward = userStake * rewardPerShare / 1e18
// If rewardPerShare = 1e18 + 1, and userStake = 1e6:
//   reward = 1e6 * (1e18 + 1) / 1e18 = 1_000_000.000001 → rounds to 1_000_000
//   0.000001 tokens lost per user per claim
```

---

### Example 3: [H-03] Front-running epoch transition captures full reward period

**Source**: Code4rena
**Protocol**: Epoch-based Staking
**Impact**: HIGH

**Details**:

Protocol distributed rewards at epoch boundaries. An attacker could monitor for the epoch transition transaction, stake a large amount in the last block of the epoch, and capture a proportional share of the entire epoch's rewards despite only staking for one block.

---

## Interaction with Other Patterns

| Combined With | Creates Risk |
|---------------|-------------|
| Flash loans | Temporary stake inflation for reward capture |
| Front-running | Stake before reward distribution for unfair share |
| Precision loss | Accumulated dust from per-share rounding |
| Access control | Reward speed/rate manipulation by admin |
| Fee-on-transfer | Reward token amount mismatch on distribution |

---

## Recommended Secure Patterns

1. **Synthetix RewardPerToken**: Use proven `rewardPerToken` accumulator with `earned()` function
2. **Time-weighted staking**: Weight rewards by stake duration, not just amount at claim time
3. **Warmup period**: New stakes don't earn rewards for N blocks to prevent front-running
4. **Accrue before change**: Always settle all pending rewards before changing rates/speeds
5. **Separate accounting**: Keep reward token balance separate from staking token balance
6. **Precision multiplier**: Use 1e36 or higher precision for `rewardPerShare` calculations
7. **Epoch checkpointing**: Record stake snapshots at epoch boundaries, not at claim time
