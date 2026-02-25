---
id: PAT-STAKING
title: Staking Security Patterns
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
  - staking
  - unstaking
  - slashing
  - delegation
  - validators
related_patterns:
  - restaking-attacks
  - deposit-reward-tokens
  - delegate-patterns
  - withdraw-pattern-patterns
finding_count: 42
last_updated: 2026-02-24
---
# Staking Security Patterns

## Overview

**Frequency**: 42 occurrences (0.08% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 3 | 18 | 16 | 5 | 0 |

**Common Sources**: Sherlock, Code4rena, Spearbit, Cyfrin

---

## Detection Checklist

- [ ] Verify stake/unstake share calculations handle rounding correctly (first staker edge case)
- [ ] Check that voting power and delegation update atomically on stake/unstake
- [ ] Review slashing logic for manipulation vectors (sandwich slash, fraction underflow)
- [ ] Analyze withdrawal queue ordering and delay bypass vectors
- [ ] Test reward distribution during edge cases (zero total staked, dust amounts)

---

## Key Vulnerability Classes

### 1. Share Calculation Manipulation

Staking pools that issue share tokens for deposits are vulnerable to the same first-depositor attack as ERC4626 vaults. An attacker stakes 1 wei, then donates tokens to inflate share price, causing subsequent stakers to receive 0 shares.

```solidity
// VULNERABLE: First staker can manipulate share price
function stake(uint256 amount) external {
    uint256 shares;
    if (totalShares == 0) {
        shares = amount; // First staker sets the ratio
    } else {
        shares = (amount * totalShares) / totalStaked;
        // ⚠ If totalStaked is inflated via donation, shares rounds to 0
    }
    _mint(msg.sender, shares);
    totalStaked += amount;
}
```

**Fix**: Require minimum initial stake, use virtual offset (dead shares), or enforce minimum shares minted.

### 2. Voting Power Desync on Unstake

When staking tokens grant governance power, unstaking must decrease voting power atomically.

```solidity
// VULNERABLE: Voting power not decreased
function unstake(uint256 tokenId) external {
    stakedBalance[msg.sender] -= tokenAmount;
    _transfer(address(this), msg.sender, tokenId);
    // ⚠ Missing: votingPower[msg.sender] -= votes;
    //    User retains voting power after unstaking
}
```

**Real-World**: FrankenDAO — unstaking did not decrease `votingPower` or `totalVotingPower`, allowing users to retain governance influence after withdrawing stake.

### 3. Stake Dilution via Reward Timing

Attackers can front-run reward distribution by staking just before rewards arrive and unstaking immediately after, capturing a disproportionate share of rewards.

```solidity
// Attack flow:
// 1. Monitor mempool for reward distribution tx
// 2. Front-run: stake large amount
// 3. Reward distributed — attacker gets large share due to stake weight
// 4. Back-run: unstake immediately
```

**Fix**: Implement warmup periods, time-weighted stake calculations, or reward vesting.

### 4. Slashing Amount Manipulation

If slashing penalties are calculated as a percentage of current stake, an attacker who knows a slash is coming can unstake to minimize loss, then restake after the slash.

```solidity
// VULNERABLE: Slash only affects current stakers
function slash(address validator, uint256 penalty) external onlySlasher {
    uint256 slashAmount = (stakedBalance[validator] * penalty) / 10000;
    stakedBalance[validator] -= slashAmount;
    // ⚠ Users who front-ran the unstake avoid the slash entirely
}
```

**Fix**: Lock stakes during slashing window, use commit-reveal for slash proposals, enforce unbonding delays.

### 5. Unbonding Period Bypass

Withdrawals should enforce minimum unbonding periods. Common bypass vectors:
- Transferring staked position tokens to bypass cooldown
- Re-staking and immediately unstaking to reset withdrawal queue position
- Using flash loans to temporarily satisfy minimum stake requirements

---

## Real-World Examples

### Example 1: [H-01] Voting power not decreased on unstake in FrankenDAO

**Source**: Code4rena
**Protocol**: FrankenDAO
**Impact**: HIGH

**Details**:

When users unstake their FrankenPunks NFTs, the contract fails to decrease `votingPower` and `totalVotingPower`. Users retain voting power after withdrawing their stake, allowing them to influence governance decisions without any economic commitment. Combined with free staking, this enables a governance takeover at zero cost.

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-frankendao)

---

### Example 2: [H-02] Reward speed manipulation drains staking rewards

**Source**: Code4rena
**Protocol**: Popcorn
**Impact**: HIGH

**Details**:

The vault owner can manipulate `changeRewardSpeed()` by attaching and detaching the vault from the staking contract. This allows draining 99.9% of reward tokens by:
1. Setting reward speed to maximum
2. Claiming accumulated rewards
3. Resetting to drain remaining balance

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-popcorn)

---

### Example 3: [M-01] Stake dilution via just-in-time deposits

**Source**: Sherlock
**Protocol**: Various
**Impact**: MEDIUM

**Details**:

Multiple protocols suffer from stake dilution where users deposit large amounts right before reward distribution epochs. Without time-weighting, the new staker captures rewards disproportionate to their contribution period. This is especially acute in protocols with discrete reward epochs rather than continuous accrual.

---

## Interaction with Other Patterns

| Combined With | Creates Risk |
|---------------|-------------|
| Flash loans | Temporary stake inflation for voting or reward capture |
| Governance | Retained voting power after unstake |
| Reward tokens | Reward speed manipulation, dust attacks |
| Withdrawal queues | Queue position manipulation, unbonding bypass |
| Restaking | Cascading slashing across AVS operators |

---

## Recommended Secure Patterns

1. **Time-weighted staking**: Calculate rewards based on stake duration, not just amount
2. **Warmup period**: New stakes don't earn rewards for N blocks
3. **Cooldown enforcement**: Non-transferable stake positions during unbonding
4. **Atomic power updates**: Update voting power in same transaction as stake/unstake
5. **Dead shares**: Mint minimum shares to address(0) on pool initialization
6. **Slash-lock**: Prevent unstaking during active slashing proposals
