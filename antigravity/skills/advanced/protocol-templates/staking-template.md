# Staking Protocol Template

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     STAKING PROTOCOL                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌───────────────┐                       ┌───────────────┐      │
│  │   STAKERS     │──── Stake ──────────▶│  STAKING      │      │
│  │               │◀─── Rewards ─────────│  CONTRACT     │      │
│  └───────────────┘                       └───────┬───────┘      │
│                                                  │               │
│  ┌───────────────┐                               │               │
│  │  DELEGATORS   │──── Delegate ─────────────────┤               │
│  │               │◀─── Share of Rewards ─────────│               │
│  └───────────────┘                               │               │
│                                                  │               │
│  ┌───────────────┐                       ┌───────┴───────┐      │
│  │  VALIDATORS   │◀───────────────────── │   VALIDATOR   │      │
│  │  /OPERATORS   │                       │   MANAGER     │      │
│  └───────────────┘                       └───────────────┘      │
│         │                                                        │
│         ▼                                                        │
│  ┌───────────────┐                       ┌───────────────┐      │
│  │   SLASHING    │                       │   REWARDS     │      │
│  │   MODULE      │                       │   DISTRIBUTION│      │
│  └───────────────┘                       └───────────────┘      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Staking Types

### Proof of Stake (PoS)
- Network consensus participation
- Slashing for misbehavior
- Validator selection

### Liquidity Staking
- Stake and receive liquid tokens
- Continue using capital while staking
- Examples: Lido, Rocket Pool

### Yield Farming
- Stake LP tokens
- Earn protocol tokens
- Often time-limited

### Governance Staking
- Stake for voting power
- Time-locked positions
- veToken models

---

## Critical Functions

### 1. Stake

```solidity
function stake(uint256 amount) external {
    // Transfer tokens
    // Update user stake
    // Update global state
    // Mint receipt tokens (optional)
}
```

**Audit Points:**
- [ ] Stake correctly recorded
- [ ] Receipt tokens (if any) correct
- [ ] Existing rewards preserved
- [ ] Minimum stake enforced

### 2. Unstake/Withdraw

```solidity
function unstake(uint256 amount) external {
    // Check unbonding period
    // Update user stake
    // Transfer tokens (after delay)
}
```

**Audit Points:**
- [ ] Unbonding period enforced
- [ ] Correct amount returned
- [ ] Partial unstake handled
- [ ] Rewards claimed or preserved

### 3. Claim Rewards

```solidity
function claimRewards() external {
    // Calculate pending rewards
    // Update reward state
    // Transfer rewards
}
```

**Audit Points:**
- [ ] Reward calculation correct
- [ ] No double claiming
- [ ] Precision handling
- [ ] Empty claims handled

### 4. Delegate

```solidity
function delegate(address validator) external {
    // Move stake to validator
    // Share rewards with validator
}
```

**Audit Points:**
- [ ] Delegation tracked correctly
- [ ] Reward sharing correct
- [ ] Redelegate handled
- [ ] Validator limits

### 5. Slash

```solidity
function slash(address validator, uint256 amount) external {
    // Reduce validator stake
    // Affect delegators proportionally
}
```

**Audit Points:**
- [ ] Only authorized can slash
- [ ] Proportional distribution
- [ ] Slashing limits
- [ ] Appeal mechanism

---

## Common Vulnerabilities

### STAKE-01: Reward Manipulation via Flash Stake

**Risk:** Critical

**Description:** Stake just before rewards, claim, unstake immediately.

**Vulnerable Pattern:**
```solidity
function claimRewards() {
    uint256 share = stakes[msg.sender] / totalStaked;
    uint256 reward = pendingRewards * share;
    // No time consideration!
    transfer(msg.sender, reward);
}
```

**Attack:**
1. Wait for reward distribution time
2. Flash borrow tokens
3. Stake right before rewards
4. Claim large share
5. Unstake and repay

**Mitigation:**
```solidity
// Time-weighted rewards
function updateReward(address account) internal {
    rewardPerToken += (block.timestamp - lastUpdate) * rewardRate / totalStaked;
    rewards[account] += stakes[account] * (rewardPerToken - userRewardPerToken[account]);
    userRewardPerToken[account] = rewardPerToken;
}
```

---

### STAKE-02: Unbonding Period Bypass

**Risk:** High

**Description:** Bypass waiting period for unstaking.

**Vulnerable Pattern:**
```solidity
function unstake(uint256 amount) {
    pendingWithdrawals[msg.sender] = Withdrawal(amount, block.timestamp + DELAY);
}

function completeWithdrawal() {
    require(block.timestamp >= pendingWithdrawals[msg.sender].timestamp);
    // No check if new unstake request replaces old one!
}
```

**Attack:**
1. Request unstake for 100 tokens
2. Wait almost full period
3. Request unstake for 1 token (resets withdrawal)
4. Claim the 100 tokens (period passed)

**Mitigation:**
- Separate withdrawal queues
- Each unstake has own timer

---

### STAKE-03: Slashing Underflow

**Risk:** High

**Description:** Slashing more than staked causes underflow.

**Vulnerable Pattern:**
```solidity
function slash(address user, uint256 amount) {
    stakes[user] -= amount;  // Underflow if amount > stake!
}
```

**Mitigation:**
```solidity
function slash(address user, uint256 amount) {
    uint256 toSlash = amount > stakes[user] ? stakes[user] : amount;
    stakes[user] -= toSlash;
}
```

---

### STAKE-04: Reward Calculation Rounding

**Risk:** Medium

**Description:** Rounding errors accumulate or can be exploited.

**Vulnerable Pattern:**
```solidity
function getReward(address user) view returns (uint256) {
    return stakes[user] * totalRewards / totalStaked;  // Truncation!
}
```

**Issues:**
- Small stakers get nothing (rounds to 0)
- Large stakers get extra (accumulation)
- Dust left in contract

**Mitigation:**
- Accumulated reward per token
- Higher precision (ray math)
- Minimum reward thresholds

---

### STAKE-05: Validator Set Manipulation

**Risk:** High

**Description:** Attacker manipulates which validators are active.

**Vulnerable Pattern:**
```solidity
function getActiveValidators() returns (address[] memory) {
    // Sort by stake
    // Return top N
}
```

**Attack:**
1. Stake large amount across multiple validators
2. Push out legitimate validators
3. Control consensus/rewards

**Mitigation:**
- Validator registration process
- Stake limits per validator
- Governance oversight

---

### STAKE-06: Delegation Reward Theft

**Risk:** High

**Description:** Validator steals delegator rewards.

**Vulnerable Pattern:**
```solidity
function claimDelegatorRewards() onlyValidator {
    // Validator can claim all rewards
    // No forced distribution to delegators
}
```

**Mitigation:**
- Automatic reward distribution
- Delegators claim directly
- Commission limits

---

### STAKE-07: Liquid Staking Token Depeg

**Risk:** High

**Description:** Liquid staking token loses peg to underlying.

**Scenarios:**
1. Large slashing event
2. Withdrawal queue too long
3. Smart contract exploit

**Impact:**
- stETH trades below ETH
- Cascading liquidations in DeFi
- Loss of confidence

**Mitigation:**
- Insurance fund
- Gradual slashing
- Secondary markets liquidity

---

### STAKE-08: Epoch Boundary Attacks

**Risk:** Medium

**Description:** Actions at epoch boundaries have unexpected effects.

**Vulnerable Pattern:**
```solidity
function stake() {
    // Stake counts from next epoch
}

function claimRewards() {
    // Rewards from current epoch
}
```

**Attack:**
1. Stake at epoch N-1
2. Claim rewards at epoch N start
3. Rewards include epoch N-1 (where stake wasn't active)

**Mitigation:**
- Clear epoch accounting
- Snapshot at epoch start
- Same rules for stake/unstake

---

## Real Exploit Examples

| Protocol | Date | Loss | Vulnerability |
|----------|------|------|---------------|
| Ankr | Dec 2022 | $5M | Minting key compromise |
| Various Farms | Ongoing | Variable | Reward manipulation |
| Staking Derivatives | Various | Variable | Depeg events |

---

## Reward Distribution Models

### Simple: Proportional

```
user_reward = total_rewards * user_stake / total_stake
```
**Issue:** Susceptible to flash staking

### Better: Time-Weighted

```
reward_per_token += time_elapsed * reward_rate / total_stake
user_reward = user_stake * (reward_per_token - user_paid)
```
**Standard:** Synthetix StakingRewards model

### Best: veToken Model

```
voting_power = stake_amount * time_remaining / max_lock
```
**Example:** Curve ve model

---

## Staking Audit Checklist

### Core Staking
- [ ] Stake correctly recorded
- [ ] Unstake enforces delay
- [ ] Rewards time-weighted
- [ ] No flash stake exploit

### Reward Distribution
- [ ] Calculation precision
- [ ] No double claiming
- [ ] Correct per-user tracking
- [ ] Handles zero total stake

### Delegation
- [ ] Reward sharing correct
- [ ] Redelegate handled
- [ ] Validator limits
- [ ] Slashing proportional

### Slashing
- [ ] Authorized callers only
- [ ] No underflow
- [ ] Limits on single slash
- [ ] Delegator protection

### Liquid Staking
- [ ] Share price calculation
- [ ] Withdrawal queue
- [ ] Oracle dependencies
- [ ] Depeg scenarios

### Access Control
- [ ] Admin functions protected
- [ ] Validator registration
- [ ] Emergency pause

---

## Protocol-Specific Patterns

### Lido Style
- stETH rebasing token
- Node operator registry
- Oracle for beacon chain

### Rocket Pool Style
- rETH value-accruing token
- Permissionless node operators
- Minipool architecture

### EigenLayer Style
- Restaking
- AVS integration
- Slashing conditions

### Curve/ve Style
- Time-locked staking
- Vote-escrow tokens
- Gauge weights

---

## Detection Commands

```bash
# Find staking functions
grep -rn "function stake\|function deposit\|function bond" --include="*.sol"

# Find reward calculations
grep -rn "reward.*token\|pending.*reward\|claim.*reward" --include="*.sol"

# Find delegation
grep -rn "delegate\|validator\|operator" --include="*.sol"

# Find slashing
grep -rn "slash\|penalty\|punish" --include="*.sol"

# Find time locks
grep -rn "unbond\|cooldown\|delay\|lock.*period" --include="*.sol"

# Find share calculations
grep -rn "share.*price\|exchange.*rate\|totalAssets" --include="*.sol"
```
