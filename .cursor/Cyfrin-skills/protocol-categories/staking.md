# Staking Protocol Security

## Quick Start

Staking protocols allow users to lock tokens in exchange for rewards. They range from simple reward distribution to complex liquid staking derivatives. Security concerns center around reward calculations, withdrawal mechanics, and slashing conditions.

**Risk Level:** MEDIUM to HIGH  
**Common Attacks:** Reward manipulation, reentrancy, first staker attacks  
**Key Considerations:** Reward math, time-based calculations, unstaking periods

## Staking Types

| Type | Examples | Primary Risks |
|------|----------|---------------|
| Simple Staking | Basic reward pools | Reward calculation errors |
| Liquid Staking | Lido, Rocket Pool | Oracle, slashing, share price |
| Delegated Staking | Validator networks | Slashing, validator trust |
| LP Staking | Farming | Impermanent loss, reward timing |
| veToken | Curve, Balancer | Lock manipulation, voting power |

## Most Critical Staking Vulnerabilities

### 1. Reward Calculation Errors
Incorrect math leads to over/under distribution.

### 2. First Staker/Donation Attacks
Early stakers can manipulate reward rates.

### 3. Reentrancy in Stake/Unstake
Callbacks during withdrawal enable attacks.

### 4. Time Manipulation
Block timestamp gaming for rewards.

### 5. Slashing Logic Errors
Incorrect slashing can drain user funds.

## API Query: Staking Vulnerabilities

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "protocolCategory": [{"value": "Staking"}],
      "impact": ["HIGH", "MEDIUM"],
      "qualityScore": 3,
      "sortField": "Quality"
    }
  }'
```

## API Query: Liquid Staking Issues

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 25,
    "filters": {
      "protocolCategory": [{"value": "Liquid Staking"}],
      "impact": ["HIGH"]
    }
  }'
```

## Security Considerations by Feature

### Reward Distribution
```solidity
// VULNERABLE - Rounding errors accumulate
function calculateReward(address user) public view returns (uint256) {
    return stakes[user] * rewardRate / totalStaked;  // Can be 0 due to rounding
}

// SECURE - MasterChef-style with accumulated rewards per share
struct Pool {
    uint256 accRewardPerShare;
    uint256 lastRewardTime;
}

function pendingReward(address user) public view returns (uint256) {
    uint256 accRewardPerShare = pool.accRewardPerShare;
    if (block.timestamp > pool.lastRewardTime && totalStaked > 0) {
        uint256 reward = (block.timestamp - pool.lastRewardTime) * rewardRate;
        accRewardPerShare += reward * 1e12 / totalStaked;
    }
    return stakes[user] * accRewardPerShare / 1e12 - rewardDebt[user];
}
```

### Stake/Unstake Logic
```solidity
// VULNERABLE - Reentrancy possible
function unstake(uint256 amount) external {
    require(stakes[msg.sender] >= amount, "Insufficient");
    
    // Send rewards first (external call)
    uint256 reward = pendingReward(msg.sender);
    rewardToken.transfer(msg.sender, reward);  // Can re-enter here
    
    // Then update state
    stakes[msg.sender] -= amount;
    stakingToken.transfer(msg.sender, amount);
}

// SECURE - CEI pattern with reentrancy guard
function unstake(uint256 amount) external nonReentrant {
    require(stakes[msg.sender] >= amount, "Insufficient");
    
    // Calculate and store
    uint256 reward = pendingReward(msg.sender);
    
    // Update state first
    stakes[msg.sender] -= amount;
    totalStaked -= amount;
    rewardDebt[msg.sender] = stakes[msg.sender] * accRewardPerShare / 1e12;
    
    // Then external calls
    stakingToken.transfer(msg.sender, amount);
    if (reward > 0) {
        rewardToken.transfer(msg.sender, reward);
    }
}
```

### Lock Period Enforcement
```solidity
// VULNERABLE - Can bypass lock
function unstake(uint256 amount) external {
    require(stakes[msg.sender] >= amount);
    stakes[msg.sender] -= amount;
    // No lock period check
}

// SECURE - Enforce lock period
struct Stake {
    uint256 amount;
    uint256 lockEnd;
}

function unstake(uint256 amount) external {
    require(stakes[msg.sender].amount >= amount, "Insufficient");
    require(block.timestamp >= stakes[msg.sender].lockEnd, "Still locked");
    
    stakes[msg.sender].amount -= amount;
    stakingToken.transfer(msg.sender, amount);
}
```

### Emergency Withdrawal
```solidity
// SECURE - Allow exit without rewards in emergency
function emergencyWithdraw() external nonReentrant {
    uint256 amount = stakes[msg.sender];
    stakes[msg.sender] = 0;
    rewardDebt[msg.sender] = 0;
    
    stakingToken.transfer(msg.sender, amount);
    emit EmergencyWithdraw(msg.sender, amount);
}
```

## Common Vulnerable Patterns

### 1. First Staker Attack
```solidity
// VULNERABLE - First staker gets all early rewards
// If Alice stakes 1 wei when reward pool has 1000 tokens:
// She gets 1000 tokens for 1 wei stake

// SECURE - Minimum stake requirement
uint256 public constant MIN_STAKE = 1e15;

function stake(uint256 amount) external {
    require(amount >= MIN_STAKE, "Below minimum");
    // ...
}
```

### 2. Reward Duration Manipulation
```solidity
// VULNERABLE - Can extend reward period with small additions
function notifyRewardAmount(uint256 reward) external {
    if (block.timestamp >= periodFinish) {
        rewardRate = reward / DURATION;
    } else {
        uint256 remaining = periodFinish - block.timestamp;
        uint256 leftover = remaining * rewardRate;
        rewardRate = (reward + leftover) / DURATION;
    }
    // Attacker adds 1 wei repeatedly to keep diluting
}

// SECURE - Only owner can notify, minimum amount
function notifyRewardAmount(uint256 reward) external onlyOwner {
    require(reward >= MIN_REWARD, "Too small");
    // ...
}
```

### 3. Share Price Manipulation
```solidity
// In liquid staking:
// VULNERABLE - Share price based on contract balance
function getSharePrice() public view returns (uint256) {
    return address(this).balance / totalShares;  // Donatable
}

// SECURE - Track deposits internally
function getSharePrice() public view returns (uint256) {
    return totalDeposited / totalShares;  // Not affected by donations
}
```

## Staking Security Checklist

### Reward Mechanics
- [ ] Accumulated reward per share pattern
- [ ] Proper precision handling (1e12 or 1e18)
- [ ] Reward rate bounds
- [ ] Reward funding validation
- [ ] Update before state changes

### Stake/Unstake
- [ ] Reentrancy protection
- [ ] CEI pattern followed
- [ ] Lock period enforcement
- [ ] Minimum stake amount
- [ ] Emergency withdrawal option

### Share Calculations (Liquid Staking)
- [ ] First depositor attack prevention
- [ ] Donation attack resistance
- [ ] Proper rounding direction
- [ ] Share price bounds

### Time Handling
- [ ] Block timestamp reasonable usage
- [ ] Period boundaries handled
- [ ] No stale reward accumulation
- [ ] Proper reward end handling

### General
- [ ] Admin functions protected
- [ ] Pausability for emergencies
- [ ] Proper event emission
- [ ] Token compatibility (fee-on-transfer, rebasing)

## Test This Query

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 5,
    "filters": {
      "protocolCategory": [{"value": "Staking"}],
      "impact": ["HIGH"],
      "qualityScore": 4,
      "sortField": "Quality"
    }
  }' | jq '.findings[] | {title, firm: .firm_name}'
```

## Cross-Reference

- For reentrancy → See [../vulnerability-tags/reentrancy.md](../vulnerability-tags/reentrancy.md)
- For calculation errors → See [../vulnerability-tags/logic-error.md](../vulnerability-tags/logic-error.md)
- For first depositor attacks → See [../vulnerability-tags/griefing.md](../vulnerability-tags/griefing.md)
