# Staking Protocol Audit Template

## Protocol Overview
Staking protocols allow users to lock tokens to earn rewards, secure proof-of-stake networks, or participate in protocol governance. Includes native staking, liquid staking, and yield farming.

## Architecture Checklist
- [ ] Deposit/withdrawal flow correct
- [ ] Reward calculation and distribution accurate
- [ ] Reward rate updates handle edge cases
- [ ] Lock period enforcement secure
- [ ] Delegation mechanism correct (if applicable)
- [ ] Liquid staking token (LST) exchange rate accurate
- [ ] Slashing conditions and distribution fair

## Critical Invariants
```
1. Conservation: totalStaked == sum(userStakes)
2. Reward Accuracy: userReward == integral(userStake * rewardRate, time)
3. LST Peg: LST.totalSupply * exchangeRate == underlyingStaked
4. No Front-Running: reward distribution not gameable by flash stake
5. Withdrawal: users can always withdraw after lock period
```

## Attack Vectors

### Reward Distribution
- [ ] Reward per token calculation has precision loss
- [ ] First staker gets diluted rewards (rounding)
- [ ] Reward rate change causes loss/windfall
- [ ] Zero total staked division (reward rate goes to infinity)
- [ ] Flash stake to capture rewards (deposit, claim, withdraw in same block)
- [ ] Reward token different from stake token — accounting separate?

### Deposit/Withdrawal
- [ ] Share inflation attack (ERC4626-style)
- [ ] Minimum deposit enforced
- [ ] Partial withdrawal handling
- [ ] Emergency withdrawal bypasses reward calculation
- [ ] Withdrawal queue manipulation (if queued)
- [ ] Lock period bypass via transfer of stake tokens

### Exchange Rate
- [ ] Exchange rate can be manipulated via donation
- [ ] Rounding direction favors protocol (not attacker)
- [ ] Exchange rate never decreases (except slashing)
- [ ] Virtual offset applied (prevents first depositor attack)

### Liquid Staking Specific
- [ ] LST can be redeemed 1:1 at maturity
- [ ] Oracle for LST/underlying price manipulation
- [ ] Validator selection and rotation (not concentrated)
- [ ] Slashing impact correctly distributed
- [ ] Withdrawal delay appropriate for chain

### MasterChef/Farm Patterns
- [ ] `updatePool()` called before state changes
- [ ] `pendingReward()` matches actual claimable amount
- [ ] Multiple reward tokens handled independently
- [ ] Pool weight changes don't cause reward loss
- [ ] Deposit fee calculated correctly (if any)

## Critical Functions to Review Deep
| Function | Risk | Check |
|----------|------|-------|
| `stake()` / `deposit()` | Share manipulation | Min amount, inflation |
| `withdraw()` / `unstake()` | Reward theft | Pending rewards, lock |
| `claim()` / `getReward()` | Incorrect amount | Precision, reentrancy |
| `updateRewardRate()` | Manipulation | Access control, transition |
| `slash()` | Unfair distribution | Proportional, recovery |

## Integration Risks
- Underlying protocol risk (validator slashing, protocol hack)
- LST price oracle for DeFi integrations
- Governance token inflation from rewards
- Composability with lending/DEX protocols

## Economic Considerations
- Reward sustainability (emission schedule)
- Staking APY vs inflation rate
- Validator concentration risks
- MEV from liquid staking derivatives
