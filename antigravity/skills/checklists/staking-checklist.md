# Staking Protocol Audit Checklist

## 1. Deposit and Withdrawal
- [ ] **CRITICAL** Staking deposit correctly credits user shares/balance
- [ ] **CRITICAL** Withdrawal returns correct proportional amount
- [ ] **CRITICAL** Cannot withdraw more than staked
- [ ] **HIGH** First depositor attack: initial share inflation mitigated
- [ ] **HIGH** Minimum stake amount enforced (avoid dust positions)
- [ ] **HIGH** Fee-on-transfer tokens: actual received amount used
- [ ] **MEDIUM** Partial withdrawal supported and correct
- [ ] **MEDIUM** Emergency withdrawal (forfeiting rewards) available
- [ ] **LOW** Deposit/withdrawal events emitted

## 2. Reward Distribution
- [ ] **CRITICAL** Rewards distributed proportionally to stake
- [ ] **CRITICAL** Reward rate calculation: correct per-second/per-block accrual
- [ ] **CRITICAL** No reward manipulation: can't inflate rewards by flash staking
- [ ] **HIGH** Reward token separate from staked token: correct accounting
- [ ] **HIGH** Multiple reward tokens: each tracked independently
- [ ] **HIGH** Reward duration: what happens when rewards run out?
- [ ] **HIGH** New rewards added: correctly extends/updates reward rate
- [ ] **MEDIUM** Compound rewards: auto-compounding math correct
- [ ] **MEDIUM** Reward claiming: partial vs full claim behavior
- [ ] **LOW** Unclaimed rewards: not lost if contract is updated

## 3. Reward Rate and Timing
- [ ] **CRITICAL** Block.timestamp vs block.number: consistent usage
- [ ] **HIGH** Reward calculation: `rewardPerToken += (reward * duration) / totalSupply`
- [ ] **HIGH** Zero total supply period: rewards don't accumulate to nobody
- [ ] **HIGH** Reward notification: `notifyRewardAmount` timing and amount correct
- [ ] **MEDIUM** Late stakers: don't receive past rewards (accounted from join time)
- [ ] **MEDIUM** Reward precision: sufficient decimal places to avoid truncation
- [ ] **LOW** Leftover rewards: handled when period ends with remainder

## 4. Lock-up and Vesting
- [ ] **HIGH** Lock period enforced: can't withdraw before lockup expires
- [ ] **HIGH** Lock extension: existing lock doesn't reset unexpectedly
- [ ] **HIGH** Vesting schedule: linear/cliff/custom correctly implemented
- [ ] **MEDIUM** Early unstake penalty: correctly calculated and distributed
- [ ] **MEDIUM** Lock period per position (not global)
- [ ] **LOW** Lock period display: matches on-chain enforcement

## 5. Delegation
- [ ] **HIGH** Delegated staking: delegatee correctly receives rewards
- [ ] **HIGH** Undelegation period: cooldown enforced
- [ ] **HIGH** Validator set: delegation to valid validators only
- [ ] **MEDIUM** Slashing: delegators share slashing risk proportionally
- [ ] **MEDIUM** Redelegate: move stake between validators without unstaking
- [ ] **LOW** Delegation limit: maximum stake per validator

## 6. Liquid Staking (stETH, rETH pattern)
- [ ] **CRITICAL** Share exchange rate: cannot be manipulated (donation attack)
- [ ] **CRITICAL** Withdrawal queue: FIFO and fair
- [ ] **HIGH** Rebasing vs non-rebasing: accounting model consistent
- [ ] **HIGH** Oracle reporting: validator balance reported correctly
- [ ] **HIGH** Slashing: share price adjusts correctly
- [ ] **MEDIUM** Secondary market: liquid staking token pegged to underlying
- [ ] **MEDIUM** Withdrawal delays: communicated to users
- [ ] **LOW** Fee structure: management/performance fees correct

## 7. Security Mechanisms
- [ ] **HIGH** Reentrancy protection on stake/unstake/claim
- [ ] **HIGH** Pausable: emergency pause on all staking operations
- [ ] **HIGH** Access control: only authorized can add rewards, change parameters
- [ ] **MEDIUM** Timelock on parameter changes
- [ ] **MEDIUM** Maximum total stake cap (if applicable)
- [ ] **LOW** Slashing conditions documented and enforceable

## 8. Integration Risks
- [ ] **HIGH** Composability: staking receipt token usable in DeFi
- [ ] **HIGH** Yield aggregator interaction: auto-compound safe
- [ ] **MEDIUM** Governance integration: staked tokens retain voting rights
- [ ] **MEDIUM** Transfer of staked position: ownership change handled
- [ ] **LOW** Analytics: historical APR/APY trackable
