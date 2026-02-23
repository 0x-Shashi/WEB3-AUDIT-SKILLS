# Restaking & Liquid Restaking Token (LRT) Audit Checklist

## 1. Staking and Delegation
- [ ] **CRITICAL** Delegation to operator cannot cause loss of principal under normal conditions
- [ ] **CRITICAL** Stake accounting: shares track deposited amount plus/minus slashing correctly
- [ ] **CRITICAL** Operator cannot withdraw or redirect delegated stake
- [ ] **HIGH** Maximum stake per operator bounded to prevent concentration risk
- [ ] **HIGH** Delegation and undelegation use queued withdrawal with delay
- [ ] **HIGH** Operator registration validates required on-chain credentials
- [ ] **MEDIUM** Minimum delegation amount enforced to prevent dust stakes
- [ ] **MEDIUM** Delegation rewards attributed to correct delegator (not operator)

## 2. Slashing Conditions
- [ ] **CRITICAL** Slashing only triggered by verifiable on-chain proof (not admin key)
- [ ] **CRITICAL** Maximum slashing percentage bounded per AVS/service
- [ ] **CRITICAL** Slashing cannot exceed delegated stake (no negative balance)
- [ ] **HIGH** Slashing proof has validity window — cannot submit stale proofs
- [ ] **HIGH** Dispute period allows operator to contest slashing before execution
- [ ] **HIGH** Cumulative slashing across multiple AVS capped at 100% of stake
- [ ] **MEDIUM** Slashing affects delegators proportionally to their share
- [ ] **MEDIUM** Slashing events emitted with proof details for monitoring
- [ ] **LOW** Slashing parameters per AVS documented and auditable on-chain

## 3. AVS (Actively Validated Service) Integration
- [ ] **CRITICAL** AVS contract cannot unilaterally slash — must go through slashing module
- [ ] **CRITICAL** AVS registration by operator is opt-in — no forced enrollment
- [ ] **HIGH** AVS can only slash for conditions agreed upon at registration time
- [ ] **HIGH** AVS reward distribution proportional to operator's committed stake
- [ ] **HIGH** Malicious AVS cannot drain restaker funds beyond slashing bounds
- [ ] **MEDIUM** AVS deregistration has cooldown — operator cannot exit before pending slashing
- [ ] **MEDIUM** Multiple AVS: shared security model — total risk across all AVS assessed
- [ ] **LOW** AVS metadata (description, risk parameters) stored on-chain or verifiable

## 4. Withdrawal Mechanics
- [ ] **CRITICAL** Withdrawal queue delay sufficient to process pending slashing
- [ ] **CRITICAL** Queued withdrawals cannot be front-run by slashing submission
- [ ] **CRITICAL** Withdrawal amount reflects post-slashing share value
- [ ] **HIGH** Withdrawal completion requires all slashing disputes resolved
- [ ] **HIGH** Partial withdrawal supported without closing entire delegation
- [ ] **HIGH** Queue ordering fair — FIFO or proportional, no preferential treatment
- [ ] **MEDIUM** Withdrawal delay parameters bounded (min/max)
- [ ] **MEDIUM** Emergency withdrawal mechanism exists with longer delay but guaranteed execution

## 5. Liquid Restaking Token (LRT)
- [ ] **CRITICAL** LRT share price accurately reflects underlying restaked assets minus slashing
- [ ] **CRITICAL** LRT minting/redemption cannot be manipulated via donation or flash loan
- [ ] **CRITICAL** LRT total supply matches total restaked principal (accounting invariant)
- [ ] **HIGH** LRT exchange rate updates atomically with slashing events
- [ ] **HIGH** First depositor attack mitigated (virtual shares or minimum deposit)
- [ ] **HIGH** LRT redemption queue: withdrawal delay passed through correctly
- [ ] **MEDIUM** LRT composability: integrations (lending, LP) handle rebasing or exchange rate
- [ ] **MEDIUM** LRT transfer does not change underlying delegation or operator assignment
- [ ] **LOW** LRT metadata (name, symbol, decimals) consistent with underlying asset

## 6. Operator Security
- [ ] **CRITICAL** Operator keys stored securely — compromise cannot steal delegated stake
- [ ] **CRITICAL** Operator cannot change AVS commitments while active delegations exist
- [ ] **HIGH** Operator ejection removes from all AVS and triggers withdrawal queue
- [ ] **HIGH** Operator performance: uptime and liveness requirements enforced
- [ ] **HIGH** Operator reward commission rate bounded and transparent
- [ ] **MEDIUM** Operator key rotation supported without disrupting delegations
- [ ] **MEDIUM** Minimum operator self-delegation ensures skin in the game
- [ ] **LOW** Operator reputation/history queryable on-chain

## 7. Reward Distribution
- [ ] **CRITICAL** Rewards accurately attributed per delegator based on share and duration
- [ ] **CRITICAL** Reward tokens cannot be drained via reentrancy or claim manipulation
- [ ] **HIGH** Multiple reward token types (AVS tokens, points) tracked independently
- [ ] **HIGH** Reward claim does not affect staked principal or delegation
- [ ] **HIGH** Unclaimed rewards do not expire or get redistributed unfairly
- [ ] **MEDIUM** Reward rate changes applied prospectively, not retroactively
- [ ] **MEDIUM** Compounding rewards (auto-restake) calculated correctly
- [ ] **LOW** Reward distribution events emitted per epoch for transparency

## 8. Points and Off-Chain Incentives
- [ ] **HIGH** Points accrual logic on-chain matches documented formula
- [ ] **HIGH** Points sybil resistance — multiple wallets don't get outsized allocation
- [ ] **MEDIUM** Points snapshot timing known — prevents JIT staking before snapshot
- [ ] **MEDIUM** Points transferability (if any) doesn't create secondary market manipulation
- [ ] **LOW** Points-to-token conversion rate (if applicable) documented and bounded
- [ ] **LOW** Points accrual paused during protocol emergency or migration

## 9. Protocol Safety
- [ ] **CRITICAL** Total restaked TVL caps enforced per asset type
- [ ] **HIGH** Emergency pause: halts new deposits and delegations while allowing withdrawals
- [ ] **HIGH** Upgrade path: restaking contract upgradeable with timelock and governance
- [ ] **HIGH** Migration: stake can be moved to new version without full withdrawal cycle
- [ ] **MEDIUM** Circuit breaker: automatic pause if slashing exceeds threshold in epoch
- [ ] **MEDIUM** Governance delay on parameter changes (slashing bounds, withdrawal delay)
- [ ] **LOW** Protocol fee on rewards bounded and transparent
