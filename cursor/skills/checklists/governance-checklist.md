# Governance Protocol Audit Checklist

## 1. Voting Power
- [ ] **CRITICAL** Flash loan voting: snapshot-based voting power (not live balance)
- [ ] **CRITICAL** Vote weight correctly calculated from token balance/delegation
- [ ] **HIGH** Delegation: delegated votes correctly tracked and untracked
- [ ] **HIGH** Double voting: same tokens can't vote twice (direct + delegated)
- [ ] **HIGH** Checkpoint system: historical balances queryable correctly
- [ ] **MEDIUM** Token transfers after snapshot: don't affect existing votes
- [ ] **MEDIUM** Self-delegation: consistent behavior
- [ ] **LOW** Voting power display: matches on-chain calculation

## 2. Proposal Lifecycle
- [ ] **CRITICAL** Proposal threshold: minimum tokens needed to create proposal
- [ ] **CRITICAL** Quorum: sufficient participation required for valid outcome
- [ ] **HIGH** Voting period: long enough for community review (3-7 days)
- [ ] **HIGH** Proposal delay: time between creation and voting start
- [ ] **HIGH** Timelock: delay between proposal passing and execution
- [ ] **MEDIUM** Proposal cancellation: only proposer or authorized canceller
- [ ] **MEDIUM** Maximum active proposals: prevents spam
- [ ] **LOW** Proposal description: stored on-chain or indexed

## 3. Execution Security
- [ ] **CRITICAL** Timelock: executed calls match proposed calls exactly
- [ ] **CRITICAL** Proposal can't be executed twice (replay)
- [ ] **CRITICAL** Timelock eta: execution only after delay expires
- [ ] **HIGH** Batch execution: all-or-nothing (atomic)
- [ ] **HIGH** ETH value forwarding: correct amounts in batch calls
- [ ] **HIGH** Target contract validation: no calls to governance itself (recursion)
- [ ] **MEDIUM** Execution window: proposal expires if not executed in time
- [ ] **MEDIUM** Guardian veto: emergency veto power exists
- [ ] **LOW** Gas estimation: proposal execution has sufficient gas

## 4. Timelock Security
- [ ] **CRITICAL** Admin of timelock is the governance contract (not EOA)
- [ ] **HIGH** Minimum delay: can't be set to zero
- [ ] **HIGH** Maximum delay: reasonable upper bound
- [ ] **HIGH** Pending transactions: visible and queryable
- [ ] **MEDIUM** Grace period: failed executions can be retried
- [ ] **MEDIUM** Emergency proposals: shorter delay with higher threshold
- [ ] **LOW** Timelock admin transfer: two-step process

## 5. Anti-Manipulation
- [ ] **CRITICAL** Governance takeover: minimum quorum prevents whale control
- [ ] **HIGH** Bribery resistance: off-chain vote buying considered
- [ ] **HIGH** Dark DAOs: contracts can't vote programmatically (or detected)
- [ ] **HIGH** Vote buying via flash loans: snapshot prevents
- [ ] **MEDIUM** Voting incentives: don't create perverse incentives
- [ ] **MEDIUM** Token concentration: large holder can't single-handedly pass
- [ ] **LOW** Social engineering: proposal descriptions can be misleading

## 6. Parameter Changes
- [ ] **HIGH** Parameter bounds: governance can't set extreme values
- [ ] **HIGH** Dependent parameters: changing one doesn't break invariants
- [ ] **MEDIUM** Parameter change communication: sufficient notice period
- [ ] **MEDIUM** Rollback mechanism: revert parameter changes if needed
- [ ] **LOW** Parameter history: all changes tracked on-chain

## 7. Token and Delegation
- [ ] **HIGH** Governance token: non-transferable during active vote (or snapshot-based)
- [ ] **HIGH** Delegation: can delegate to another address
- [ ] **HIGH** Undelegation: immediate or delayed effect
- [ ] **MEDIUM** Multiple delegation: partial delegation supported (if claimed)
- [ ] **MEDIUM** Delegation chain: A delegates to B delegates to C (depth limit?)
- [ ] **LOW** Delegation events: properly emitted for indexing

## 8. Multi-chain Governance
- [ ] **HIGH** Cross-chain proposal execution: message verified
- [ ] **HIGH** Voting on L1, execution on L2 (or vice versa): timing aligned
- [ ] **MEDIUM** Different finality times across chains handled
- [ ] **MEDIUM** Bridge failure: governance not permanently blocked
- [ ] **LOW** Chain-specific parameters: different chains may need different values
