---
id: CHECKLIST-GOVERNANCE
title: Governance Protocol Audit Checklist
category: checklists
difficulty: intermediate
tags: [governance, dao, voting, timelock, delegation, proposal]
last_updated: 2026-01-31
---

# Governance Protocol Audit Checklist

Quick-reference checklist for auditing DAO governance, voting systems, and timelocks.

---

## 🔴 Critical Checks

### Flash Loan Attacks
```
[ ] Can voting power be flash loaned?
[ ] Is voting power snapshotted at proposal creation?
[ ] Can tokens be borrowed just for voting?
[ ] Is there a voting delay after proposal creation?
[ ] Can delegate voting be flash manipulated?
```

### Proposal Security
```
[ ] Can malicious proposals be submitted?
[ ] Is proposal threshold sufficient?
[ ] Can proposals call arbitrary contracts?
[ ] Are dangerous function selectors blocked?
[ ] Can proposal description be misleading?
```

### Execution Safety
```
[ ] Is timelock delay sufficient (48h+ recommended)?
[ ] Can timelock be bypassed?
[ ] Can queued proposals be front-run?
[ ] Are executed proposals marked correctly?
[ ] Can same proposal be executed twice?
```

---

## 🟠 High Priority Checks

### Voting Mechanics
```
[ ] Is quorum requirement appropriate?
[ ] Can quorum be manipulated?
[ ] Is voting period sufficient for participation?
[ ] Can votes be changed after casting?
[ ] Are abstain votes counted correctly?
```

### Delegation
```
[ ] Can delegated voting power be double-counted?
[ ] Is delegation snapshot taken correctly?
[ ] Can delegation be changed during voting?
[ ] Self-delegation handled properly?
[ ] Delegation chain length limited?
```

### Guardian/Veto Powers
```
[ ] Who can veto proposals?
[ ] Can guardian power be abused?
[ ] Is guardian role revocable?
[ ] Can emergency actions bypass governance?
[ ] Are guardian actions logged?
```

---

## 🟡 Medium Priority Checks

### Timelock
```
[ ] Is delay configurable?
[ ] Minimum/maximum delay enforced?
[ ] Can admin set delay to 0?
[ ] Grace period for execution?
[ ] Can pending actions be cancelled?
```

### Access Control
```
[ ] Who can cancel proposals?
[ ] Who can update governance parameters?
[ ] Who can upgrade contracts?
[ ] Are critical roles separated?
[ ] Multi-sig requirements for admin actions?
```

### Token-Based Voting
```
[ ] Checkpointing implemented correctly?
[ ] Historical voting power queryable?
[ ] Voting power at block N accurate?
[ ] Transfers affect current vote?
```

---

## 🟢 Standard Checks

### Proposal Lifecycle
```
[ ] Pending → Active → Succeeded/Defeated → Queued → Executed?
[ ] State transitions correct?
[ ] Can proposals get stuck?
[ ] Expired proposals handled?
[ ] Events emitted for all state changes?
```

### Threshold & Quorum
```
[ ] Proposal threshold: reasonable % of supply?
[ ] Quorum: reasonable % of supply?
[ ] Can thresholds be changed?
[ ] Are threshold changes timelocked?
```

### Off-Chain Voting Integration
```
[ ] Snapshot voting result verified on-chain?
[ ] Off-chain signatures validated?
[ ] Can off-chain votes be replayed?
[ ] Merkle proofs for vote aggregation correct?
```

---

## Common Vulnerability Patterns

### 1. Flash Loan Governance Attack
```solidity
// VULNERABLE: Current balance used for voting
function castVote(uint256 proposalId, bool support) {
    uint256 votes = token.balanceOf(msg.sender);  // Can be flash loaned!
    _vote(proposalId, support, votes);
}

// SECURE: Use snapshot at proposal creation
function castVote(uint256 proposalId, bool support) {
    uint256 snapshotBlock = proposals[proposalId].snapshotBlock;
    uint256 votes = token.getPastVotes(msg.sender, snapshotBlock);
    _vote(proposalId, support, votes);
}
```

### 2. Proposal Front-Running
```solidity
// VULNERABLE: Can see proposal and accumulate tokens before snapshot
function propose(...) {
    uint256 snapshotBlock = block.number;  // Snapshot is now!
    // Attacker already bought tokens in previous block
}

// SECURE: Snapshot in the past
function propose(...) {
    uint256 snapshotBlock = block.number - 1;  // Past block
    // Attacker couldn't know proposal was coming
}
```

### 3. Timelock Bypass
```solidity
// VULNERABLE: Emergency function bypasses timelock
function emergencyExecute(bytes calldata data) external onlyAdmin {
    (bool success,) = target.call(data);  // No timelock!
}

// SECURE: Even emergency has minimum delay
function emergencyExecute(bytes calldata data) external onlyAdmin {
    require(
        block.timestamp >= emergencyRequestTime + MIN_EMERGENCY_DELAY,
        "Too soon"
    );
}
```

### 4. Double Voting via Delegation
```solidity
// VULNERABLE: Can delegate and vote separately
function vote(uint256 proposalId) {
    votes[proposalId][msg.sender] = token.balanceOf(msg.sender);
}

function voteAsDelegate(uint256 proposalId, address delegator) {
    votes[proposalId][delegator] = token.balanceOf(delegator);
    // Same tokens counted twice!
}

// SECURE: Use getPastVotes which accounts for delegation
function vote(uint256 proposalId) {
    uint256 power = token.getPastVotes(msg.sender, snapshotBlock);
    // Includes delegated power, prevents double counting
}
```

---

## Governance Type-Specific Checks

### OpenZeppelin Governor
```
[ ] Correct Governor modules used?
[ ] Counting mode appropriate (Simple, Bravo)?
[ ] Quorum calculation correct?
[ ] Timelock controller properly connected?
```

### Compound Governor (Bravo)
```
[ ] Proposal actions array bounded?
[ ] Max operations per proposal?
[ ] Voting delay and period appropriate?
[ ] Guardian role properly configured?
```

### Snapshot (Off-Chain)
```
[ ] Voting strategy weights correct?
[ ] Block number for snapshot accurate?
[ ] Delegation snapshot handled?
[ ] Result verification on-chain?
```

### Optimistic Governance
```
[ ] Challenge period sufficient?
[ ] Who can challenge?
[ ] Bond required for proposals?
[ ] Bond slashing conditions clear?
```

### veToken Governance
```
[ ] Voting power decay correct?
[ ] Lock-weighted voting accurate?
[ ] Can lock be extended to gain power?
[ ] Historical voting power tracked?
```

---

## Timelock Patterns

### Standard Timelock
```
queue(target, value, data, predecessor, delay)
    → Wait for delay
    → execute(target, value, data, predecessor, salt)
```

### Critical Parameters
```
Minimum Delay: 48 hours (recommended)
Maximum Delay: 30 days (prevent locking)
Grace Period: 14 days (time to execute after ready)
```

### Roles
```
PROPOSER_ROLE: Can queue transactions
EXECUTOR_ROLE: Can execute after delay
CANCELLER_ROLE: Can cancel queued transactions
TIMELOCK_ADMIN_ROLE: Can manage roles
```

---

## Integration Points

### With Treasury
```
[ ] Governance controls treasury?
[ ] Are withdrawal limits in place?
[ ] Can treasury be drained in one proposal?
[ ] Multi-step approval for large withdrawals?
```

### With Protocol Upgrades
```
[ ] Upgrade proposals timelocked?
[ ] Can upgrades be vetoed?
[ ] Are upgrade implementations verified?
[ ] Rollback mechanism available?
```

### With Parameter Changes
```
[ ] Critical parameters timelocked?
[ ] Bounds checking on parameter changes?
[ ] Can parameters be changed to dangerous values?
[ ] Are changes gradual or instant?
```

---

## Quick Reference

### Typical Governance Parameters
```
Proposal Threshold: 0.1% - 1% of supply
Quorum: 4% - 10% of supply  
Voting Delay: 1-2 days (time before voting starts)
Voting Period: 3-7 days
Timelock Delay: 2-7 days
```

### Voting Power Calculation
```solidity
// ERC20Votes pattern
votingPower = getVotes(account) // Includes delegated votes

// veToken pattern
votingPower = lockedAmount * remainingLockTime / maxLockTime
```

### Proposal States
```
0: Pending (before voting delay)
1: Active (voting open)
2: Canceled
3: Defeated (quorum not met or majority against)
4: Succeeded (passed vote)
5: Queued (in timelock)
6: Expired (not executed in time)
7: Executed
```

---

## Red Flags 🚩

- [ ] No voting delay (flash loan risk)
- [ ] Snapshot at current block
- [ ] Timelock < 24 hours
- [ ] Quorum < 4% of supply
- [ ] No guardian/veto mechanism
- [ ] Proposals can call any function
- [ ] Delegation allows double voting
- [ ] No checkpointing for historical votes
- [ ] Single admin can bypass governance
- [ ] Emergency functions with no delay
