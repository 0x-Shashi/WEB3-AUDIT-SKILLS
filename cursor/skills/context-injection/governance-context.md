# GOVERNANCE SECURITY CONTEXT
> Ultra-compressed audit context. ~200 lines = 80% coverage.

## VOTE MANIPULATION CRITICAL
1. Flash loan voting: borrow → vote → return → proposal passes | snapshot BEFORE proposal
2. Vote buying: off-chain bribes for votes → centralized outcome | commit-reveal voting
3. Last-minute vote: vote in final block → no time to respond | minimum voting window
4. Self-delegation: delegate to self for double voting → inflated power | prevent self-delegate

## PROPOSAL VULNERABILITIES
1. No proposal threshold: anyone can create → spam proposals | require minimum stake
2. Malicious calldata: proposal calls `selfdestruct` or drains treasury | review calldata carefully
3. Proposal overwrite: new proposal replaces old with same ID → confusion | unique sequential IDs
4. Empty proposal: proposal with no actions → gas waste or confusion | require actions > 0

## QUORUM ISSUES
1. Low quorum: 1% quorum → attacker passes alone | reasonable quorum (5-20%)
2. Quorum bypass: abstain counts toward quorum → easier to pass | only yes+no for quorum
3. Dynamic quorum: quorum changes during vote → manipulation | lock quorum at proposal creation
4. Quorum snipe: meet quorum in last block → no response time | early quorum locking

## TIMELOCK ATTACKS
1. No timelock: proposals execute immediately → no escape window | 24-48h minimum timelock
2. Timelock bypass: emergency function without delay → admin backdoor | limit emergency powers
3. Queue manipulation: cancel queued tx, requeue different → bait and switch | immutable queue
4. Eta manipulation: execute before eta → premature execution | strict eta check

## DELEGATION RISKS
1. Circular delegation: A→B→C→A → infinite or stuck votes | max delegation depth
2. Delegation sniping: delegate just before snapshot → concentrated power | snapshot before announce
3. Stale delegation: user transfers tokens, delegation remains → wrong vote power | auto-clear on transfer
4. Hidden delegation: delegatee votes without delegator knowledge → vote surprise | event transparency

## EXECUTION VULNERABILITIES
1. Reentrancy in execute: malicious proposal reenters → double execute | nonReentrant
2. Failed execution: one action fails, all revert → stuck proposal | allow partial success option
3. Value extraction: proposal sends ETH to attacker → treasury drain | cap ETH in single proposal
4. External call failure: proposal calls external contract that reverts → stuck | try/catch wrapper

## VOTE COUNTING
1. Overflow: total votes overflow → wrong winner | use SafeMath or 0.8+
2. Snapshot too old: use token balance from months ago → doesn't reflect current holders | recent snapshot
3. Vote after snapshot: transfer tokens, vote with new balance → double voting | strict snapshot
4. Abstain power: abstain treated as against → unfair | neutral abstain

## CANCELLATION
1. Anyone can cancel: attacker cancels valid proposals → DoS | only proposer or guardian
2. No cancel after vote: can't stop malicious proposal discovered late | guardian emergency cancel
3. Cancel griefing: cancel then repropose same → delay tactics | cooldown for same proposal

## CRITICAL CODE PATTERNS

### Bad Vote Counting (Flash Loan)
```solidity
// ❌ VULNERABLE - Can flash loan tokens to vote
function vote(uint256 proposalId, bool support) external {
    uint256 votes = token.balanceOf(msg.sender);  // Current balance
    proposals[proposalId].votes += votes;
}

// ✅ SAFE - Snapshot at proposal creation
function vote(uint256 proposalId, bool support) external {
    uint256 votes = token.getPastVotes(msg.sender, proposals[proposalId].snapshotBlock);
    proposals[proposalId].votes += votes;
}
```

### Bad Timelock (Bypass)
```solidity
// ❌ VULNERABLE - Emergency can do anything instantly
function emergencyExecute(bytes calldata data) external onlyEmergency {
    (bool success,) = target.call(data);  // No timelock!
}

// ✅ SAFE - Emergency is limited
function emergencyPause() external onlyEmergency {
    paused = true;  // Can only pause, not arbitrary execution
}
```

### Bad Proposal Execution
```solidity
// ❌ VULNERABLE - Reentrancy possible
function execute(uint256 proposalId) external {
    Proposal storage prop = proposals[proposalId];
    require(prop.executed == false);
    for (uint i = 0; i < prop.targets.length; i++) {
        (bool success,) = prop.targets[i].call(prop.calldatas[i]);
        require(success);
    }
    prop.executed = true;  // Set after calls
}

// ✅ SAFE
function execute(uint256 proposalId) external nonReentrant {
    Proposal storage prop = proposals[proposalId];
    require(!prop.executed);
    prop.executed = true;  // Set before calls (CEI)
    for (uint i = 0; i < prop.targets.length; i++) {
        (bool success,) = prop.targets[i].call(prop.calldatas[i]);
        require(success);
    }
}
```

### Bad Delegation
```solidity
// ❌ VULNERABLE - Circular delegation possible
function delegate(address to) external {
    delegates[msg.sender] = to;  // Can set to anyone
}

// ✅ SAFE - Prevent circular
function delegate(address to) external {
    require(to != msg.sender, "Self-delegation");
    require(delegates[to] == address(0) || delegates[to] != msg.sender, "Circular");
    delegates[msg.sender] = to;
}
```

## CHECKLIST (Quick Scan)
- [ ] Voting: snapshot before proposal, flash loan protection
- [ ] Proposal: threshold required, calldata validated
- [ ] Quorum: reasonable level, abstain handling
- [ ] Timelock: 24h+ delay, limited emergency bypass
- [ ] Delegation: no circular, depth limit
- [ ] Execution: reentrancy guard, CEI pattern
- [ ] Cancellation: proper access control
- [ ] Vote counting: overflow protection, snapshot enforcement

## GOVERNANCE TOKEN SPECIFIC
1. ERC20Votes: use `getPastVotes()` not `balanceOf()` | snapshot-based voting
2. Checkpoint gas: many delegations → expensive checkpoint | lazy checkpointing
3. Supply changes: mint during voting → dilute/inflate votes | lock supply during vote
4. Wrapped tokens: wToken vote power vs underlying | clear documentation

## COMMON FINDINGS BY SEVERITY
**Critical**: Flash loan voting, timelock bypass, proposal reentrancy
**High**: Low quorum, circular delegation, malicious calldata
**Medium**: Vote sniping, cancel griefing, stale delegation
**Low**: Abstain counting, gas optimization, event emission
