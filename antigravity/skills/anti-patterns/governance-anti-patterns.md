---
id: GOVERNANCE-ANTI-PATTERNS
title: Governance Anti-Patterns
category: anti-pattern
tags: [governance, timelock, voting, dao]
severity_range: High-Critical
real_exploits: $500M+
related_skills:
  - patterns/governance-patterns.md
  - attack-trees/governance-attack-tree.md
  - anti-patterns/flash-loan-anti-patterns.md
---

# Governance Anti-Patterns

Common mistakes in DAO governance that lead to exploits. Total losses from governance attacks exceed $500M+.

---

## Anti-Pattern 1: No Timelock on Critical Changes

### Description
Critical parameter changes or upgrades execute immediately after passing vote, giving users no time to exit before malicious changes take effect.

### Vulnerable Code
```solidity
// VULNERABLE
function execute(uint256 proposalId) external {
    require(proposals[proposalId].forVotes > quorum, "Not passed");
    require(!proposals[proposalId].executed, "Already executed");
    
    // Execute immediately! No delay.
    proposals[proposalId].executed = true;
    (bool success, ) = proposals[proposalId].target.call(proposals[proposalId].data);
    require(success, "Execution failed");
}

// ATTACK:
// 1. Accumulate 51% of voting power
// 2. Propose malicious upgrade (drain funds)
// 3. Vote passes
// 4. Execute immediately
// 5. Users have no time to exit
```

### Why It's Vulnerable
- No grace period for users to react
- Malicious proposals execute instantly
- Users cannot exit before harm
- Proposal can drain all funds immediately

### Secure Pattern
```solidity
// SECURE - Timelock enforced
uint256 constant TIMELOCK_DELAY = 2 days;

struct Proposal {
    // ... proposal details
    uint256 eta;  // Earliest time for execution
    bool queued;
    bool executed;
}

function queue(uint256 proposalId) external {
    require(proposals[proposalId].forVotes > quorum, "Not passed");
    require(!proposals[proposalId].queued, "Already queued");
    
    proposals[proposalId].queued = true;
    proposals[proposalId].eta = block.timestamp + TIMELOCK_DELAY;
    
    emit ProposalQueued(proposalId, proposals[proposalId].eta);
}

function execute(uint256 proposalId) external {
    Proposal storage proposal = proposals[proposalId];
    require(proposal.queued, "Not queued");
    require(!proposal.executed, "Already executed");
    require(block.timestamp >= proposal.eta, "Timelock not expired");
    require(block.timestamp <= proposal.eta + GRACE_PERIOD, "Stale proposal");
    
    proposal.executed = true;
    (bool success, ) = proposal.target.call(proposal.data);
    require(success, "Execution failed");
}
```

### Detection Checklist
- [ ] Timelock enforced (minimum 24-48 hours)
- [ ] Critical functions require queuing
- [ ] Grace period for stale proposals
- [ ] Timelock cannot be bypassed

### Real-World Impact
- **Tornado Cash (2023):** Malicious proposal with hidden code executed immediately
- **Multiple DAOs:** Governance attacks due to no timelock
- **Severity:** Critical (protocol takeover)

---

## Anti-Pattern 2: Flash Loan Voting

### Description
Governance tokens can be flash-borrowed to vote, allowing attackers to pass proposals without long-term stake.

### Vulnerable Code
```solidity
// VULNERABLE - Current balance used for voting
function vote(uint256 proposalId, bool support) external {
    uint256 votes = governanceToken.balanceOf(msg.sender);  // Spot balance!
    require(votes > 0, "No voting power");
    
    proposals[proposalId].votes[support] += votes;
}

// ATTACK:
// 1. Flash loan 51% of governance tokens
// 2. Vote on malicious proposal
// 3. Proposal passes
// 4. Repay flash loan
// 5. Execute after timelock (if any)
```

### Why It's Vulnerable
- Voting power based on spot balance
- Flash loan provides instant voting power
- No stake duration requirement
- Attacker doesn't hold long-term risk

### Secure Pattern
```solidity
// SECURE - Snapshot-based voting with delegation
uint256 public proposalCount;
mapping(uint256 => uint256) public proposalSnapshots;

function propose(...) external returns (uint256 proposalId) {
    proposalId = proposalCount++;
    proposalSnapshots[proposalId] = block.number - 1;  // Snapshot 1 block ago
    // ... proposal details
}

function vote(uint256 proposalId, bool support) external {
    uint256 snapshotBlock = proposalSnapshots[proposalId];
    require(block.number > snapshotBlock, "Snapshot not taken");
    
    // Vote with balance at historical snapshot
    uint256 votes = governanceToken.balanceOfAt(msg.sender, snapshotBlock);
    require(votes > 0, "No voting power at snapshot");
    
    proposals[proposalId].votes[support] += votes;
}
```

### Detection Checklist
- [ ] Voting uses historical snapshot (not current balance)
- [ ] Snapshot taken before proposal created
- [ ] Delegation recorded at snapshot block
- [ ] Cannot flash loan vote

### Real-World Impact
- **Beanstalk (2022):** $182M via flash loan governance attack
- **Build Finance (2021):** Flash loan vote passed malicious proposal
- **Severity:** Critical (protocol takeover)

---

## Anti-Pattern 3: Low Quorum / Participation Requirement

### Description
Proposals pass with very low participation, allowing small holders or attackers to control governance during low activity.

### Vulnerable Code
```solidity
// VULNERABLE - Only 1% quorum required
uint256 constant QUORUM = 1e16;  // 1% of total supply

function execute(uint256 proposalId) external {
    uint256 totalVotes = proposals[proposalId].forVotes + proposals[proposalId].againstVotes;
    uint256 totalSupply = governanceToken.totalSupply();
    
    require(totalVotes * 1e18 / totalSupply >= QUORUM, "Quorum not met");
    require(proposals[proposalId].forVotes > proposals[proposalId].againstVotes, "Not passed");
    
    // Execute proposal
}

// ATTACK:
// 1. Wait for governance inactivity
// 2. Buy 1.1% of tokens (cheap during bear market)
// 3. Propose malicious change
// 4. Vote with 1.1% (meets quorum, no opposition)
// 5. Execute
```

### Why It's Vulnerable
- Low quorum allows minority control
- Governance activity fluctuates
- Cheap to accumulate small percentage
- No minimum "FOR" vote requirement

### Secure Pattern
```solidity
// SECURE - Reasonable quorum + approval threshold
uint256 constant QUORUM = 10e16;  // 10% of total supply
uint256 constant APPROVAL_THRESHOLD = 60e16;  // 60% approval required

function execute(uint256 proposalId) external {
    Proposal storage proposal = proposals[proposalId];
    uint256 totalVotes = proposal.forVotes + proposal.againstVotes;
    uint256 totalSupply = governanceToken.totalSupply();
    
    // Require 10% participation
    require(totalVotes * 1e18 / totalSupply >= QUORUM, "Quorum not met");
    
    // Require 60% approval of votes cast
    require(
        proposal.forVotes * 1e18 / totalVotes >= APPROVAL_THRESHOLD,
        "Insufficient approval"
    );
    
    // Execute proposal
}
```

### Detection Checklist
- [ ] Quorum reasonable (5-15% of supply)
- [ ] Approval threshold (>50% of votes cast)
- [ ] Both participation AND approval required
- [ ] Dynamic quorum adjustment considered

### Real-World Impact
- **Multiple DAOs:** Governance attacks during low participation
- **Severity:** High (minority control)

---

## Anti-Pattern 4: Proposal Spam / DoS

### Description
Anyone can create unlimited proposals, spamming governance and preventing legitimate proposals from being reviewed.

### Vulnerable Code
```solidity
// VULNERABLE - No cost to propose
function propose(
    address target,
    bytes calldata data,
    string calldata description
) external returns (uint256 proposalId) {
    // Anyone can propose for free!
    proposalId = proposalCount++;
    proposals[proposalId] = Proposal({
        proposer: msg.sender,
        target: target,
        data: data,
        description: description,
        forVotes: 0,
        againstVotes: 0
    });
}

// ATTACK:
// 1. Create 1000 spam proposals
// 2. Legitimate proposals buried
// 3. Governance participants overwhelmed
// 4. Real proposals don't get attention
```

### Why It's Vulnerable
- Free to create proposals
- No rate limiting
- Governance UI overwhelmed
- Important proposals hidden in spam

### Secure Pattern
```solidity
// SECURE - Proposal threshold + rate limiting
uint256 constant PROPOSAL_THRESHOLD = 100_000e18;  // 100k tokens required
mapping(address => uint256) public lastProposalBlock;
uint256 constant PROPOSAL_COOLDOWN = 6000;  // ~1 day

function propose(
    address target,
    bytes calldata data,
    string calldata description
) external returns (uint256 proposalId) {
    // Require minimum token holding
    require(
        governanceToken.balanceOf(msg.sender) >= PROPOSAL_THRESHOLD,
        "Insufficient tokens to propose"
    );
    
    // Rate limit proposals
    require(
        block.number >= lastProposalBlock[msg.sender] + PROPOSAL_COOLDOWN,
        "Proposal cooldown active"
    );
    
    proposalId = proposalCount++;
    proposals[proposalId] = Proposal({
        proposer: msg.sender,
        target: target,
        data: data,
        description: description,
        forVotes: 0,
        againstVotes: 0
    });
    
    lastProposalBlock[msg.sender] = block.number;
}
```

### Detection Checklist
- [ ] Proposal threshold (e.g., 0.1% of supply)
- [ ] Cooldown period between proposals
- [ ] Proposal cancellation by proposer/admin
- [ ] Active proposal limit per address

### Real-World Impact
- **Multiple DAOs:** Spam proposals disrupt governance
- **Severity:** Medium (DoS, not theft)

---

## Anti-Pattern 5: Hidden Malicious Code in Proposals

### Description
Proposal description doesn't match actual code to be executed, hiding malicious actions.

### Vulnerable Code
```solidity
// VULNERABLE - No on-chain verification of description
function propose(
    address target,
    bytes calldata data,
    string calldata description  // Off-chain, can be misleading!
) external returns (uint256 proposalId) {
    proposalId = proposalCount++;
    proposals[proposalId] = Proposal({
        target: target,
        data: data,  // Actual code
        description: description  // What voters see
    });
}

// ATTACK:
// Description: "Increase rewards by 10%"
// Actual code: transferOwnership(attacker)
// Voters approve based on description
```

### Why It's Vulnerable
- Description is off-chain text
- Voters don't verify actual bytecode
- Misleading descriptions pass
- Malicious code hidden

### Secure Pattern
```solidity
// SECURE - Proposal simulation + UI verification
function propose(
    address[] calldata targets,
    uint256[] calldata values,
    bytes[] calldata calldatas,
    string calldata description
) external returns (uint256 proposalId) {
    // Store complete proposal details
    proposalId = proposalCount++;
    proposals[proposalId] = Proposal({
        targets: targets,
        values: values,
        calldatas: calldatas,
        description: description
    });
    
    // Emit event with ALL details for transparency
    emit ProposalCreated(
        proposalId,
        msg.sender,
        targets,
        values,
        calldatas,
        description
    );
}

// Frontend must:
// 1. Decode calldata to human-readable
// 2. Simulate execution (e.g., Tenderly)
// 3. Show state changes clearly
// 4. Warn about sensitive functions
```

### Detection Checklist
- [ ] Proposal simulation before voting
- [ ] Calldata decoded and displayed
- [ ] Sensitive functions flagged (transferOwnership, upgrade, etc.)
- [ ] Community review process

### Real-World Impact
- **Tornado Cash (2023):** Hidden malicious code in governance proposal
- **Severity:** Critical (complete compromise)

---

## Anti-Pattern 6: Vote Buying Not Addressed

### Description
Nothing prevents voters from selling their votes off-chain, allowing bribery and vote manipulation.

### Vulnerable Code
```solidity
// VULNERABLE - Simple voting, no protection
function vote(uint256 proposalId, bool support) external {
    uint256 votes = governanceToken.balanceOfAt(msg.sender, snapshotBlock);
    proposals[proposalId].votes[support] += votes;
}

// ATTACK:
// 1. Attacker offers $X to voters off-chain
// 2. Voters vote as attacker wants
// 3. Attacker verifies votes on-chain
// 4. Pays voters off-chain
// 5. Malicious proposal passes
```

### Why It's Vulnerable
- Votes are public and verifiable
- No mechanism to prevent bribes
- Vote buying is profitable
- Delegators may not care about protocol

### Secure Pattern
```solidity
// PARTIAL MITIGATION - Secret ballot / commit-reveal
mapping(bytes32 => bool) public commitments;

function commitVote(uint256 proposalId, bytes32 commitment) external {
    // Hash of (proposalId, support, salt, voter)
    commitments[commitment] = true;
    emit VoteCommitted(proposalId, msg.sender, commitment);
}

function revealVote(
    uint256 proposalId,
    bool support,
    bytes32 salt
) external {
    bytes32 commitment = keccak256(abi.encode(proposalId, support, salt, msg.sender));
    require(commitments[commitment], "No matching commitment");
    
    uint256 votes = governanceToken.balanceOfAt(msg.sender, snapshotBlock);
    proposals[proposalId].votes[support] += votes;
    
    delete commitments[commitment];
}

// NOTE: This doesn't fully prevent vote buying,
// but makes it harder to verify before payment
```

### Detection Checklist
- [ ] Commit-reveal voting (if feasible)
- [ ] Reputation/sybil resistance
- [ ] Delegate accountability mechanisms
- [ ] Skin-in-the-game requirements

### Real-World Impact
- **Curve Wars:** Massive vote buying via Votium, Bribe.crv
- **Multiple DAOs:** Mercenary capital influences votes
- **Severity:** Medium-High (governance manipulation)

---

## Anti-Pattern 7: Arbitrary Call in Governance Execution

### Description
Governance can call any function on any contract without restrictions, enabling dangerous operations.

### Vulnerable Code
```solidity
// VULNERABLE - Unrestricted arbitrary calls
function execute(uint256 proposalId) external {
    Proposal storage proposal = proposals[proposalId];
    require(proposal.forVotes > quorum, "Not passed");
    
    // Can call ANYTHING!
    (bool success, ) = proposal.target.call(proposal.data);
    require(success, "Execution failed");
}

// ATTACK:
// 1. Propose call to governanceToken.transfer() to drain treasury
// 2. Or call to upgrade proxy to malicious implementation
// 3. Or call to external protocol to drain funds
// 4. Pass via flash loan voting or low quorum
```

### Why It's Vulnerable
- No restrictions on call targets
- Can drain treasury directly
- Can upgrade to malicious contracts
- Can interact with external protocols dangerously

### Secure Pattern
```solidity
// SECURE - Whitelist + specific actions
mapping(bytes4 => bool) public allowedFunctions;

constructor() {
    // Whitelist safe functions
    allowedFunctions[0x095ea7b3] = true;  // approve()
    allowedFunctions[0xa9059cbb] = true;  // transfer() (with amount limits)
    // Do NOT whitelist: transferOwnership, upgrade, selfdestruct
}

function execute(uint256 proposalId) external {
    Proposal storage proposal = proposals[proposalId];
    require(proposal.forVotes > quorum, "Not passed");
    
    // Extract function selector
    bytes4 selector = bytes4(proposal.data[:4]);
    require(allowedFunctions[selector], "Function not whitelisted");
    
    // Additional checks based on function
    if (selector == 0xa9059cbb) {  // transfer()
        (address to, uint256 amount) = abi.decode(proposal.data[4:], (address, uint256));
        require(amount <= MAX_TRANSFER_AMOUNT, "Amount too large");
    }
    
    (bool success, ) = proposal.target.call(proposal.data);
    require(success, "Execution failed");
}
```

### Detection Checklist
- [ ] Function whitelist for governance
- [ ] Restricted target contracts
- [ ] Amount limits on transfers
- [ ] Multi-sig for sensitive operations

### Real-World Impact
- **Multiple protocols:** Governance used to drain treasury
- **Severity:** Critical (complete fund theft)

---

## Comparison Table

| Anti-Pattern | Severity | Exploitability | Fix Difficulty | Notable Exploit |
|--------------|----------|----------------|----------------|-----------------|
| No Timelock | Critical | Medium | Easy | Tornado Cash 2023 |
| Flash Loan Voting | Critical | Medium | Medium | Beanstalk ($182M) |
| Low Quorum | High | Easy | Easy | Multiple DAOs |
| Proposal Spam | Medium | Easy | Easy | N/A (DoS only) |
| Hidden Malicious Code | Critical | Hard | Medium | Tornado Cash 2023 |
| Vote Buying | High | Hard | Hard | Curve Wars (ongoing) |
| Arbitrary Call | Critical | Medium | Medium | Multiple protocols |

---

## Governance Safety Checklist

```markdown
## Governance Security Audit

### Timelock
- [ ] Timelock enforced (24-48 hours minimum)
- [ ] Applies to all critical functions (upgrade, transfer, param changes)
- [ ] Cannot be bypassed
- [ ] Grace period for stale proposals

### Voting Mechanism
- [ ] Snapshot-based voting (historical balance)
- [ ] Snapshot before proposal creation
- [ ] Flash loan voting impossible
- [ ] Delegation tracked at snapshot

### Participation
- [ ] Reasonable quorum (5-15% of supply)
- [ ] Approval threshold (>50% of votes)
- [ ] Both quorum AND approval required
- [ ] Dynamic adjustment considered

### Proposal Creation
- [ ] Proposal threshold (e.g., 0.1% of supply)
- [ ] Cooldown period between proposals
- [ ] Active proposal limit
- [ ] Proposal cancellation mechanism

### Transparency
- [ ] Proposal simulation available
- [ ] Calldata decoded and displayed
- [ ] Sensitive functions flagged
- [ ] Community review process

### Vote Integrity
- [ ] Commit-reveal or other anti-bribery (if feasible)
- [ ] Delegate accountability
- [ ] Reputation/skin-in-the-game

### Execution Safety
- [ ] Function whitelist
- [ ] Target contract restrictions
- [ ] Amount limits on transfers
- [ ] Multi-sig for ultra-sensitive ops

### Emergency
- [ ] Guardian role for emergency pause
- [ ] Veto power with timelock
- [ ] Recovery mechanism if compromised
```

---

## Testing Strategy

### Governance Attack Simulation
```solidity
function testFlashLoanGovernanceAttack() public {
    // 1. Flash loan governance tokens
    uint256 flashAmount = governanceToken.totalSupply() * 51 / 100;
    governanceToken.mint(attacker, flashAmount);
    
    // 2. Create malicious proposal
    vm.startPrank(attacker);
    uint256 proposalId = governance.propose(
        maliciousTarget,
        maliciousData,
        "Drain funds"
    );
    
    // 3. Vote with flash-borrowed tokens
    governance.vote(proposalId, true);
    vm.stopPrank();
    
    // 4. Repay flash loan
    governanceToken.burn(attacker, flashAmount);
    
    // 5. Verify attack fails
    vm.warp(block.timestamp + TIMELOCK_DELAY);
    vm.expectRevert("Snapshot-based voting prevents flash loan attack");
    governance.execute(proposalId);
}
```

---

## Mitigation Priority

### Critical (Immediate)
1. Add timelock (24-48 hours)
2. Implement snapshot-based voting
3. Whitelist governance functions

### High (Short-term)
4. Reasonable quorum (5-15%)
5. Proposal threshold and cooldown
6. Simulation/transparency tools

### Medium (Long-term)
7. Anti-bribery mechanisms
8. Multi-sig for ultra-sensitive operations
9. Comprehensive governance documentation

---

## See Also

- **Attack Trees:** [governance-attack-tree.md](../attack-trees/governance-attack-tree.md)
- **Patterns:** [governance-patterns.md](../patterns/governance-patterns.md)
- **Related:** [flash-loan-anti-patterns.md](./flash-loan-anti-patterns.md)

---

**Last Updated:** 2025  
**Version:** 1.0  
**Total Known Losses:** $500M+
