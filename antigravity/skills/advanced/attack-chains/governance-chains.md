# Governance Attack Chains

## Overview

Governance controls protocol parameters, treasury, and upgrades. Attacks can:

- Drain treasury
- Change critical parameters
- Upgrade to malicious contracts
- Permanent protocol takeover

---

## Chain 1: Flash Loan + Instant Voting

**Components:**
1. Voting power = current token balance
2. No snapshot mechanism
3. Immediate proposal execution

**Attack Flow:**
```
1. Flash borrow governance tokens
2. Create malicious proposal
3. Vote with borrowed tokens
4. Execute immediately
5. Drain treasury
6. Repay flash loan
```

**Real Example:** Beanstalk ($182M)

**Vulnerable Pattern:**
```solidity
function vote(uint256 proposalId) {
    uint256 votes = token.balanceOf(msg.sender);  // Current balance!
    proposals[proposalId].forVotes += votes;
}

function execute(uint256 proposalId) {
    require(proposals[proposalId].forVotes > quorum);
    // No timelock!
    _execute(proposalId);
}
```

**Secure Pattern:**
```solidity
function propose(...) returns (uint256) {
    uint256 proposalId = nextId++;
    proposals[proposalId].snapshot = block.number;  // Snapshot!
    // ...
}

function vote(uint256 proposalId) {
    uint256 snapshot = proposals[proposalId].snapshot;
    uint256 votes = token.getPastVotes(msg.sender, snapshot);  // Historical
    // ...
}

function execute(uint256 proposalId) {
    require(block.timestamp >= proposals[proposalId].eta);  // Timelock
    // ...
}
```

---

## Chain 2: Low Quorum + Voter Apathy

**Components:**
1. Low quorum threshold
2. Low voter participation
3. Attacker accumulates enough tokens

**Attack Flow:**
```
1. Accumulate tokens over time
2. Wait for low-activity period
3. Create proposal
4. Vote with your tokens (exceeds quorum)
5. No one contests
6. Execute malicious proposal
```

**Detection:**
```solidity
uint256 public quorumThreshold = 1000;  // Is this enough?
// If total supply is 1,000,000, quorum is only 0.1%
```

**Mitigation:**
- Dynamic quorum based on participation
- Minimum quorum percentage
- Longer voting periods
- Vote delegation to active voters

---

## Chain 3: Delegation Exploit + Vote Splitting

**Components:**
1. Vote delegation system
2. Delegation can be changed mid-vote
3. Same tokens counted multiple times

**Attack Flow:**
```
1. Delegate to Address A
2. A votes
3. Re-delegate to Address B
4. B votes with same tokens
5. Tokens counted twice
```

**Vulnerable Pattern:**
```solidity
function vote(uint256 proposalId) {
    uint256 votes = getVotes(msg.sender);  // Uses current delegation
    // Delegation can change between votes!
}
```

**Secure Pattern:**
```solidity
function vote(uint256 proposalId) {
    uint256 snapshot = proposals[proposalId].snapshot;
    uint256 votes = getPastVotes(msg.sender, snapshot);
    require(!hasVoted[proposalId][msg.sender], "Already voted");
    hasVoted[proposalId][msg.sender] = true;
}
```

---

## Chain 4: Timelock Bypass + Emergency Functions

**Components:**
1. Timelock on proposals
2. Emergency function with no timelock
3. Attacker gains emergency access

**Attack Flow:**
```
1. Gain access to emergency role
2. Use emergency function to bypass timelock
3. Execute malicious changes immediately
4. Damage done before anyone can react
```

**Detection:**
```solidity
function emergencyAction(bytes memory data) onlyEmergency {
    // No timelock!
    (bool success,) = target.call(data);
}
```

**Mitigation:**
- Emergency actions also timelock-protected
- Multi-sig for emergency
- Limited scope emergency functions
- Kill switch only (no arbitrary calls)

---

## Chain 5: Proposal Griefing + DOS

**Components:**
1. Anyone can create proposals
2. Voting on proposal locks tokens
3. Spam proposals to lock tokens

**Attack Flow:**
```
1. Create many spam proposals
2. Users must vote on each to unlock tokens
3. Users give up, tokens stay locked
4. Reduced voting participation
5. Attacker's votes now have more weight
```

**Mitigation:**
- Proposal creation costs (bond)
- Proposal threshold (min tokens to propose)
- Proposal limits per account

---

## Chain 6: Upgrade Takeover + Proxy Control

**Components:**
1. Governance controls upgrades
2. Proxy pattern with implementation swap
3. No upgrade restrictions

**Attack Flow:**
```
1. Pass proposal to upgrade contract
2. New implementation has backdoor
3. All future interactions compromised
4. Drain funds through backdoor
```

**Detection:**
```solidity
function upgrade(address newImplementation) onlyGovernance {
    // Any address accepted!
    implementation = newImplementation;
}
```

**Mitigation:**
- Whitelist of approved implementations
- Upgrade cooldown period
- Audit requirement for new implementations
- Two-step upgrade process

---

## Chain 7: Vote Buying + Bribery

**Components:**
1. Off-chain vote buying platforms
2. Private bribe payments
3. Voters sell their votes

**Attack Flow:**
```
1. Attacker sets up bribe on platform
2. "Vote YES on proposal X for $Y per token"
3. Voters claim bribes
4. Malicious proposal passes
5. Attacker profits more than bribes cost
```

**Real Example:** Various DeFi governance bribes

**Mitigation:**
- Veto mechanisms
- Time-weighted voting
- Conviction voting
- Reputation systems

---

## Chain 8: Proposal Front-Running + Sandwich

**Components:**
1. Proposal affects token price
2. Proposal visible in mempool
3. MEV opportunity

**Attack Flow:**
```
1. Spot governance proposal in mempool
2. Front-run with buy order
3. Let proposal execute (price impact)
4. Back-run with sell order
5. Profit from price movement
```

**Mitigation:**
- Private proposal submission (Flashbots)
- Commit-reveal proposals
- MEV protection

---

## Governance Security Checklist

### Voting Power
- [ ] Snapshot-based voting (getPastVotes)
- [ ] Flash loan protection
- [ ] Delegation snapshot at proposal time
- [ ] No double counting possible

### Proposals
- [ ] Proposal threshold sufficient
- [ ] Proposal bond/cost
- [ ] Rate limiting on proposals
- [ ] Quorum is meaningful percentage

### Execution
- [ ] Timelock on all executions
- [ ] Emergency functions limited
- [ ] Upgrade restrictions
- [ ] Veto/cancel mechanisms

### Parameters
- [ ] Voting period long enough
- [ ] Quorum can't be bypassed
- [ ] Threshold for sensitive actions higher

---

## Common Governance Parameters

| Parameter | Risky Value | Safe Value |
|-----------|-------------|------------|
| Quorum | <5% | 10-20% |
| Voting Period | <1 day | 3-7 days |
| Timelock | None | 24-48 hours |
| Proposal Threshold | 0 | 1-5% of supply |
| Emergency Roles | EOA | Multi-sig |

---

## Detection Commands

```bash
# Find voting mechanisms
grep -rn "vote\|proposal\|quorum" --include="*.sol"

# Find snapshot usage
grep -rn "getPastVotes\|snapshot\|checkpoint" --include="*.sol"

# Find timelock
grep -rn "timelock\|delay\|eta" --include="*.sol"

# Find emergency functions
grep -rn "emergency\|pause\|guardian" --include="*.sol"

# Find upgrade mechanisms
grep -rn "upgrade\|implementation\|proxy" --include="*.sol"
```
