# Governance Attack Chains

## Chain 1: Flash Loan Governance Takeover
```
Step 1: Acquire governance tokens (flash loan or market buy)
Step 2: Create malicious proposal (change admin, drain treasury)
Step 3: Vote with overwhelming majority
Step 4: Execute proposal (bypass or wait for timelock)
Step 5: Return/sell governance tokens
```

### Detection Points
- [ ] Voting power snapshot at proposal creation (not current balance)?
- [ ] Proposal creation requires minimum token holding period?
- [ ] Timelock on execution (minimum 2 days)?
- [ ] Guardian/multisig can veto malicious proposals?
- [ ] Quorum based on total supply (not just participating voters)?

### Real Example: Beanstalk ($182M)
- Attacker used `emergencyCommit` — no timelock
- Flash-loaned governance power
- One-transaction governance takeover

## Chain 2: Vote Buying / Dark DAO
```
Step 1: Create off-chain agreement to buy votes
Step 2: Voters delegate or vote as instructed
Step 3: Proposal passes due to bought votes
Step 4: Attacker profits from proposal execution
```

### Detection Points
- [ ] Delegation to smart contracts restricted?
- [ ] Vote privacy (makes buying harder)?
- [ ] On-chain voting identity verification?
- [ ] Unusual voting patterns detected?

## Chain 3: Proposal Griefing
```
Step 1: Create many proposals to exhaust governance bandwidth
Step 2: Sneak malicious proposal among legitimate ones
Step 3: Voters miss the malicious proposal
Step 4: Proposal passes with low participation
```

### Detection Points
- [ ] Proposal creation cost (bond/tokens required)?
- [ ] Maximum active proposals limit?
- [ ] Minimum review period?
- [ ] Community notification system?

## Chain 4: Timelock Bypass
```
Step 1: Identify timelock admin functions
Step 2: Find path to execute without timelock
Step 3: Use emergency functions, proxy upgrades, or initialization
Step 4: Execute privileged action instantly
```

### Detection Points
- [ ] ALL admin functions route through timelock?
- [ ] No emergency bypass that skips timelock?
- [ ] Proxy upgrade goes through timelock?
- [ ] Initialization functions can't be called post-deployment?
- [ ] No direct `owner` functions that bypass governance?

## Chain 5: Delegation Exploit
```
Step 1: Accumulate delegated voting power
Step 2: Delegators don't monitor delegate's votes
Step 3: Vote on self-serving proposals
Step 4: Execute before delegators react
```

### Detection Points
- [ ] Delegation revocable at any time?
- [ ] Vote notification to delegators?
- [ ] Delegation caps?
- [ ] Waiting period after delegation change?

## Chain 6: Cross-Chain Governance Attack
```
Step 1: Governance on Chain A controls protocol on Chain B
Step 2: Exploit bridge delay or message verification
Step 3: Execute unauthorized governance actions on Chain B
Step 4: Drain protocol before message is verified
```

### Detection Points
- [ ] Cross-chain governance messages properly verified?
- [ ] Bridge delay sufficient for detection?
- [ ] Guardian can pause cross-chain execution?
- [ ] Chain B has independent safety checks?

## Governance Security Checklist Summary
| Control | Purpose |
|---------|---------|
| Snapshot voting | Prevent flash loan attacks |
| Timelock (2+ days) | Allow community review |
| Guardian veto | Emergency malicious proposal rejection |
| Quorum (4%+ of supply) | Prevent low-turnout attacks |
| Proposal threshold | Prevent spam proposals |
| Vote delay | Time between proposal and voting start |
