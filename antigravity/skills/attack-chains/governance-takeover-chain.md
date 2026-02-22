# Attack Chain: Governance Takeover

## Overview

Attacker accumulates enough voting power (via flash loans, token purchases, or delegation exploits) to pass malicious proposals that drain the treasury or modify critical protocol parameters.

**Complexity:** High
**Typical Severity:** CRITICAL
**Protocols At Risk:** DAOs, Governance-controlled treasuries, Timelock-governed protocols

---

## Attack Steps

```
ACCUMULATE POWER → SUBMIT PROPOSAL → VOTE → EXECUTE → DRAIN
```

### Step 1: Accumulate Voting Power
```
Methods to gain votes:
- Flash loan governance tokens
- Buy tokens before snapshot
- Exploit delegation mechanics
- Accumulate via multiple wallets
- Borrow tokens from lending protocols
```

**What to check:**
- [ ] Can voting power be acquired via flash loan?
- [ ] Is snapshot taken at proposal creation or vote time?
- [ ] Is there a minimum holding period?
- [ ] Can delegated votes be used for proposals?
- [ ] Is there a quorum that's realistically achievable?

### Step 2: Submit Malicious Proposal
```
Proposal types:
- Transfer treasury funds to attacker
- Change admin/owner to attacker address
- Upgrade implementation to malicious contract
- Modify critical parameters (fees, collateral ratios)
- Whitelist attacker contract for special access
```

**What to check:**
- [ ] What actions can proposals execute?
- [ ] Is there a proposal threshold?
- [ ] Can arbitrary calldata be executed?
- [ ] Are there restrictions on target contracts?

### Step 3: Pass the Vote
```
- Vote with accumulated power
- Prevent opposition (buy up remaining tokens)
- Use multiple addresses to seem organic
- Wait out the voting period (or exploit short period)
```

**What to check:**
- [ ] Is voting period sufficient? (< 1 day is risky)
- [ ] Is quorum reasonable? (< 5% is risky)
- [ ] Can votes be changed or withdrawn?
- [ ] Is there vote delegation that can be exploited?

### Step 4: Execute After Timelock
```
- Wait for timelock delay to pass
- Execute the malicious proposal
- Drain treasury/modify parameters
```

**What to check:**
- [ ] Is there a timelock? How long?
- [ ] Can timelock be bypassed?
- [ ] Can proposal be cancelled during timelock?
- [ ] Who can cancel? Is guardian set?

---

## Code Signals

### Flash Loan Governance
```solidity
// [VULNERABLE] Votes counted at time of voting, not snapshot
function castVote(uint256 proposalId, bool support) external {
    uint256 votes = token.balanceOf(msg.sender);  // Current balance
    // Flash loaned tokens count as votes!
    proposals[proposalId].votes += votes;
}
```

### Missing Snapshot
```solidity
// [VULNERABLE] No snapshot - vote weight = current balance
function getVotes(address account) public view returns (uint256) {
    return governanceToken.balanceOf(account);
    // Should use: governanceToken.getPastVotes(account, snapshotBlock)
}
```

### Short Voting Period
```solidity
// [VULNERABLE] 1-day voting period is too short
uint256 public constant VOTING_PERIOD = 1 days;  // Should be 3-7 days
uint256 public constant QUORUM = 100e18;  // Only 100 tokens needed
```

### Unrestricted Proposal Actions
```solidity
// [VULNERABLE] Can execute arbitrary calls
function execute(
    address[] memory targets,
    uint256[] memory values,
    bytes[] memory calldatas
) external {
    // No restriction on which contracts or functions can be called
    for (uint i = 0; i < targets.length; i++) {
        (bool ok,) = targets[i].call{value: values[i]}(calldatas[i]);
        require(ok);
    }
}
```

---

## Detection Checklist

- [ ] Governance token available via flash loan
- [ ] Voting power uses current balance (no snapshots)
- [ ] Voting period < 3 days
- [ ] Quorum < 10% of circulating supply
- [ ] No proposal threshold or threshold too low
- [ ] No timelock on proposal execution
- [ ] Timelock delay < 24 hours
- [ ] No guardian/veto power to cancel malicious proposals
- [ ] Proposals can execute arbitrary contract calls
- [ ] Delegation allows vote multiplying
- [ ] No minimum holding period for voting
- [ ] Treasury accessible via governance proposals

---

## Real-World Examples

| Protocol | Impact | Method | Year |
|----------|--------|--------|------|
| Beanstalk | $182M | Flash loan governance | 2022 |
| Build Finance | $470K | Low quorum takeover | 2022 |
| Tornado Cash | governance hijack | Malicious proposal | 2023 |
| Audius | $6M | Proxy upgrade via governance | 2022 |

---

## Mitigations

| Mitigation | Effectiveness |
|-----------|---------------|
| ERC20Votes with snapshots | HIGH |
| Timelock (48hr+) | HIGH |
| Guardian/veto mechanism | HIGH |
| Minimum holding period for voting | MEDIUM |
| Reasonable quorum (10%+) | MEDIUM |
| Proposal threshold (1%+ supply) | MEDIUM |
| Vote escrow (veToken) | HIGH |
| Multi-sig execution requirement | HIGH |

---

## Related Patterns

- [Vote Patterns](../patterns/vote-patterns.md)
- [Admin Patterns](../patterns/admin-patterns.md)
- [Access Control Patterns](../patterns/access-control-patterns.md)
