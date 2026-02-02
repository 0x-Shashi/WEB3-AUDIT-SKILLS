---
id: GOVERNANCE-ATTACK-TREE
title: Governance Protocol Attack Tree
category: attack-tree
protocol: governance
triggers:
  - governance attack paths
  - how to attack governance
  - dao vulnerabilities
  - governance exploit tree
related_skills:
  - patterns/governance-patterns.md
  - patterns/flash-loan-patterns.md
  - patterns/signature-patterns.md
  - exploit-forensics/beanstalk-2022.md
---

# Governance Protocol Attack Tree

Visual decision path for attacking governance protocols and DAOs.

---

## ROOT: Manipulate Governance Outcome

```
ROOT: Manipulate Governance Outcome
│
├── [A] Vote Manipulation
│   │
│   ├── [A1] Flash Loan Voting Attack
│   │   ├── Condition: No snapshot delay, governance tokens transferable
│   │   ├── Action: Flash loan tokens → Vote → Repay
│   │   ├── Result: Pass malicious proposal with borrowed voting power
│   │   └── Check: patterns/governance-patterns.md#flash-loan-voting
│   │
│   ├── [A2] Vote Buying
│   │   ├── Condition: Delegation allowed, voters economically rational
│   │   ├── Action: Offer payment for votes/delegation
│   │   ├── Result: Buy enough votes to pass proposal
│   │   └── Check: patterns/governance-patterns.md#vote-buying
│   │
│   ├── [A3] Bribe Attack
│   │   ├── Condition: Voters receive rewards for voting certain way
│   │   ├── Action: Offer higher reward than protocol
│   │   ├── Result: Voters vote against protocol interest
│   │   └── Check: patterns/governance-patterns.md#bribes
│   │
│   ├── [A4] Vote Delegation Attack
│   │   ├── Condition: Users delegate voting power
│   │   ├── Action: Accumulate delegations, then vote maliciously
│   │   ├── Result: Trusted delegate turns malicious
│   │   └── Check: patterns/governance-patterns.md#delegation
│   │
│   ├── [A5] Sybil Attack (Low Cost Votes)
│   │   ├── Condition: Low barrier to obtain voting power
│   │   ├── Action: Create many addresses, accumulate minimum votes
│   │   ├── Result: 51% attack with many small positions
│   │   └── Check: patterns/governance-patterns.md#sybil
│   │
│   └── [A6] Snapshot Timing Attack
│       ├── Condition: Snapshot block predictable
│       ├── Action: Accumulate tokens right before snapshot
│       ├── Result: Vote without long-term commitment
│       └── Check: patterns/governance-patterns.md#snapshot-timing
│
├── [B] Proposal Manipulation
│   │
│   ├── [B1] Proposal Spam
│   │   ├── Condition: Low proposal threshold
│   │   ├── Action: Flood governance with spam proposals
│   │   ├── Result: DoS legitimate proposals, voter fatigue
│   │   └── Check: patterns/governance-patterns.md#proposal-spam
│   │
│   ├── [B2] Hidden Malicious Code
│   │   ├── Condition: Voters don't read proposal code
│   │   ├── Action: Hide malicious action in complex proposal
│   │   ├── Result: Malicious proposal passes unnoticed
│   │   └── Check: patterns/governance-patterns.md#hidden-code
│   │
│   ├── [B3] Last-Minute Proposal Change
│   │   ├── Condition: Proposal can be modified after voting starts
│   │   ├── Action: Submit good proposal → Change to malicious
│   │   ├── Result: Voters approve without re-reviewing
│   │   └── Check: patterns/governance-patterns.md#proposal-mutation
│   │
│   ├── [B4] Frontrun Proposal Execution
│   │   ├── Condition: Proposal execution in mempool
│   │   ├── Action: Front-run with transaction exploiting new state
│   │   ├── Result: Profit from knowing proposal will execute
│   │   └── Check: patterns/mev-patterns.md#governance-frontrun
│   │
│   └── [B5] Proposal Cancellation Attack
│       ├── Condition: Anyone can cancel if proposer's votes drop
│       ├── Action: Trick/force proposer to transfer tokens
│       ├── Result: Cancel legitimate proposals
│       └── Check: patterns/governance-patterns.md#cancel-attack
│
├── [C] Timelock Bypass
│   │
│   ├── [C1] Zero Timelock
│   │   ├── Condition: No timelock or can be set to 0
│   │   ├── Action: Pass proposal to set timelock = 0
│   │   ├── Result: Instant execution, no reaction time
│   │   └── Check: patterns/governance-patterns.md#no-timelock
│   │
│   ├── [C2] Timelock Admin Override
│   │   ├── Condition: Admin can bypass or shorten timelock
│   │   ├── Action: Compromise admin → Execute immediately
│   │   ├── Result: Bypass timelock protection
│   │   └── Check: patterns/governance-patterns.md#timelock-bypass
│   │
│   ├── [C3] Timelock Front-Running
│   │   ├── Condition: Timelock execution public
│   │   ├── Action: Monitor timelock → Front-run execution
│   │   ├── Result: Exploit known upcoming changes
│   │   └── Check: patterns/mev-patterns.md#timelock-frontrun
│   │
│   └── [C4] Multiple Timelock Queues
│       ├── Condition: Different timelocks for different actions
│       ├── Action: Use shortest timelock for critical action
│       ├── Result: Bypass longer timelock requirements
│       └── Check: patterns/governance-patterns.md#timelock-bypass
│
├── [D] Quorum Manipulation
│   │
│   ├── [D1] Quorum Too Low
│   │   ├── Condition: Required quorum < 10% of supply
│   │   ├── Action: Pass proposal with tiny voter participation
│   │   ├── Result: Minority controls protocol
│   │   └── Check: patterns/governance-patterns.md#low-quorum
│   │
│   ├── [D2] Quorum Denial (DoS)
│   │   ├── Condition: Quorum required but hard to reach
│   │   ├── Action: Ensure quorum never reached (split votes)
│   │   ├── Result: Protocol cannot upgrade or respond
│   │   └── Check: patterns/dos-patterns.md#governance-dos
│   │
│   ├── [D3] Circulating Supply Manipulation
│   │   ├── Condition: Quorum based on circulating supply
│   │   ├── Action: Burn tokens to reduce circulating supply
│   │   ├── Result: Lower absolute quorum threshold
│   │   └── Check: patterns/governance-patterns.md#supply-manipulation
│   │
│   └── [D4] Excluded Balance Attack
│       ├── Condition: Some balances excluded from quorum calc
│       ├── Action: Move tokens to excluded addresses
│       ├── Result: Artificially reduce quorum requirement
│       └── Check: patterns/governance-patterns.md#quorum-calc
│
├── [E] Execution Exploits
│   │
│   ├── [E1] Arbitrary Call Execution
│   │   ├── Condition: Governance can execute arbitrary calls
│   │   ├── Action: Pass proposal to call malicious contract
│   │   ├── Result: Execute any action as governance
│   │   └── Check: patterns/governance-patterns.md#arbitrary-call
│   │
│   ├── [E2] Reentrancy During Execution
│   │   ├── Condition: Proposal execution calls external contracts
│   │   ├── Action: Reenter during proposal execution
│   │   ├── Result: Execute proposal multiple times
│   │   └── Check: patterns/reentrancy-patterns.md#governance
│   │
│   ├── [E3] Failed Execution (Silent)
│   │   ├── Condition: Proposal execution failure not detected
│   │   ├── Action: Submit proposal that will fail silently
│   │   ├── Result: Proposal marked executed but no effect
│   │   └── Check: patterns/governance-patterns.md#failed-execution
│   │
│   ├── [E4] Gas Griefing
│   │   ├── Condition: Anyone can execute queued proposal
│   │   ├── Action: Execute with insufficient gas
│   │   ├── Result: Proposal fails, locks governance
│   │   └── Check: patterns/dos-patterns.md#gas-griefing
│   │
│   └── [E5] Execution Order Dependency
│       ├── Condition: Multiple proposals queued
│       ├── Action: Execute in wrong order
│       ├── Result: Protocol in inconsistent state
│       └── Check: patterns/governance-patterns.md#execution-order
│
├── [F] Token Distribution Attack
│   │
│   ├── [F1] Whale Accumulation
│   │   ├── Condition: Large holders can control votes
│   │   ├── Action: Accumulate >50% of voting power
│   │   ├── Result: Complete governance control
│   │   └── Check: patterns/governance-patterns.md#whale-attack
│   │
│   ├── [F2] Airdrop Farming
│   │   ├── Condition: Governance tokens airdropped
│   │   ├── Action: Sybil attack to get multiple airdrops
│   │   ├── Result: Accumulate unfair voting power
│   │   └── Check: patterns/governance-patterns.md#airdrop-gaming
│   │
│   ├── [F3] Liquid Staking Attack
│   │   ├── Condition: Staked tokens have voting power
│   │   ├── Action: Control liquid staking derivative
│   │   ├── Result: Vote with others' staked tokens
│   │   └── Check: patterns/governance-patterns.md#liquid-staking
│   │
│   └── [F4] Voting Power Concentration
│       ├── Condition: Early adopters have most tokens
│       ├── Action: Wait for token concentration
│       ├── Result: Small group controls governance
│       └── Check: patterns/governance-patterns.md#concentration
│
└── [G] Economic Attacks
    │
    ├── [G1] Governance Token Price Manipulation
    │   ├── Condition: Voting power tied to token price
    │   ├── Action: Manipulate token price to change voting power
    │   ├── Result: Temporary governance control
    │   └── Check: patterns/governance-patterns.md#price-manipulation
    │
    ├── [G2] Rage Quit Attack
    │   ├── Condition: Users can exit with treasury share
    │   ├── Action: Pass malicious proposal → Users rage quit
    │   ├── Result: Drain treasury via exits
    │   └── Check: patterns/governance-patterns.md#rage-quit
    │
    ├── [G3] Fee Switch Attack
    │   ├── Condition: Governance can enable protocol fees
    │   ├── Action: Pass proposal to extract max fees
    │   ├── Result: Value extraction from users
    │   └── Check: patterns/governance-patterns.md#fee-extraction
    │
    └── [G4] Treasury Drain
        ├── Condition: Governance controls treasury
        ├── Action: Pass proposal to send treasury to attacker
        ├── Result: Complete treasury theft
        └── Check: patterns/governance-patterns.md#treasury-drain
```

---

## Audit Workflow

**How to use this tree:**

1. **Identify governance type** - Token-weighted, NFT-based, Quadratic, Conviction
2. **Check voting mechanism** - Snapshot, on-chain, hybrid
3. **Analyze timelock** - Duration, bypass conditions, admin powers
4. **Test vote manipulation** - Flash loans, delegation, buying
5. **Review execution** - Who can execute, validation, failure handling

---

## Quick Reference by Attack Type

| Attack Type | Most Common Branch | Severity | Ease |
|-------------|-------------------|----------|------|
| Flash Loan Voting | [A1] Flash Loan Attack | Critical | Medium |
| No Timelock | [C1] Zero Timelock | Critical | Easy |
| Low Quorum | [D1] Quorum Too Low | High | Easy |
| Hidden Malicious Code | [B2] Hidden Code | Critical | Medium |
| Treasury Drain | [G4] Treasury Drain | Critical | Hard |
| Arbitrary Call | [E1] Arbitrary Call | Critical | Medium |

---

## Real-World Exploits Mapped

| Exploit | Year | Loss | Attack Branch | Details |
|---------|------|------|---------------|---------|
| Beanstalk | 2022 | $182M | [A1] Flash Loan Voting + [G4] Treasury Drain | Flash loan → Vote → Drain treasury |
| Build Finance | 2021 | $470K | [F1] Whale Accumulation | 51% attack via token accumulation |
| Tornado Cash Governance | 2023 | Compromised | [B2] Hidden Malicious Code | Malicious proposal passed unnoticed |

---

## Checklist (Copy for Audit)

```markdown
## Governance Attack Surface

### Vote Manipulation [A]
- [ ] [A1] Flash loan voting prevented (snapshot delay)
- [ ] [A2] Vote buying mitigated (non-transferable votes)
- [ ] [A3] Bribe resistance mechanisms
- [ ] [A4] Delegation limits or warnings
- [ ] [A5] Sybil resistance (minimum stake)
- [ ] [A6] Snapshot timing secure

### Proposal [B]
- [ ] [B1] Proposal spam prevented (threshold, deposit)
- [ ] [B2] Code review required before voting
- [ ] [B3] Proposal immutable after voting starts
- [ ] [B4] Execution delay for frontrun protection
- [ ] [B5] Cancellation conditions secure

### Timelock [C]
- [ ] [C1] Minimum timelock enforced (24-48h)
- [ ] [C2] No admin timelock bypass
- [ ] [C3] Frontrun protection mechanisms
- [ ] [C4] Consistent timelock across actions

### Quorum [D]
- [ ] [D1] Quorum threshold reasonable (>10%)
- [ ] [D2] DoS attack on quorum prevented
- [ ] [D3] Supply manipulation resistant
- [ ] [D4] Quorum calculation accurate

### Execution [E]
- [ ] [E1] Whitelisted targets only (no arbitrary calls)
- [ ] [E2] Reentrancy protection on execution
- [ ] [E3] Execution failure properly detected
- [ ] [E4] Gas griefing prevented
- [ ] [E5] Execution order enforced

### Token Distribution [F]
- [ ] [F1] Whale limits or quadratic voting
- [ ] [F2] Airdrop sybil resistance
- [ ] [F3] Liquid staking voting handled
- [ ] [F4] Voting power distribution monitored

### Economic [G]
- [ ] [G1] Voting not tied to manipulable price
- [ ] [G2] Rage quit limits or delays
- [ ] [G3] Fee changes have limits/timelock
- [ ] [G4] Treasury access restricted/vested
```

---

## Governance Types & Specific Risks

### Token-Weighted Voting
**Unique Risks:**
- Flash loan attacks (high)
- Whale control (high)
- Vote buying (medium)

**Mitigations:**
- Snapshot voting (eliminates flash loans)
- Quadratic voting (reduces whale power)
- Vote delegation limits

### NFT-Based Voting
**Unique Risks:**
- Sybil attacks via cheap NFTs (high)
- Snapshot timing (medium)
- Transfer right before vote (medium)

**Mitigations:**
- NFT rarity weighting
- Holding period requirement
- Soul-bound voting NFTs

### Quadratic Voting
**Unique Risks:**
- Sybil attacks (critical)
- Identity verification bypass (high)
- Cost calculation manipulation (medium)

**Mitigations:**
- Proof of humanity / identity
- Retroactive sybil detection
- On-chain reputation

### Conviction Voting
**Unique Risks:**
- Long-term voting power accumulation (medium)
- Early proposer advantage (low)
- Vote withdrawal manipulation (medium)

**Mitigations:**
- Conviction decay
- Maximum conviction caps
- Withdrawal cooldowns

---

## Integration with Other Protocols

### Governance Controlling DeFi Protocol

**Additional Checks:**
- Emergency pause authority limits
- Parameter change bounds (e.g., max fee = 10%)
- Oracle change restrictions
- Upgrade timelock minimums

### Governance with Treasury

**Additional Checks:**
- Spending limits per proposal
- Multi-sig for large transfers
- Vesting for treasury distributions
- Whitelist for recipient addresses

### Cross-Chain Governance

**Additional Checks:**
- Message verification on destination chains
- Cross-chain execution delays
- Bridge security dependencies
- Chain-specific vote confirmation

---

## See Also

- **Patterns:** [governance-patterns.md](../patterns/governance-patterns.md)
- **Anti-Patterns:** [governance-anti-patterns.md](../anti-patterns/governance-anti-patterns.md)
- **Flash Loans:** [flash-loan-patterns.md](../patterns/flash-loan-patterns.md)
- **Exploits:** exploit-forensics/beanstalk-2022.md

---

**Last Updated:** 2025
**Version:** 1.0
