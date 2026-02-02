---
id: LIQUID-STAKING-ATTACK-TREE
title: Liquid Staking Attack Tree
category: attack-tree
protocol: liquid-staking
triggers:
  - liquid staking attack paths
  - how to attack staking derivatives
  - LST vulnerabilities
  - staking exploit tree
related_skills:
  - patterns/staking-patterns.md
  - patterns/oracle-patterns.md
  - patterns/withdrawal-patterns.md
  - exploit-forensics/lido-oracle-2023.md
---

# Liquid Staking Attack Tree

Visual decision path for attacking liquid staking protocols (Lido, Rocket Pool, Frax ETH, etc.).

---

## ROOT: Steal Staked Assets or Manipulate Derivatives

```
ROOT: Steal Staked Assets or Manipulate Derivatives
│
├── [A] Oracle Manipulation
│   │
│   ├── [A1] Exchange Rate Oracle Attack
│   │   ├── Condition: LST/ETH rate from manipulatable source
│   │   ├── Action: Flash loan → Manipulate rate → Arbitrage
│   │   ├── Result: Mint more LST than deserved or redeem for more
│   │   └── Check: patterns/oracle-patterns.md#exchange-rate
│   │
│   ├── [A2] Stale Exchange Rate
│   │   ├── Condition: Rate not updated frequently
│   │   ├── Action: Stake/unstake when rate is outdated
│   │   ├── Result: Profit from rate discrepancy
│   │   └── Check: patterns/oracle-patterns.md#staleness
│   │
│   ├── [A3] Validator Performance Oracle
│   │   ├── Condition: Rewards based on reported performance
│   │   ├── Action: Manipulate performance data
│   │   ├── Result: Claim unearned rewards
│   │   └── Check: patterns/oracle-patterns.md#validator-oracle
│   │
│   ├── [A4] Beacon Chain Oracle Manipulation
│   │   ├── Condition: Off-chain oracle reports beacon state
│   │   ├── Action: Compromise oracle or front-run reports
│   │   ├── Result: Incorrect reward distribution
│   │   └── Check: patterns/oracle-patterns.md#beacon-chain
│   │
│   └── [A5] Multi-Oracle Inconsistency
│       ├── Condition: Multiple oracles with different values
│       ├── Action: Exploit divergence between oracles
│       ├── Result: Arbitrage across oracle discrepancies
│       └── Check: patterns/oracle-patterns.md#multi-oracle
│
├── [B] Withdrawal Exploits
│   │
│   ├── [B1] Withdrawal Queue Manipulation
│   │   ├── Condition: FIFO withdrawal queue
│   │   ├── Action: Front-run large withdrawals
│   │   ├── Result: Exit before others, leave them stuck
│   │   └── Check: patterns/withdrawal-patterns.md#queue
│   │
│   ├── [B2] Withdrawal DoS
│   │   ├── Condition: Withdrawal can be blocked
│   │   ├── Action: Prevent withdrawals via gas griefing
│   │   ├── Result: Users trapped, LST depegs
│   │   └── Check: patterns/dos-patterns.md#withdrawal
│   │
│   ├── [B3] Instant vs Delayed Arbitrage
│   │   ├── Condition: Some users get instant, others delayed
│   │   ├── Action: Game the instant withdrawal mechanism
│   │   ├── Result: Extract value from delayed users
│   │   └── Check: patterns/withdrawal-patterns.md#instant-delayed
│   │
│   ├── [B4] Partial Withdrawal Drain
│   │   ├── Condition: Partial withdrawals processed automatically
│   │   ├── Action: Exploit accounting during partial processing
│   │   ├── Result: Claim more than entitled
│   │   └── Check: patterns/withdrawal-patterns.md#partial
│   │
│   └── [B5] Exit Penalty Bypass
│       ├── Condition: Penalties for early withdrawal
│       ├── Action: Find path to bypass penalty calculation
│       ├── Result: Exit without paying penalty
│       └── Check: patterns/withdrawal-patterns.md#penalty-bypass
│
├── [C] Validator/Node Operator Attacks
│   │
│   ├── [C1] Malicious Validator Registration
│   │   ├── Condition: Anyone can register as validator
│   │   ├── Action: Register with wrong withdrawal credentials
│   │   ├── Result: Stake to attacker-controlled validator
│   │   └── Check: patterns/staking-patterns.md#validator-registration
│   │
│   ├── [C2] Slashing Event Exploitation
│   │   ├── Condition: Slashing reduces total staked
│   │   ├── Action: Cause slashing → LST value drops → Buy cheap
│   │   ├── Result: Acquire LST at discount
│   │   └── Check: patterns/staking-patterns.md#slashing
│   │
│   ├── [C3] Validator Key Theft
│   │   ├── Condition: Validator keys stored insecurely
│   │   ├── Action: Steal keys → Force exit or slash
│   │   ├── Result: Drain staked assets
│   │   └── Check: patterns/staking-patterns.md#key-management
│   │
│   ├── [C4] Node Operator Collusion
│   │   ├── Condition: Few node operators control majority
│   │   ├── Action: Collude to manipulate rewards
│   │   ├── Result: Unfair reward distribution
│   │   └── Check: patterns/staking-patterns.md#operator-collusion
│   │
│   ├── [C5] MEV Extraction by Operators
│   │   ├── Condition: Operators propose blocks
│   │   ├── Action: Extract MEV without sharing
│   │   ├── Result: Stakers miss MEV rewards
│   │   └── Check: patterns/mev-patterns.md#validator-mev
│   │
│   └── [C6] Validator Exit Timing Attack
│       ├── Condition: Validators can time their exit
│       ├── Action: Exit before slashing, after rewards
│       ├── Result: Avoid losses, keep gains
│       └── Check: patterns/staking-patterns.md#exit-timing
│
├── [D] LST Token Exploits
│   │
│   ├── [D1] Rebasing Token Accounting Error
│   │   ├── Condition: LST is rebasing (e.g., stETH)
│   │   ├── Action: Exploit protocol not handling rebases
│   │   ├── Result: Mint/withdraw more than entitled
│   │   └── Check: patterns/token-patterns.md#rebasing
│   │
│   ├── [D2] Wrapped LST Manipulation
│   │   ├── Condition: wstETH-style wrapper exists
│   │   ├── Action: Exploit wrap/unwrap ratio changes
│   │   ├── Result: Arbitrage between wrapped and unwrapped
│   │   └── Check: patterns/token-patterns.md#wrapped-rebasing
│   │
│   ├── [D3] LST Flash Loan Attack
│   │   ├── Condition: LST available for flash loans
│   │   ├── Action: Flash borrow LST → Manipulate → Profit
│   │   ├── Result: Exploit LST-dependent protocols
│   │   └── Check: patterns/flash-loan-patterns.md#lst
│   │
│   ├── [D4] LST/ETH Peg Manipulation
│   │   ├── Condition: LST trades on DEXes
│   │   ├── Action: Manipulate LST price vs peg
│   │   ├── Result: Exploit protocols using LST as collateral
│   │   └── Check: patterns/staking-patterns.md#peg-manipulation
│   │
│   └── [D5] Cross-Protocol LST Exploit
│       ├── Condition: LST used in multiple DeFi protocols
│       ├── Action: Exploit interaction between protocols
│       ├── Result: Amplified attack across ecosystem
│       └── Check: patterns/composability-patterns.md#lst
│
├── [E] Reward Distribution Attacks
│   │
│   ├── [E1] Reward Timing Manipulation
│   │   ├── Condition: Rewards distributed periodically
│   │   ├── Action: Stake right before, unstake right after
│   │   ├── Result: Maximize rewards per time staked
│   │   └── Check: patterns/staking-patterns.md#reward-timing
│   │
│   ├── [E2] Reward Accounting Error
│   │   ├── Condition: Complex reward calculation
│   │   ├── Action: Exploit rounding or precision errors
│   │   ├── Result: Claim extra rewards
│   │   └── Check: patterns/precision-patterns.md#rewards
│   │
│   ├── [E3] Socialized Loss Exploitation
│   │   ├── Condition: Losses spread across all stakers
│   │   ├── Action: Cause loss → Exit before socialization
│   │   ├── Result: Others bear attacker's loss
│   │   └── Check: patterns/staking-patterns.md#socialized-loss
│   │
│   ├── [E4] Insurance Fund Drain
│   │   ├── Condition: Protocol has insurance/buffer
│   │   ├── Action: Trigger events that drain insurance
│   │   ├── Result: Protocol becomes insolvent
│   │   └── Check: patterns/staking-patterns.md#insurance
│   │
│   └── [E5] Fee Distribution Gaming
│       ├── Condition: Fees distributed to stakers
│       ├── Action: Flash stake to capture fees
│       ├── Result: Dilute rewards for long-term stakers
│       └── Check: patterns/staking-patterns.md#fee-distribution
│
├── [F] Governance Attacks
│   │
│   ├── [F1] LST-Weighted Governance Attack
│   │   ├── Condition: LST holders can vote
│   │   ├── Action: Flash loan LST → Vote → Repay
│   │   ├── Result: Pass malicious governance proposals
│   │   └── Check: patterns/governance-patterns.md#lst-voting
│   │
│   ├── [F2] Operator Selection Manipulation
│   │   ├── Condition: Governance selects node operators
│   │   ├── Action: Manipulate voting to select malicious operator
│   │   ├── Result: Control over staked assets
│   │   └── Check: patterns/governance-patterns.md#operator-selection
│   │
│   ├── [F3] Parameter Change Attack
│   │   ├── Condition: Governance can change fees/limits
│   │   ├── Action: Pass proposal to extract fees
│   │   ├── Result: Drain protocol via fee extraction
│   │   └── Check: patterns/governance-patterns.md#parameter-attack
│   │
│   └── [F4] Emergency Pause Abuse
│       ├── Condition: Governance can pause withdrawals
│       ├── Action: Pause during depeg to trap users
│       ├── Result: Users can't exit, worsens panic
│       └── Check: patterns/pausable-patterns.md#staking
│
└── [G] Cross-Layer/Bridge Attacks
    │
    ├── [G1] L1 to L2 LST Bridge Exploit
    │   ├── Condition: LST bridged to L2
    │   ├── Action: Exploit bridge to mint unbacked LST
    │   ├── Result: Drain L2 liquidity
    │   └── Check: patterns/bridge-patterns.md#lst-bridge
    │
    ├── [G2] Cross-Chain LST Arbitrage
    │   ├── Condition: LST on multiple chains
    │   ├── Action: Exploit price differences across chains
    │   ├── Result: Risk-free arbitrage at protocol expense
    │   └── Check: patterns/cross-chain-patterns.md#lst
    │
    ├── [G3] Restaking Exploit
    │   ├── Condition: LST can be restaked (e.g., EigenLayer)
    │   ├── Action: Double-count collateral across layers
    │   ├── Result: Over-leverage, systemic risk
    │   └── Check: patterns/restaking-patterns.md#double-count
    │
    └── [G4] DVT (Distributed Validator) Attack
        ├── Condition: Validators use DVT
        ├── Action: Compromise threshold of DVT nodes
        ├── Result: Control validator despite distribution
        └── Check: patterns/staking-patterns.md#dvt
```

---

## Audit Workflow

**How to use this tree:**

1. **Identify LST type** - Rebasing (stETH), Non-rebasing (rETH), Wrapped
2. **Check validator model** - Permissioned, Permissionless, DVT
3. **Analyze withdrawal** - Queue, Instant, Delayed, Penalties
4. **Test oracle** - Exchange rate source, Update frequency, Manipulation resistance
5. **Review governance** - Operator selection, Parameter changes, Emergency powers

---

## Quick Reference by Protocol Type

### Rebasing LSTs (stETH-style)
**Critical Vulnerabilities:**
- [D1] Rebasing accounting errors (Critical)
- [D2] Wrap/unwrap ratio manipulation (High)
- [A1] Exchange rate oracle attack (Critical)

**Examples:** Lido stETH, Coinbase cbETH (rebasing mode)

### Non-Rebasing LSTs (rETH-style)
**Critical Vulnerabilities:**
- [A1] Exchange rate manipulation (Critical)
- [B1] Withdrawal queue manipulation (High)
- [E2] Reward accounting errors (Medium)

**Examples:** Rocket Pool rETH, Frax frxETH

### Permissionless Staking
**Critical Vulnerabilities:**
- [C1] Malicious validator registration (Critical)
- [C2] Slashing exploitation (High)
- [C4] Operator collusion (High)

**Examples:** Rocket Pool, SSV Network

### Permissioned Staking
**Critical Vulnerabilities:**
- [C3] Validator key theft (Critical)
- [F2] Operator selection manipulation (High)
- [C5] MEV extraction (Medium)

**Examples:** Lido, Coinbase

---

## Real-World Exploits Mapped

| Exploit | Year | Loss | Attack Branch | Details |
|---------|------|------|---------------|---------|
| Lido Oracle Manipulation | 2023 | N/A (caught) | [A4] Beacon Oracle | Oracle reported incorrect data |
| stETH Depeg | 2022 | Market impact | [D4] Peg Manipulation | Large withdrawals caused depeg |
| Rocket Pool rETH Arbitrage | 2023 | Minor | [A1] Exchange Rate | Rate discrepancy exploitation |

---

## Checklist (Copy for Audit)

```markdown
## Liquid Staking Attack Surface

### Oracle [A]
- [ ] [A1] Exchange rate manipulation resistant
- [ ] [A2] Rate updated frequently (staleness check)
- [ ] [A3] Validator performance data verified
- [ ] [A4] Beacon chain oracle secure
- [ ] [A5] Multi-oracle consistency checked

### Withdrawal [B]
- [ ] [B1] Withdrawal queue fair (no front-running)
- [ ] [B2] Withdrawal cannot be DoS'd
- [ ] [B3] Instant/delayed mechanism fair
- [ ] [B4] Partial withdrawal accounting correct
- [ ] [B5] Exit penalties enforced

### Validators [C]
- [ ] [C1] Validator registration validates credentials
- [ ] [C2] Slashing handled correctly
- [ ] [C3] Validator keys secure
- [ ] [C4] Operator collusion mitigated
- [ ] [C5] MEV sharing enforced
- [ ] [C6] Exit timing restrictions

### LST Token [D]
- [ ] [D1] Rebasing handled by all integrations
- [ ] [D2] Wrap/unwrap ratios correct
- [ ] [D3] Flash loan attacks mitigated
- [ ] [D4] Peg deviation handled
- [ ] [D5] Cross-protocol interactions safe

### Rewards [E]
- [ ] [E1] Reward timing gaming prevented
- [ ] [E2] Reward accounting precise
- [ ] [E3] Socialized loss fair
- [ ] [E4] Insurance fund sustainable
- [ ] [E5] Fee distribution fair

### Governance [F]
- [ ] [F1] LST voting snapshot-based
- [ ] [F2] Operator selection secure
- [ ] [F3] Parameter changes have limits
- [ ] [F4] Emergency pause has safeguards

### Cross-Layer [G]
- [ ] [G1] Bridge security verified
- [ ] [G2] Cross-chain consistency
- [ ] [G3] Restaking risks documented
- [ ] [G4] DVT threshold secure
```

---

## Protocol-Specific Considerations

### Lido (stETH)
- Rebasing token - check all DeFi integrations
- Permissioned operators - check selection process
- Large market share - systemic risk

### Rocket Pool (rETH)
- Non-rebasing - exchange rate oracle critical
- Permissionless - validator registration security
- Minipool system - check collateral requirements

### Frax (frxETH/sfrxETH)
- Dual token model - check conversion
- AMO integration - check rebalancing
- Validator diversity - check centralization

### EigenLayer (Restaking)
- Double-counted collateral risk
- Slashing propagation
- Operator trust assumptions

---

## See Also

- **Patterns:** [staking-patterns.md](../patterns/staking-patterns.md)
- **Oracle Patterns:** [oracle-patterns.md](../patterns/oracle-patterns.md)
- **Token Patterns:** [token-patterns.md](../patterns/token-patterns.md)
- **Related:** [governance-attack-tree.md](./governance-attack-tree.md)

---

**Last Updated:** 2025
**Version:** 1.0
