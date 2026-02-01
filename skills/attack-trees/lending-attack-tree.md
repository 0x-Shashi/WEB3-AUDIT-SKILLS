---
id: LENDING-ATTACK-TREE
title: Lending Protocol Attack Tree
category: attack-tree
protocol: lending
triggers:
  - lending attack paths
  - how to attack lending
  - lending vulnerabilities
  - lending exploit tree
related_skills:
  - patterns/lending-pool-patterns.md
  - patterns/oracle-patterns.md
  - patterns/flash-loan-patterns.md
  - exploit-forensics/euler-2023.md
  - exploit-forensics/radiant-2024.md
---

# Lending Protocol Attack Tree

Visual decision path for attacking lending protocols. Follow branches systematically during audit.

---

## ROOT: Steal Funds from Lending Pool

```
ROOT: Steal Funds from Lending Pool
│
├── [A] Manipulate Oracle Price
│   │
│   ├── [A1] Stale Price Attack
│   │   ├── Condition: No staleness check on oracle
│   │   ├── Action: Wait for price to become stale
│   │   ├── Result: Borrow at outdated favorable price
│   │   └── Check: patterns/oracle-patterns.md#stale-price
│   │
│   ├── [A2] Flash Loan + Spot Price
│   │   ├── Condition: Using DEX spot price (not TWAP)
│   │   ├── Action: Flash loan → Manipulate DEX → Borrow → Repay
│   │   ├── Result: Inflate collateral value, overborrow
│   │   └── Check: patterns/flash-loan-patterns.md#price-manipulation
│   │
│   ├── [A3] Oracle Returns Zero
│   │   ├── Condition: No zero-price validation
│   │   ├── Action: Exploit paused/broken oracle
│   │   ├── Result: Division by zero or infinite borrowing
│   │   └── Check: patterns/oracle-patterns.md#zero-price
│   │
│   ├── [A4] Oracle Returns Negative
│   │   ├── Condition: No negative check, int→uint cast
│   │   ├── Action: Trigger oracle edge case
│   │   ├── Result: Negative casts to huge uint256
│   │   └── Check: patterns/oracle-patterns.md#negative-price
│   │
│   └── [A5] Multi-Oracle Deviation
│       ├── Condition: Using multiple oracles without deviation check
│       ├── Action: Exploit disagreement between oracles
│       ├── Result: Choose favorable oracle price
│       └── Check: patterns/oracle-patterns.md#multi-oracle
│
├── [B] Exploit Liquidation Mechanism
│   │
│   ├── [B1] Self-Liquidation Bonus
│   │   ├── Condition: User can liquidate themselves
│   │   ├── Action: Borrow → Price drops → Self-liquidate for bonus
│   │   ├── Result: Earn liquidation bonus on own position
│   │   └── Check: patterns/lending-pool-patterns.md#self-liquidation
│   │
│   ├── [B2] Block Liquidation (DoS)
│   │   ├── Condition: Liquidation can be prevented
│   │   ├── Action: Revert on liquidation call (malicious collateral)
│   │   ├── Result: Create bad debt, protocol insolvency
│   │   └── Check: patterns/dos-patterns.md#liquidation-dos
│   │
│   ├── [B3] Flash Loan Liquidation
│   │   ├── Condition: Flash loans allowed during liquidation
│   │   ├── Action: Flash loan → Manipulate price → Liquidate → Profit
│   │   ├── Result: Unfair MEV extraction
│   │   └── Check: patterns/flash-loan-patterns.md#liquidation-mev
│   │
│   ├── [B4] Liquidation Before Update
│   │   ├── Condition: Interest not accrued before liquidation check
│   │   ├── Action: Liquidate position that should be healthy
│   │   ├── Result: Steal collateral before proper accounting
│   │   └── Check: patterns/lending-pool-patterns.md#accrue-interest
│   │
│   └── [B5] Partial Liquidation Loop
│       ├── Condition: Partial liquidation allowed repeatedly
│       ├── Action: Liquidate in small chunks to maximize bonus
│       ├── Result: Extract more than intended liquidation bonus
│       └── Check: patterns/lending-pool-patterns.md#partial-liquidation
│
├── [C] Accounting Manipulation
│   │
│   ├── [C1] First Depositor Attack
│   │   ├── Condition: No virtual shares offset
│   │   ├── Action: Deposit 1 wei → Donate large amount → Inflate share price
│   │   ├── Result: Next depositor gets 0 shares, funds stolen
│   │   └── Check: patterns/defi-vault-patterns.md#first-depositor
│   │
│   ├── [C2] Rounding Direction Exploit
│   │   ├── Condition: Rounding favors user on critical operations
│   │   ├── Action: Repeatedly deposit/withdraw small amounts
│   │   ├── Result: Drain dust over time
│   │   └── Check: patterns/defi-vault-patterns.md#rounding
│   │
│   ├── [C3] Interest Rate Manipulation
│   │   ├── Condition: Interest rate based on utilization
│   │   ├── Action: Flash loan → Max utilization → Force high rate
│   │   ├── Result: Charge unfair interest to borrowers
│   │   └── Check: patterns/lending-pool-patterns.md#interest-rate
│   │
│   ├── [C4] Share Inflation via Donation
│   │   ├── Condition: Direct transfer affects exchange rate
│   │   ├── Action: Send tokens directly to pool
│   │   ├── Result: Inflate share price, harm subsequent users
│   │   └── Check: patterns/defi-vault-patterns.md#donation-attack
│   │
│   └── [C5] Borrow Before Supply Update
│       ├── Condition: Borrow possible before supply state update
│       ├── Action: Borrow funds that shouldn't be available
│       ├── Result: Over-borrow, protocol insolvency
│       └── Check: patterns/lending-pool-patterns.md#state-sync
│
├── [D] Reentrancy Attacks
│   │
│   ├── [D1] Withdraw Reentrancy
│   │   ├── Condition: No reentrancy guard on withdraw
│   │   ├── Action: Withdraw → Callback → Withdraw again
│   │   ├── Result: Drain pool before balance update
│   │   └── Check: patterns/reentrancy-patterns.md#classic
│   │
│   ├── [D2] Cross-Function Reentrancy
│   │   ├── Condition: Multiple functions share state, no global guard
│   │   ├── Action: Withdraw → Callback → Borrow
│   │   ├── Result: Use inconsistent state between functions
│   │   └── Check: patterns/reentrancy-patterns.md#cross-function
│   │
│   ├── [D3] Read-Only Reentrancy
│   │   ├── Condition: View function called during state transition
│   │   ├── Action: Flash loan → Read view function → Use stale data
│   │   ├── Result: Other protocols read wrong collateral value
│   │   └── Check: patterns/reentrancy-patterns.md#read-only
│   │
│   └── [D4] ERC777 Callback Reentrancy
│       ├── Condition: Accepting ERC777 tokens
│       ├── Action: Deposit ERC777 → Callback → Reenter
│       ├── Result: Manipulate state during callback
│       └── Check: patterns/token-patterns.md#erc777-hooks
│
├── [E] Flash Loan Exploitation
│   │
│   ├── [E1] Flash Loan + Governance
│   │   ├── Condition: Flash loan tokens have voting power immediately
│   │   ├── Action: Flash loan → Vote maliciously → Repay
│   │   ├── Result: Pass malicious proposal
│   │   └── Check: patterns/governance-patterns.md#flash-loan-voting
│   │
│   ├── [E2] Flash Loan + Interest Spike
│   │   ├── Condition: Interest rate changes based on utilization
│   │   ├── Action: Flash borrow → Max utilization → Others pay high rate
│   │   ├── Result: Extract value from other borrowers
│   │   └── Check: patterns/flash-loan-patterns.md#interest-spike
│   │
│   └── [E3] Flash Loan + Emergency Pause
│       ├── Condition: Pause possible during flash loan
│       ├── Action: Flash loan → Trigger pause → Funds stuck
│       ├── Result: DoS or steal paused funds
│       └── Check: patterns/pausable-patterns.md#flash-loan
│
├── [F] Access Control Bypass
│   │
│   ├── [F1] Unprotected Initialize
│   │   ├── Condition: initialize() not protected
│   │   ├── Action: Call initialize() and set self as admin
│   │   ├── Result: Take over protocol
│   │   └── Check: patterns/access-control-patterns.md#initialization
│   │
│   ├── [F2] Missing Modifier
│   │   ├── Condition: Admin function missing onlyOwner
│   │   ├── Action: Call privileged function as anyone
│   │   ├── Result: Change critical parameters
│   │   └── Check: patterns/access-control-patterns.md#missing-modifier
│   │
│   └── [F3] tx.origin Authentication
│       ├── Condition: Using tx.origin instead of msg.sender
│       ├── Action: Phish admin into calling malicious contract
│       ├── Result: Bypass access control
│       └── Check: patterns/access-control-patterns.md#tx-origin
│
└── [G] Economic Exploits
    │
    ├── [G1] MEV Sandwich Attack
    │   ├── Condition: Large trades without slippage protection
    │   ├── Action: Front-run → User swap → Back-run
    │   ├── Result: Extract value from user trades
    │   └── Check: patterns/mev-patterns.md#sandwich
    │
    ├── [G2] Liquidation MEV
    │   ├── Condition: Public liquidation mempool
    │   ├── Action: Monitor mempool → Front-run liquidation
    │   ├── Result: Steal liquidation rewards
    │   └── Check: patterns/mev-patterns.md#liquidation
    │
    └── [G3] JIT (Just-In-Time) Liquidity
        ├── Condition: Liquidity provider gets unfair advantage
        ├── Action: Add liquidity → User trades → Remove liquidity
        ├── Result: Earn fees without risk
        └── Check: patterns/mev-patterns.md#jit-liquidity
```

---

## Audit Workflow

**How to use this tree:**

1. **Start at ROOT** - Understand the ultimate goal (steal funds)
2. **Follow each branch** - Check if conditions exist
3. **Test each leaf** - Write PoC for exploitable paths
4. **Cross-reference** - Load linked pattern files for details
5. **Document** - Mark which branches are vulnerable

---

## Quick Reference by Attack Type

| Attack Type | Most Common Branch | Severity | Ease |
|-------------|-------------------|----------|------|
| Oracle Manipulation | [A2] Flash Loan + Spot Price | Critical | Medium |
| First Depositor | [C1] First Depositor Attack | High | Easy |
| Reentrancy | [D1] Withdraw Reentrancy | Critical | Medium |
| Liquidation | [B1] Self-Liquidation | High | Easy |
| Flash Loan | [E1] Flash Loan + Governance | Critical | Hard |
| Access Control | [F1] Unprotected Initialize | Critical | Easy |

---

## Real-World Exploits Mapped

| Exploit | Year | Loss | Attack Branch | Details |
|---------|------|------|---------------|---------|
| Euler Finance | 2023 | $197M | [B2] Block Liquidation | exploit-forensics/euler-2023.md |
| Radiant Capital | 2024 | $4.5M | [D2] Cross-Function Reentrancy | exploit-forensics/radiant-2024.md |
| Rari Fuse | 2022 | $80M | [A2] Flash Loan + Spot Price | exploit-forensics/rari-2022.md |
| Cream Finance | 2021 | $130M | [A2] Flash Loan + Spot Price | exploit-forensics/cream-2021.md |

---

## Checklist (Copy for Audit)

```markdown
## Lending Protocol Attack Surface

### Oracle [A]
- [ ] [A1] Stale price check present
- [ ] [A2] Using TWAP not spot price
- [ ] [A3] Zero price validation
- [ ] [A4] Negative price handling
- [ ] [A5] Multi-oracle deviation check

### Liquidation [B]
- [ ] [B1] Self-liquidation prevented
- [ ] [B2] Liquidation cannot be blocked
- [ ] [B3] Flash loan liquidation handled
- [ ] [B4] Interest accrued before liquidation
- [ ] [B5] Partial liquidation limits

### Accounting [C]
- [ ] [C1] First depositor protection
- [ ] [C2] Correct rounding direction
- [ ] [C3] Interest rate manipulation resistant
- [ ] [C4] Donation attack prevented
- [ ] [C5] Supply updated before borrow

### Reentrancy [D]
- [ ] [D1] Withdraw has nonReentrant
- [ ] [D2] Cross-function reentrancy protected
- [ ] [D3] View functions safe during transitions
- [ ] [D4] ERC777 tokens handled or blocked

### Flash Loans [E]
- [ ] [E1] Voting requires time-lock
- [ ] [E2] Interest rate spike protection
- [ ] [E3] Pause cannot trap flash loans

### Access Control [F]
- [ ] [F1] Initialize protected
- [ ] [F2] All admin functions have modifiers
- [ ] [F3] Using msg.sender not tx.origin

### Economic [G]
- [ ] [G1] Slippage protection on swaps
- [ ] [G2] Fair liquidation mechanism
- [ ] [G3] JIT liquidity protections
```
