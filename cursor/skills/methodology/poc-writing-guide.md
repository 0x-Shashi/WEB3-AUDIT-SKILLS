---
id: POC-WRITING-GUIDE
title: Proof of Concept Writing Guide
category: methodology
triggers:
  - write a PoC
  - proof of concept
  - how to demonstrate vulnerability
  - exploit template
  - foundry test structure
  - PoC best practices
related_skills:
  - methodology/audit-report-templates.md
  - patterns/reentrancy-patterns.md
  - patterns/flash-loan-patterns.md
  - patterns/oracle-patterns.md
---

# 📝 Proof of Concept Writing Guide

## Overview

This guide teaches how to write effective PoCs that clearly demonstrate vulnerabilities. A good PoC proves exploitability and helps developers understand the fix.

---

## PoC Structure Template

Every PoC should follow this structure:

```
1. SETUP
   - Deploy vulnerable contract(s)
   - Set initial state (balances, roles, etc.)
   - Deploy attacker contract if needed

2. PRECONDITIONS
   - Log/assert initial state
   - Show what "normal" looks like

3. ATTACK
   - Execute the exploit steps
   - Clear comments explaining each step

4. POSTCONDITIONS
   - Assert the exploit succeeded
   - Show profit/damage quantified
```

---

## Reentrancy PoC Pattern

### What to Demonstrate
- Attacker can drain funds via callback
- State is inconsistent during external call

### Key Elements
```solidity
// SETUP: Deploy vulnerable bank with funds
// ATTACK: Attacker deposits small amount, then withdraws
// CALLBACK: In receive(), call withdraw again
// RESULT: Attacker gets more than deposited
```

### Assertions to Include
- `assertGt(attackerBalanceAfter, attackerBalanceBefore)`
- `assertLt(bankBalanceAfter, expectedBalance)`
- Show exact profit amount

### Common Mistakes
- ❌ Not showing initial vs final balances
- ❌ No comments explaining the flow
- ❌ Hardcoded values without explanation
- ✅ Clear setup → attack → verify flow

---

## Flash Loan Attack PoC Pattern

### What to Demonstrate
- Temporary capital enables attack
- Price/state manipulation during loan
- Profitable despite fees

### Key Elements
```solidity
// SETUP: Target protocol with manipulable oracle
// BORROW: Flash loan large amount
// MANIPULATE: Affect price/state
// EXPLOIT: Profit from manipulation
// REPAY: Return loan + fee
// RESULT: Net profit after fees
```

### Assertions to Include
- `attackerProfitAfter > flashLoanFee`
- Protocol lost expected amount
- Oracle returned to normal (if applicable)

---

## Oracle Manipulation PoC Pattern

### What to Demonstrate
- Stale price acceptance
- Zero/negative price handling
- Price deviation impact

### Key Elements
```solidity
// SETUP: Protocol using Chainlink oracle
// MOCK: Set stale timestamp or bad price
// EXPLOIT: Use bad price for profitable action
// RESULT: Show incorrect valuation impact
```

### Scenarios to Test
1. **Stale Price**: `updatedAt` older than heartbeat
2. **Zero Price**: Oracle returns 0
3. **Negative Price**: Oracle returns negative (rare but possible)
4. **Round Incomplete**: `answeredInRound < roundId`

---

## First Depositor Attack PoC Pattern

### What to Demonstrate
- First depositor controls share price
- Small deposit + donation = share inflation
- Subsequent depositors lose funds

### Key Elements
```solidity
// SETUP: Empty vault
// ATTACKER: Deposit 1 wei, get 1 share
// DONATE: Send tokens directly to vault (e.g., 10000 tokens)
// VICTIM: Deposits 9999 tokens, gets 0 shares (rounded down)
// RESULT: Attacker redeems for victim's deposit
```

### Key Calculations
- Show exchange rate before/after donation
- Victim's expected shares vs actual shares
- Attacker's profit = victim's loss

---

## Access Control PoC Pattern

### What to Demonstrate
- Unauthorized user can call restricted function
- Privilege escalation path
- Missing modifier impact

### Key Elements
```solidity
// SETUP: Deploy with roles configured
// ATTACKER: Non-privileged account
// EXPLOIT: Call admin function successfully
// RESULT: State changed by unauthorized user
```

### Scenarios to Test
1. **Missing Modifier**: Function lacks `onlyOwner`
2. **Wrong Check**: `tx.origin` instead of `msg.sender`
3. **Initialization**: Unprotected `initialize()`
4. **Self-Destruct**: Missing protection on selfdestruct

---

## Signature Replay PoC Pattern

### What to Demonstrate
- Same signature works twice
- Cross-chain replay possible
- Signature valid after intended expiry

### Key Elements
```solidity
// SETUP: Valid signature for action
// USE: Execute action with signature
// REPLAY: Execute same action again
// RESULT: Action performed twice with one signature
```

### Scenarios to Test
1. **No Nonce**: Signature lacks nonce
2. **No Deadline**: Signature valid forever
3. **No ChainId**: Valid on all chains
4. **Malleable**: (v, r, s) can be transformed

---

## PoC Quality Checklist

### Must Have
- [ ] Clear setup with realistic values
- [ ] Comments explaining each step
- [ ] Before/after state logging
- [ ] Quantified impact (profit, loss, damage)
- [ ] Assertions proving the exploit

### Should Have
- [ ] Multiple attack scenarios if applicable
- [ ] Edge case demonstrations
- [ ] Mitigation that makes PoC fail
- [ ] Realistic token amounts (not just 1 wei)

### Nice to Have
- [ ] Gas costs for attack
- [ ] Time constraints (if any)
- [ ] Comparison with fixed version

---

## Foundry Test Commands

```bash
# Run specific PoC
forge test --match-test testExploit -vvvv

# Run with gas report
forge test --match-test testExploit --gas-report

# Fork mainnet for realistic test
forge test --fork-url $ETH_RPC_URL --match-test testExploit

# Debug specific test
forge test --match-test testExploit --debug
```

---

## Common PoC Anti-Patterns

### ❌ Unrealistic Setup
```
"Attacker needs 1 billion tokens to exploit"
→ Not a realistic vulnerability
```

### ❌ No Quantification
```
"Attacker gains tokens"
→ How many? What's the profit?
```

### ❌ Missing Context
```
"Call withdraw() to exploit"
→ What state is needed? What's the attack flow?
```

### ❌ Over-Complicated
```
100 lines of setup for simple bug
→ Minimize to essential elements
```

---

## PoC Report Template

When documenting your PoC:

```markdown
## Proof of Concept

### Setup
1. Deploy VulnerableContract with 100 ETH
2. Attacker starts with 1 ETH

### Attack Steps
1. Attacker calls deposit(1 ETH)
2. Attacker calls withdraw(1 ETH)
3. In receive callback, attacker calls withdraw(1 ETH) again
4. Repeat until contract drained

### Result
- Attacker profit: 99 ETH
- Protocol loss: 100 ETH (entire balance)

### Mitigation
Add ReentrancyGuard modifier to withdraw()
```

---

## Summary

A good PoC:
1. **Proves** the vulnerability exists
2. **Quantifies** the impact
3. **Explains** the attack flow
4. **Guides** the fix

Focus on clarity over complexity. The goal is to help developers understand and fix the issue.
