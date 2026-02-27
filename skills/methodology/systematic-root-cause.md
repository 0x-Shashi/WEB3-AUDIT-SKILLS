---
id: METH-SYSTEMATIC-ROOT-CAUSE
title: Systematic Root Cause Analysis for Security Findings
category: methodology
severity: high
chains: [ethereum, solana, cosmos, aptos, sui, starknet, all]
languages: [solidity, rust, move, cairo, typescript]
tags:
  - root-cause
  - debugging
  - vulnerability-analysis
  - triage
  - data-flow
  - hypothesis-testing
  - audit-methodology
last_updated: 2026-02-27
description: >-
  Use when analyzing any suspected vulnerability, unexpected behavior, or
  failed exploit attempt — enforces 4-phase root-cause investigation before
  proposing fixes or classifying severity. Prevents symptom-fixing,
  duplicate findings, and misclassified severities.
---

# Systematic Root Cause Analysis for Security Findings

## Overview

Random vulnerability classification wastes time and produces weak findings.
A reentrancy symptom might mask an access control root cause. A price
manipulation symptom might trace back to a missing TWAP window.

**Core principle**: ALWAYS find root cause before classifying severity.
Symptom-level findings are low quality.

### The Iron Law

```
NO SEVERITY CLASSIFICATION WITHOUT ROOT CAUSE INVESTIGATION FIRST
```

If you haven't completed Phase 1, you cannot classify the finding.

## When to Use

Use for ANY suspected vulnerability:
- Suspicious code patterns spotted during review
- Failed assertions in test suites
- Unexpected state transitions
- Economic attack hypotheses
- Cross-contract interaction anomalies

**Use ESPECIALLY when**:
- "This looks like reentrancy" (is it really?)
- "Oracle can be manipulated" (what's the actual path?)
- Multiple findings seem related (shared root cause?)
- A fix didn't resolve the issue (wrong root cause?)

## The Four Phases

### Phase 1: Root Cause Investigation

**BEFORE classifying severity or writing the finding:**

#### 1a. Read the Error Signal

| Signal Type | What to Look For |
|------------|-----------------|
| Revert message | Custom error, require string, panic code |
| State change | Storage slot before/after, event emission |
| Return value | Unexpected zero, overflow indicator |
| Missing call | Expected CPI/external call not happening |
| Extra call | Unexpected delegate/external call |

**Don't skip past the signal.** The error message often contains the exact
root cause — a specific require statement, a computation that produces zero,
or a missing authorization check.

#### 1b. Reproduce Consistently

```
Can you trigger this reliably?
├── YES → Document the exact trigger sequence
│         Minimum: 3 consecutive reproductions
└── NO  → Gather more data before proceeding
          • Is it timing-dependent? (block.timestamp, slot)
          • Is it state-dependent? (specific balances, positions)
          • Is it ordering-dependent? (tx ordering, MEV)
```

#### 1c. Check Recent Context

What makes this code different from similar safe patterns?

- Compare with audited implementations of the same pattern
- Check the protocol's own documentation for intended behavior
- Review related functions that DON'T have this issue — why not?

#### 1d. Trace the Data Flow (Critical)

For every suspected vulnerability, trace the bad value backward:

```
WHERE does the bad value appear?
  ├── In a state variable → WHO wrote this value? WHEN?
  ├── In a function return → WHAT computation produced it?
  ├── In a function parameter → WHO called this? WITH WHAT?
  └── In an external call result → WHICH contract? WHAT state?

Keep tracing backward until you find the SOURCE.
The source is the root cause. Everything else is symptoms.
```

**Example: Price Manipulation Trace**

```
Symptom: User borrows more than collateral value allows

← borrow() uses getPrice() for collateral valuation
  ← getPrice() reads from oracle contract
    ← oracle returns spot price from pool.getReserves()
      ← pool reserves were manipulated by flash loan
        ← ROOT CAUSE: Using spot price instead of TWAP

The finding is NOT "user can over-borrow"
The finding IS "oracle uses spot price without TWAP protection"
```

**Example: Reentrancy Trace**

```
Symptom: Attacker drained funds through repeated withdraw()

← withdraw() sends ETH before updating balance
  ← Balance update at L52, ETH transfer at L48
    ← CEI pattern violated: effect before interaction
      ← BUT there's a nonReentrant guard... checking...
        ← Guard is on deposit(), NOT on withdraw()
          ← ROOT CAUSE: Missing reentrancy guard on withdraw()

The finding is NOT "reentrancy in withdraw"
The finding IS "nonReentrant modifier missing on withdraw() 
  (present on deposit() but not consistently applied)"
```

### Phase 2: Pattern Analysis

**Find the pattern before classifying:**

#### 2a. Find Similar Code

Search the codebase for the same pattern:
- Same function name in different contracts
- Same math operation with different inputs
- Same access control pattern elsewhere

**Key question**: Is this a one-off issue or a systemic pattern?

| Finding | Systemic? | Impact |
|---------|-----------|--------|
| Missing check in one function | No | Single finding |
| Missing check in all withdraw functions | Yes | Higher severity, one finding with multiple locations |
| Missing check in a shared library | Yes | Critical, affects all consumers |

#### 2b. Compare Against Known Vulnerabilities

Cross-reference with known attack patterns:
- Does this match a known exploit? (check XREF.md)
- Is there a published advisory for this pattern?
- Has this protocol type been exploited before?

#### 2c. Identify the Trust Boundary Violation

Every vulnerability violates a trust boundary:

| Trust Boundary | Violation Example |
|----------------|-------------------|
| User → Contract | Missing input validation |
| Contract → Oracle | No price validation |
| Contract → Contract | Missing CPI verification |
| Admin → Protocol | No timelock on admin |
| L1 → L2 | Missing message verification |

**Name the violated boundary.** This becomes the finding category.

### Phase 3: Hypothesis and Testing

**Scientific method — one variable at a time:**

#### 3a. Form Single Hypothesis

```
"I think the root cause is X because:
1. The data flow trace shows Y
2. The pattern analysis shows Z
3. The trust boundary violated is W"
```

Write it down. Be specific, not vague.

#### 3b. Test Minimally

Design the SMALLEST possible test that confirms or denies the hypothesis:

```solidity
// HYPOTHESIS: Missing access control on withdraw()
// TEST: Non-depositor can withdraw another user's funds

function test_hypothesis_unauthorized_withdraw() public {
    // Setup: Alice deposits
    vm.prank(alice);
    vault.deposit(1000e6);
    
    // Test: Bob (non-depositor) tries to withdraw Alice's funds
    vm.prank(bob);
    vault.withdraw(1000e6);
    
    // If this line executes (no revert), hypothesis confirmed
    assertEq(usdc.balanceOf(bob), 1000e6, "Unauthorized withdrawal succeeded");
}
```

#### 3c. Interpret Results

| Result | Action |
|--------|--------|
| Test confirms hypothesis | Proceed to Phase 4 |
| Test denies hypothesis | Form NEW hypothesis from new data |
| Test is inconclusive | Gather more data, don't guess |

#### 3d. When 3+ Hypotheses Fail

```
STOP. If the first 3 hypotheses were wrong:
├── The mental model of the code is wrong
├── Re-read the ENTIRE function, not just the suspicious part
├── Check inherited contracts, libraries, interfaces
├── The vulnerability might be in the INTERACTION, not the code
└── Consider: Is this actually safe and I'm looking for ghosts?
```

### Phase 4: Classification

**ONLY after root cause is confirmed:**

#### 4a. Write the Root Cause Statement

One sentence that captures the fundamental issue:

| Bad | Good |
|-----|------|
| "Reentrancy vulnerability" | "withdraw() performs ETH transfer (L48) before balance update (L52), and lacks nonReentrant modifier" |
| "Oracle manipulation" | "getPrice() reads spot reserves via pool.getReserves() without TWAP, allowing single-block manipulation" |
| "Access control issue" | "setFeeRecipient() has no onlyOwner modifier, allowing any address to redirect protocol fees" |

#### 4b. Classify with Evidence

| Field | Requirement |
|-------|-------------|
| Root Cause | One-sentence fundamental issue |
| Attack Path | Step-by-step exploitation (from Phase 1d) |
| Impact | Measured, not estimated (from PoC) |
| Likelihood | Based on preconditions, not intuition |
| Severity | Derived from Impact × Likelihood matrix |

#### 4c. Check for Deduplication

Before writing the finding, check if the root cause is shared:

```
Same root cause → ONE finding (list all affected locations)
Different root causes, same symptom → SEPARATE findings
Same root cause, different contracts → ONE finding (systemic)
```

## Multi-Component System Analysis

When the vulnerability spans multiple contracts or layers:

```
For EACH component boundary:
  1. What data enters this component?
  2. What validation does this component perform?
  3. What data exits this component?
  4. WHERE does validation fail?

Run a trace showing data at each boundary.
THEN identify which component is responsible.
```

**Example: Lending Protocol**

```
User → Router → LendingPool → Oracle → PriceAggregator

Data at each boundary:
  User → Router: collateral address, amount
  Router → Pool: validated collateral, amount
  Pool → Oracle: collateral address (query)
  Oracle → Aggregator: token pair (query)
  
  Aggregator returns: stale price (24h old)
  Oracle passes through: stale price (no staleness check!)
  Pool uses: stale price for LTV calculation
  
  ROOT CAUSE: Oracle contract has no staleness check
  NOT: "LendingPool uses stale prices"
```

## Architecture-Level Root Cause

When 3+ individual fixes fail, the root cause may be architectural:

**Signals of architectural root cause**:
- Each fix reveals new problems elsewhere
- Fixes require "massive refactoring"
- The same pattern keeps appearing in different forms
- State coupling between components prevents isolation

**Response**: Document the architectural issue as a finding separate
from the individual symptoms. Recommend architectural refactoring,
not point fixes.

## Security Review Checklist

- [ ] Every finding traces data flow backward to root cause
- [ ] Root cause is a one-sentence fundamental issue (not a symptom)
- [ ] Similar code elsewhere has been checked (systemic analysis)
- [ ] Trust boundary violation is named
- [ ] Hypothesis was tested with minimal PoC
- [ ] Deduplication check performed against other findings
- [ ] Multi-component boundaries were traced
- [ ] Architecture-level issues flagged separately from symptoms

## Cross-References

- [verification-discipline.md](verification-discipline.md) — Evidence requirements for each severity level
- [poc-writing-guide.md](poc-writing-guide.md) — How to write the PoC that tests the hypothesis
- [exploit-case-studies.md](exploit-case-studies.md) — Real-world root cause examples

## Sources

- Superpowers: systematic-debugging skill (adapted for security auditing)
- Trail of Bits: Root cause analysis methodology
- Consensys Diligence: Finding deduplication guidelines
