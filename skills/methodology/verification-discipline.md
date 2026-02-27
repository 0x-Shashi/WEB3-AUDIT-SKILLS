---
id: METH-VERIFICATION-DISCIPLINE
title: Audit Verification Discipline
category: methodology
severity: high
chains: [ethereum, solana, cosmos, aptos, sui, starknet, all]
languages: [solidity, rust, move, cairo, typescript]
tags:
  - verification
  - evidence
  - quality-assurance
  - audit-workflow
  - finding-validation
  - claim-verification
  - PoC-validation
last_updated: 2026-02-27
description: >-
  Use when making any claims about vulnerability severity, exploit feasibility,
  code correctness, or fix adequacy — enforces evidence-before-claims discipline
  to prevent hallucinated findings, phantom bugs, and unverified severity ratings.
  Adapted from the verification-before-completion methodology.
---

# Audit Verification Discipline

## Overview

Claiming a vulnerability exists without proof is as dangerous as missing one.
False positives erode trust, waste protocol team time, and dilute real findings.

**Core principle**: Evidence before claims, always.

### The Iron Law

```
NO SEVERITY CLAIMS WITHOUT FRESH VERIFICATION EVIDENCE
```

If you haven't reproduced the exploit in this session, you cannot claim it's exploitable.

## The Gate Function

Before claiming ANY finding status:

```
1. IDENTIFY: What evidence proves this claim?
2. PRODUCE: Generate the evidence (PoC, trace, calculation)
3. VERIFY: Does the evidence confirm the claim?
   - If NO → State actual status with evidence
   - If YES → State claim WITH evidence attached
4. ONLY THEN: Write the finding

Skip any step = unreliable finding
```

## Verification Requirements by Claim Type

| Claim | Required Evidence | NOT Sufficient |
|-------|-------------------|----------------|
| "Critical severity" | PoC showing direct fund loss | "Could potentially drain funds" |
| "High severity" | PoC showing conditional fund loss OR DoS | "Users might lose funds" |
| "Medium severity" | Trace showing state corruption | "This looks wrong" |
| "Exploit is feasible" | Working PoC test | "An attacker could theoretically..." |
| "Fix is correct" | PoC fails after fix applied | "The fix addresses the issue" |
| "No vulnerability exists" | Branch analysis showing safety | "Code looks fine" |
| "Function is unreachable" | Call graph proving no path | "I don't see any callers" |
| "Value can't overflow" | Math proof or fuzzing results | "Values are typically small" |
| "Re-entrancy is safe" | CEI analysis + nonReentrant check | "There's a reentrancy guard" |
| "Oracle is manipulation-resistant" | TWAP analysis + cost calculation | "They use Chainlink" |

## Verification Levels

### Level 1: Assertion (Weakest)

```
"The withdraw function lacks access control."
```

**Strength**: Zero. This is a claim without evidence.

### Level 2: Code Reference

```
"The withdraw function at Vault.sol:L45 has no modifier:
  function withdraw(uint amount) external {
      // no onlyOwner, no access check
```

**Strength**: Low. Shows the code but doesn't prove exploitability.

### Level 3: Logical Trace

```
"At Vault.sol:L45, withdraw() has no access control.
An attacker can call withdraw(victim_balance) because:
1. No msg.sender == depositor check (L45-L52)
2. Balance mapping reads from parameter, not msg.sender (L48)
3. Transfer sends to msg.sender (L51)
Path: attacker.withdraw(1000e18) → balance[victim] read → transfer to attacker"
```

**Strength**: Medium. Shows the attack path but hasn't executed it.

### Level 4: Proof of Concept (Strongest)

```solidity
function test_unauthorized_withdraw() public {
    // Setup: Alice deposits 1000 USDC
    vm.prank(alice);
    vault.deposit(1000e6);
    assertEq(usdc.balanceOf(address(vault)), 1000e6);

    // Attack: Bob withdraws Alice's funds
    vm.prank(bob);
    vault.withdraw(1000e6);  // No revert!

    // Verify: Bob stole Alice's funds
    assertEq(usdc.balanceOf(bob), 1000e6);
    assertEq(usdc.balanceOf(address(vault)), 0);
}
```

**Strength**: Maximum. Executable proof that the vulnerability exists.

### Required Levels by Severity

| Severity | Minimum Level | Preferred Level |
|----------|---------------|-----------------|
| Critical | Level 4 (PoC) | Level 4 with value quantification |
| High | Level 3 (Trace) | Level 4 |
| Medium | Level 3 (Trace) | Level 3 with branch analysis |
| Low | Level 2 (Code Reference) | Level 3 |
| Info | Level 2 (Code Reference) | Level 2 |

## Common Verification Failures

### 1. The Phantom Bug

```
CLAIM: "Re-entrancy vulnerability in withdraw()"
REALITY: Function uses CEI pattern correctly, guard is inherited from base
CAUSE: Auditor saw external call, assumed reentrancy without tracing state updates
```

**Prevention**: Before claiming reentrancy, verify:
- [ ] State update happens AFTER external call (not before)
- [ ] No reentrancy guard exists (check inheritance chain)
- [ ] Re-entrant call can actually modify relevant state
- [ ] Write a PoC that demonstrates state corruption

### 2. The Severity Inflation

```
CLAIM: "Critical — attacker can drain all funds"
REALITY: Attack requires admin key + 7-day timelock + governance vote
CAUSE: Auditor described worst case without checking access control chain
```

**Prevention**: Before claiming Critical:
- [ ] Who can trigger this? (any user vs admin vs governance)
- [ ] What preconditions are needed? (timelock, votes, oracle state)
- [ ] What's the realistic attack cost? (gas, capital, bribes)
- [ ] Is the attack profitable after costs?

### 3. The Fix Assumption

```
CLAIM: "Fix verified — adding nonReentrant modifier resolves the issue"
REALITY: Fix added modifier to wrong function; vulnerable path still exists
CAUSE: Auditor assumed fix location without re-running PoC
```

**Prevention**: After fix is applied:
- [ ] Re-run original PoC — does it NOW fail/revert?
- [ ] Check if fix created new issues (DoS, gas increase, state inconsistency)
- [ ] Verify fix covers ALL vulnerable paths, not just the reported one

### 4. The Theoretical Attack

```
CLAIM: "Flash loan attack can manipulate oracle"
REALITY: Oracle uses TWAP with 30-minute window; manipulation cost exceeds profit
CAUSE: Auditor identified theoretical vector without economic analysis
```

**Prevention**: For economic attacks:
- [ ] Calculate attack capital required
- [ ] Calculate expected profit
- [ ] Account for gas costs, slippage, MEV competition
- [ ] Is profit > cost? By how much?

## Red Flags — STOP and Verify

If you catch yourself thinking:
- "This looks like a vulnerability" → STOP. Prove it IS a vulnerability.
- "Should be exploitable" → STOP. Write the exploit.
- "Probably Critical severity" → STOP. Quantify the impact.
- "Fix looks correct" → STOP. Re-run the PoC against the fix.
- "I'm confident this is right" → Confidence ≠ evidence.
- "Already checked this pattern before" → Check it again for THIS code.
- "Similar to a known bug" → Similar ≠ identical. Verify specifics.

## Rationalization Prevention

| Excuse | Reality |
|--------|---------|
| "PoC would take too long" | PoC is faster than defending a false finding |
| "It's obviously vulnerable" | Obvious bugs have obvious fixes — verify first |
| "Client will understand" | Client trusts you. Don't speculate. |
| "I'll add the PoC later" | Findings without PoC get disputed |
| "The pattern is well-known" | Known pattern ≠ present in THIS code |
| "Other auditors would agree" | Agreement ≠ evidence |
| "Time pressure" | Fast wrong < slow right |

## Verification Workflows

### For New Findings

```
┌──────────────────────┐
│  Spot suspicious code │
├──────────────────────┤
│  Trace the data flow  │ ← Level 3
├──────────────────────┤
│  Can I exploit it?    │
│  ├── YES → Write PoC  │ ← Level 4
│  └── NO → Downgrade   │
│       or discard       │
├──────────────────────┤
│  PoC succeeds?        │
│  ├── YES → Write      │
│  │   finding with PoC │
│  └── NO → Re-analyze  │
│       root cause       │
└──────────────────────┘
```

### For Severity Classification

```
┌──────────────────────────┐
│  Write PoC first          │
├──────────────────────────┤
│  Measure impact:          │
│  • Funds lost? How much?  │
│  • Who is affected?       │
│  • What conditions needed?│
├──────────────────────────┤
│  Apply severity matrix    │
│  with MEASURED values,    │
│  not estimated ones       │
└──────────────────────────┘
```

### For Fix Verification

```
┌──────────────────────────┐
│  1. Run ORIGINAL PoC     │
│     → Must PASS (vuln    │
│       still exists)       │
├──────────────────────────┤
│  2. Apply fix             │
├──────────────────────────┤
│  3. Run ORIGINAL PoC     │
│     → Must FAIL/REVERT   │
│     (vuln is fixed)      │
├──────────────────────────┤
│  4. Run full test suite   │
│     → No regressions     │
├──────────────────────────┤
│  5. Check for new issues  │
│     created by fix        │
└──────────────────────────┘
```

## Integration with Audit Workflow

### Pre-Report Gate

Before adding ANY finding to the report:
- [ ] Evidence level meets minimum for claimed severity
- [ ] PoC is reproducible (not just "worked once")
- [ ] Impact is quantified (not just "funds at risk")
- [ ] Attack prerequisites are documented
- [ ] Fix recommendation has been verified (if provided)

### Finding Review Checklist

| Check | Question |
|-------|----------|
| Evidence | Is there a working PoC or detailed trace? |
| Severity | Is severity justified by measured impact? |
| Feasibility | Is the attack economically rational? |
| Completeness | Are all prerequisites documented? |
| Uniqueness | Is this truly a separate finding (not duplicate)? |
| Actionability | Can the team fix this with the recommendation? |

## Security Review Checklist

- [ ] Every Critical/High finding has a Level 4 PoC
- [ ] Every Medium finding has a Level 3 trace minimum
- [ ] No findings use "could potentially" without evidence
- [ ] Fix recommendations have been verified against PoC
- [ ] Economic attacks include cost-profit analysis
- [ ] Access control assumptions are traced through inheritance
- [ ] Oracle safety claims include manipulation cost analysis

## Cross-References

- [poc-writing-guide.md](poc-writing-guide.md) — PoC format and Foundry test patterns
- [audit-report-templates.md](audit-report-templates.md) — Report structure (uses findings from this discipline)
- [audit-session-management.md](audit-session-management.md) — Session tracking for verification state

## Sources

- Superpowers: verification-before-completion skill (adapted for security auditing)
- Anthropic: "Effective harnesses for long-running agents"
- Trail of Bits: Audit methodology guidelines
- OpenZeppelin: Audit report quality standards
