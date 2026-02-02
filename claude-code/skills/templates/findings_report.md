# Findings Report: [Protocol Name]

<!--
  WHAT: Live document tracking all discovered vulnerabilities.
  WHY: Findings get lost in context resets. This file persists them.
  WHEN: Update IMMEDIATELY after discovering ANY suspicious code.
  
  THE 2-CONTRACT RULE:
  After reviewing 2 contracts or 2 major functions, IMMEDIATELY update this file.
  This prevents discoveries from being lost when context resets.
-->

## Summary

| Severity | Count | Status |
|----------|-------|--------|
| [C] Critical | 0 | |
| [H] High | 0 | |
| [M] Medium | 0 | |
| [L] Low | 0 | |
| [I] Informational | 0 | |
| [G] Gas | 0 | |

**Total Findings:** 0  
**Total Estimated Loss:** $0

---

## Findings

<!--
  Add each finding as it's discovered.
  Don't wait until the end - update this file continuously.
-->

### [H-01] [Title]

| Field | Value |
|-------|-------|
| **Severity** | [H] High |
| **Status** | Confirmed / Unconfirmed / Fixed / Won't Fix |
| **Contract** | [Contract.sol] |
| **Function** | [functionName()] |
| **Line** | [Line number] |
| **Attack Tree** | [Branch reference, e.g., A2: Flash Loan + Spot Price] |
| **Estimated Loss** | $XXX |
| **CVSS Score** | X.X |

#### Description

<!--
  Clear, concise description of the vulnerability.
  Focus on: What's wrong? Why is it dangerous?
-->
[Description of the vulnerability]

#### Vulnerable Code

```solidity
// Location: contracts/Contract.sol:L123
function vulnerableFunction() external {
    // [VULNERABLE]: [explain why]
    ...
}
```

#### Impact

<!--
  What can an attacker achieve?
  Quantify: How much can be stolen/lost?
-->
- [Impact 1]
- [Impact 2]
- **Maximum Loss:** $XXX

#### Root Cause

<!--
  WHY does this vulnerability exist?
  Reference anti-patterns if applicable.
-->
- [Root cause analysis]
- **Anti-Pattern:** [anti-patterns/xxx-anti-patterns.md #X]

#### Proof of Concept

```solidity
// test/PoC.t.sol
function testExploit() public {
    // 1. Setup
    ...
    
    // 2. Attack
    ...
    
    // 3. Verify profit
    assertGt(attacker.balance, initialBalance);
}
```

**PoC Result:**
- Initial balance: X
- Final balance: Y
- Profit: Z

#### Recommendation

```solidity
// [FIXED]: [explain the fix]
function fixedFunction() external {
    ...
}
```

#### References

- Similar exploit: [exploit-forensics/xxx.md]
- Pattern: [patterns/xxx-patterns.md]

---

### [M-01] [Title]

| Field | Value |
|-------|-------|
| **Severity** | [M] Medium |
| **Status** | Confirmed / Unconfirmed / Fixed / Won't Fix |
| **Contract** | [Contract.sol] |
| **Function** | [functionName()] |
| **Line** | [Line number] |

#### Description
[Description]

#### Impact
[Impact]

#### Recommendation
[Recommendation]

---

## Suspicious Code (Needs Investigation)

<!--
  Code that looks suspicious but needs more analysis.
  Move to Findings section once confirmed.
-->

| Contract | Function | Line | Suspicion | Status |
|----------|----------|------|-----------|--------|
| | | | | Investigating / Dismissed / Promoted to Finding |

---

## Dismissed Findings

<!--
  Findings that were investigated but turned out to be non-issues.
  Keep for documentation - shows audit thoroughness.
-->

### [D-01] [Title]

**Reason for Dismissal:** [Why this isn't actually a vulnerability]

---

## Notes for Report

<!--
  Additional observations that don't fit in findings.
  Positive observations, architecture concerns, etc.
-->

### Positive Observations
- [Things done well]

### Architecture Concerns
- [Concerns that aren't vulnerabilities but worth noting]

### Centralization Risks
- [Admin privileges, multisig concerns, etc.]

---

## Severity Definitions

| Severity | Definition | Examples |
|----------|------------|----------|
| [C] Critical | Direct fund loss, no user interaction | Oracle manipulation, infinite mint |
| [H] High | Fund loss with conditions | Reentrancy, access control bypass |
| [M] Medium | Limited fund loss or DoS | Griefing, temporary DoS |
| [L] Low | Minor impact | Edge cases, unlikely scenarios |
| [I] Info | Best practices | Code quality, documentation |
| [G] Gas | Gas optimization | Loop optimization, storage packing |

---

## CVSS Calculator Reference

**Base Score Components:**
- Attack Vector (AV): Network (N) / Adjacent (A) / Local (L) / Physical (P)
- Attack Complexity (AC): Low (L) / High (H)
- Privileges Required (PR): None (N) / Low (L) / High (H)
- User Interaction (UI): None (N) / Required (R)
- Scope (S): Unchanged (U) / Changed (C)
- Impact: Confidentiality, Integrity, Availability (None/Low/High)

---

*THE 2-CONTRACT RULE: After reviewing 2 contracts, update this file.*
*Never lose a finding to context reset.*
