# New Pattern Contribution Template

Use this template to contribute a newly discovered vulnerability pattern to the community knowledge base.

---

## Pre-Submission Checklist

Before filling out this template, verify:

- [ ] Pattern is not already in the knowledge base (search first)
- [ ] All code examples are sanitized (no protocol names, addresses, etc.)
- [ ] Pattern is technically accurate and reproducible
- [ ] Detection method is clear and actionable
- [ ] Remediation actually fixes the issue

---

## Contribution Form

### Pattern Information

**Pattern Name:**  
[Descriptive name for the vulnerability pattern]

**Vulnerability Class:**  
[ ] Reentrancy  
[ ] Access Control  
[ ] Oracle Manipulation  
[ ] Flash Loan Attack  
[ ] Precision/Rounding  
[ ] Denial of Service  
[ ] Logic Error  
[ ] Signature/Replay  
[ ] Front-Running/MEV  
[ ] Upgrade/Proxy  
[ ] Cross-Chain  
[ ] Other: ___________

**Severity:**  
[ ] CRITICAL - Direct fund loss, no user interaction needed  
[ ] HIGH - Fund loss possible with conditions  
[ ] MEDIUM - Limited fund loss or protocol disruption  
[ ] LOW - Minor issues, best practice violations

**Discovery Context:**  
[ ] Private audit engagement (anonymized)  
[ ] Public audit/contest  
[ ] Personal research  
[ ] Exploit analysis (post-mortem)  
[ ] Other: ___________

---

### Pattern Description

**Summary:**  
[1-2 sentence description of the vulnerability]

**Detailed Description:**  
[Full explanation of the vulnerability, how it works, and why it's dangerous]

**Attack Scenario:**  
1. [Step 1 of how an attacker would exploit this]
2. [Step 2]
3. [Step 3]
4. [...]

**Prerequisites/Conditions:**  
[What conditions must be true for this vulnerability to be exploitable?]

---

### Code Examples

**Vulnerable Code:**
```solidity
// [VULNERABLE] - Example showing the vulnerability pattern
// Use generic names: VulnerableContract, TargetContract, TokenA, etc.

contract VulnerableContract {
    // [Paste sanitized vulnerable code here]
}
```

**Why It's Vulnerable:**  
[Explain specifically what makes the above code vulnerable]

**Secure Code:**
```solidity
// [SAFE] - Fixed version of the same pattern

contract SecureContract {
    // [Paste sanitized fixed code here]
}
```

**What Changed:**  
[Explain the specific changes that fixed the vulnerability]

---

### Detection

**Code Signals:**  
[What patterns in code indicate this vulnerability might be present?]
- Signal 1: [e.g., "External call before state update"]
- Signal 2: [e.g., "View function reading from state during external call"]
- Signal 3: [...]

**Detection Query:**  
[How would you search for this in a codebase?]
```
[Search pattern or methodology]
```

**Related Patterns to Check:**  
[What other vulnerabilities often appear alongside this one?]
- Related pattern 1
- Related pattern 2

---

### Remediation

**Recommended Fix:**  
[Primary recommended way to fix this vulnerability]

**Alternative Fixes:**  
[Other acceptable ways to address the issue]
1. Alternative 1
2. Alternative 2

**Common Mistakes When Fixing:**  
[What do developers often get wrong when trying to fix this?]

---

### Integration Suggestions

**Suggested Checklist Item:**
```markdown
- [ ] [Checklist item text that would catch this vulnerability]
```

**Suggested Trigger:**  
[What code patterns should trigger loading this pattern?]
```
| [Trigger condition] | [pattern-file.md] |
```

**Related Files to Update:**  
[Which existing files should reference this pattern?]
- [ ] patterns/[category]-patterns.md
- [ ] checklists/comprehensive-checklist.md
- [ ] anti-patterns/[category]-anti-patterns.md
- [ ] Other: ___________

---

### Contributor Information (Optional)

**Contributor:**  
[ ] Anonymous  
[ ] Credit me as: ___________

**Contact (Optional):**  
[For follow-up questions only, not published]

**Additional Notes:**  
[Any other context or information]

---

## Submission

When complete:
1. Verify all sanitization rules followed
2. Save as `contributions/pending/pattern-[name]-[date].md`
3. Submit for community review

---

## Sanitization Reminder

Before submitting, ensure you have removed/anonymized:
- [ ] Protocol/project names
- [ ] Contract addresses
- [ ] Developer/team names
- [ ] Client information
- [ ] Specific token names → use "TokenA", "RewardToken"
- [ ] Protocol references → use "Protocol X", "Lending Protocol"
- [ ] Transaction hashes
- [ ] Any identifying information
