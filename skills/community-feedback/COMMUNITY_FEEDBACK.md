# Community Feedback Loop System

## Overview

The Community Feedback Loop enables crowdsourced improvement of audit patterns, checklists, and techniques. Auditors contribute anonymized learnings that benefit the entire community.

---

## Core Concept: Collective Intelligence

```
INDIVIDUAL DISCOVERY → ANONYMIZE → CONTRIBUTE → REVIEW → MERGE → COLLECTIVE BENEFIT
```

One auditor's discovery becomes everyone's defense.

---

## Contribution Types

### 1. New Pattern Discovery

When you discover a vulnerability pattern not in the knowledge base:

```yaml
contribution_type: NEW_PATTERN
category: reentrancy | oracle | access_control | ...
severity: CRITICAL | HIGH | MEDIUM | LOW
source: audit_engagement | research | exploit_analysis
anonymized: true
```

### 2. Pattern Enhancement

When an existing pattern needs improvement:

```yaml
contribution_type: PATTERN_ENHANCEMENT
target_pattern: patterns/reentrancy-patterns.md
enhancement_type: new_variant | better_detection | clearer_example
```

### 3. Checklist Addition

When a new checklist item should be added:

```yaml
contribution_type: CHECKLIST_ADDITION
target_checklist: checklists/comprehensive-checklist.md
section: reentrancy | oracle | access_control | ...
```

### 4. Anti-Pattern Contribution

Real-world vulnerable code examples:

```yaml
contribution_type: ANTI_PATTERN
vulnerability_class: [class]
code_sanitized: true
exploit_reproducible: false  # Never contribute exploitable code
```

### 5. Gradient Contribution

Share learning from misses (anonymized):

```yaml
contribution_type: GRADIENT
miss_type: [vulnerability class]
gradient_template_used: gradient-templates/[template].md
outcome: pattern_improved | checklist_updated | trigger_added
```

---

## Contribution Workflow

### Step 1: Prepare Contribution

```markdown
## Pre-Contribution Checklist

- [ ] Discovery is novel (not already in knowledge base)
- [ ] Code examples are sanitized
- [ ] No protocol-specific identifiers
- [ ] No private information
- [ ] Technically accurate
- [ ] Includes detection method
- [ ] Includes remediation
```

### Step 2: Use Contribution Template

Select appropriate template from `templates/`:
- `new-pattern-template.md`
- `pattern-enhancement-template.md`
- `checklist-addition-template.md`
- `anti-pattern-template.md`
- `gradient-template.md`

### Step 3: Sanitize Content

```markdown
## Sanitization Rules

### MUST Remove:
- Protocol names
- Contract addresses
- Developer names
- Audit client information
- Specific token names
- Transaction hashes
- Private keys/seeds (obviously)
- Internal communication references

### MUST Anonymize:
- Contract names → "TargetContract", "VulnerableContract"
- Function names → Keep if generic, anonymize if unique
- Variable names → Keep if generic, anonymize if unique
- Token names → "TokenA", "RewardToken"
- Protocol references → "Protocol X", "Lending Protocol"

### CAN Keep:
- Standard interface names (ERC20, ERC721)
- Common library references (OpenZeppelin)
- Generic patterns and logic
- Vulnerability mechanics
```

### Step 4: Submit for Review

```markdown
## Submission Format

**Contribution Type:** [type]
**Category:** [category]
**Severity:** [severity]

### Content
[Sanitized contribution content]

### Detection Method
[How to detect this]

### Remediation
[How to fix this]

### Verification
- [ ] I have sanitized all identifying information
- [ ] This contribution is technically accurate
- [ ] I have the right to contribute this knowledge
```

### Step 5: Community Review

Contributions go through peer review:

```markdown
## Review Criteria

| Criterion | Weight | Reviewer Notes |
|-----------|--------|----------------|
| Novelty | 25% | Is this new knowledge? |
| Accuracy | 30% | Is it technically correct? |
| Clarity | 20% | Is it well explained? |
| Actionable | 15% | Can auditors use this? |
| Sanitized | 10% | Is it properly anonymized? |

**Approval Threshold:** 70% score from 2+ reviewers
```

### Step 6: Merge and Distribute

Approved contributions are:
1. Merged into master knowledge base
2. Distributed to all platform versions
3. Credited (if contributor opts in)

---

## Contribution Templates

### New Pattern Template

```markdown
# New Pattern Contribution

## Pattern Name
[Descriptive name]

## Vulnerability Class
[reentrancy | oracle | access_control | ...]

## Severity
[CRITICAL | HIGH | MEDIUM | LOW]

## Description
[What is this vulnerability?]

## Detection Signals
[What code patterns indicate this?]

## Vulnerable Code Example
```solidity
// [VULNERABLE] - Sanitized example
contract VulnerableContract {
    // ...
}
```

## Why It's Vulnerable
[Explanation]

## Secure Code Example
```solidity
// [SAFE] - Fixed version
contract SecureContract {
    // ...
}
```

## Detection Query
[How to search for this in a codebase]

## Discovery Context
[How was this discovered? Research/audit/exploit analysis]
No protocol-specific details.

## Contributor
[Optional: Name/handle for credit]
[Optional: Anonymous]
```

### Checklist Addition Template

```markdown
# Checklist Addition Contribution

## Target Checklist
[checklists/comprehensive-checklist.md]

## Section
[reentrancy | oracle | access_control | ...]

## New Item(s)
```markdown
- [ ] [New checklist item]
  - [ ] [Sub-item if needed]
```

## Rationale
[Why is this item needed?]

## Detection Example
[Code example that this item would catch]

## False Positive Consideration
[What might this incorrectly flag?]

## Contributor
[Optional]
```

### Gradient Contribution Template

```markdown
# Gradient Contribution

## Miss Type
[Vulnerability class that was missed]

## Gradient Summary
[Brief description of what went wrong]

## Analysis (Sanitized)
- **What was missed:** [Description]
- **Why it was missed:** [Root cause]
- **What pattern/checklist gap existed:** [Gap identified]

## Applied Fix
[What was added/updated to prevent future misses]

## Validation
[How was the fix validated?]

## Contributor
[Optional]
```

---

## Quality Standards

### Content Quality

```markdown
## Quality Checklist

### Technical Accuracy
- [ ] Code compiles (if applicable)
- [ ] Vulnerability is reproducible (conceptually)
- [ ] Fix actually resolves the issue
- [ ] No false information

### Clarity
- [ ] Clear title and description
- [ ] Well-formatted code examples
- [ ] Step-by-step detection method
- [ ] Actionable remediation

### Sanitization
- [ ] No identifying information
- [ ] Generic naming conventions
- [ ] No exploitable specifics
```

### Review Standards

```markdown
## Reviewer Guidelines

### Accept If:
- Novel and useful contribution
- Technically accurate
- Properly sanitized
- Clear and actionable

### Request Changes If:
- Minor accuracy issues
- Needs better sanitization
- Unclear explanation
- Missing detection method

### Reject If:
- Duplicate of existing content
- Technically incorrect
- Contains identifying information
- Not actionable
```

---

## Contribution Recognition

### Contribution Points

```yaml
points_system:
  new_pattern_merged: 50 points
  pattern_enhancement_merged: 25 points
  checklist_addition_merged: 15 points
  anti_pattern_merged: 20 points
  gradient_merged: 30 points
  review_performed: 5 points
```

### Recognition Levels

| Level | Points | Recognition |
|-------|--------|-------------|
| Contributor | 0+ | Listed in contributors |
| Bronze | 100+ | Badge + mentions |
| Silver | 300+ | Badge + profile feature |
| Gold | 500+ | Badge + advisory input |
| Diamond | 1000+ | Core contributor status |

### Leaderboard (Optional)

```markdown
## Monthly Leaderboard

| Rank | Contributor | Points | Top Contribution |
|------|-------------|--------|------------------|
| 1 | @auditor_a | 85 | Novel L2 oracle pattern |
| 2 | @auditor_b | 60 | 3 checklist additions |
| 3 | @auditor_c | 45 | Gradient contribution |
```

---

## Integration with Other Systems

### ← From Feedback Loop
```
Gradient computed → 
If novel and valuable → 
Prepare contribution → 
Community review
```

### ← From Audit Traces
```
Trace reveals new detection method →
Document as pattern →
Contribute to community
```

### → To Pattern Files
```
Approved contribution →
Merge to patterns/ →
Sync to all platforms
```

### → To Checklists
```
Approved checklist item →
Add to relevant checklists →
Update INDEX.md
```

---

## Feedback Integration

### Receiving Feedback

```markdown
## When Using Community Contributions

If you find issues with community-contributed content:

1. Document the issue
2. Submit enhancement contribution
3. Reference original contribution

This creates a continuous improvement loop.
```

### Giving Feedback

```markdown
## Reviewing Contributions

Be constructive:
- Point out specific issues
- Suggest improvements
- Acknowledge good aspects
- Help contributors improve
```

---

## Directory Structure

```
community-feedback/
├── COMMUNITY_FEEDBACK.md        # This guide
├── templates/
│   ├── new-pattern-template.md
│   ├── pattern-enhancement-template.md
│   ├── checklist-addition-template.md
│   ├── anti-pattern-template.md
│   └── gradient-template.md
├── sanitization-rules.md        # Detailed sanitization guide
├── review-guidelines.md         # Reviewer instructions
└── contributions/               # Pending contributions
    ├── pending/
    ├── under-review/
    └── archived/
```

---

## Quick Start

### To Contribute:
1. Identify valuable discovery
2. Select appropriate template
3. Sanitize all content
4. Fill in template
5. Submit for review

### To Review:
1. Check technical accuracy
2. Verify sanitization
3. Assess clarity and usefulness
4. Provide feedback or approve

### To Use:
1. Browse merged contributions
2. Integrate into your workflow
3. Provide feedback if issues found

---

## Related Files

- [Feedback Loop](../audit-feedback/FEEDBACK_LOOP.md)
- [Pattern Addition Template](../audit-feedback/apply-edit-templates/pattern-addition.md)
- [Checklist Expansion Template](../audit-feedback/apply-edit-templates/checklist-expansion.md)
