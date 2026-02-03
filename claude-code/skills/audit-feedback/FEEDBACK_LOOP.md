# Audit Feedback Loop Methodology

## Overview

The Textual Gradient System captures audit misses and generates improved prompts, patterns, and checklists. This creates a self-improving audit knowledge base.

---

## Core Concept: Textual Gradients

In machine learning, gradients tell you how to adjust weights to reduce error. **Textual gradients** are natural language critiques that tell you how to adjust audit prompts to reduce missed vulnerabilities.

```
MISS → ANALYZE → CRITIQUE → IMPROVE → VALIDATE
```

---

## The Feedback Loop Process

### Step 1: Detect the Miss

When a vulnerability is missed during audit but discovered later (by another auditor, exploit, or review):

```yaml
miss_detected:
  vulnerability_type: "Read-only reentrancy"
  severity: "HIGH"
  contract: "LPVault.sol"
  discovery_source: "Post-audit exploit"
  original_audit_date: "2026-01-15"
```

### Step 2: Analyze the Miss

Ask these questions:

| Question | Answer Template |
|----------|-----------------|
| What pattern file should have caught this? | `patterns/reentrancy-patterns.md` |
| Was the attack vector documented? | Yes / No / Partially |
| What code signal was present? | `view function + external call` |
| Why was it missed? | `Read-only variant not in checklist` |
| What trigger would have loaded the right context? | `ERC4626 + view function` |

### Step 3: Compute Textual Gradient (Critique)

Write a precise critique of what went wrong:

```markdown
## Textual Gradient: Read-Only Reentrancy Miss

**Critique:**
"The auditor checked for classic reentrancy (state update after external call)
but did not check for read-only reentrancy where view functions return
inconsistent state during a transaction. The pattern file mentioned this
variant but it was not in the quick-check list."

**Signal Missed:**
- View function `getSharePrice()` callable externally
- Another protocol integrates and calls this during state transition
- Share price calculation uses `totalSupply` which changes mid-transaction

**Root Cause:**
Read-only reentrancy was documented in patterns but:
1. Not in TRIGGERS.md for auto-loading
2. Not in the attack tree quick-check section
3. No explicit checklist item for view functions
```

### Step 4: Apply Edit (Improve)

Generate specific improvements:

```markdown
## Applied Edits

### Edit 1: Update Attack Tree
File: `attack-trees/lending-attack-tree.md`
Location: Branch [D] Reentrancy
Add:
- [ ] D4: Read-only reentrancy
  - [ ] View functions callable by external protocols
  - [ ] State reads during external calls
  - [ ] Price/share functions mid-transaction

### Edit 2: Update Triggers
File: `TRIGGERS.md`
Add:
| ERC4626 vault | vault-context.md, read-only-reentrancy.md |

### Edit 3: Update Anti-Pattern
File: `anti-patterns/reentrancy-anti-patterns.md`
Add: New Anti-Pattern #8: Read-Only Reentrancy

### Edit 4: Update Checklist
File: `checklists/comprehensive-checklist.md`
Add: [ ] View functions protected during state transitions
```

### Step 5: Validate Improvement

Re-run the original audit with updated patterns:

```yaml
validation:
  original_detection: false
  post_edit_detection: true
  false_positive_introduced: false
  improvement_confirmed: true
```

---

## Gradient Template Structure

Each gradient template follows this format:

```markdown
# Gradient: [Vulnerability Type]

## Detection Signal
What code patterns indicate this vulnerability

## Common Miss Reasons
Why auditors typically miss this

## Critique Template
Standard critique format for this miss type

## Edit Targets
Which files to update

## Validation Query
How to verify the improvement works
```

---

## Directory Structure

```
audit-feedback/
├── FEEDBACK_LOOP.md          # This methodology guide
├── gradient-templates/        # Templates for specific miss types
│   ├── missed-reentrancy.md
│   ├── missed-oracle-manipulation.md
│   ├── missed-access-control.md
│   ├── missed-precision-loss.md
│   └── missed-dos.md
├── apply-edit-templates/      # Templates for applying fixes
│   ├── checklist-expansion.md
│   ├── pattern-addition.md
│   ├── trigger-update.md
│   └── attack-tree-branch.md
└── gradients/                 # Actual computed gradients (examples)
    ├── GRAD-001-readonly-reentry.md
    └── GRAD-002-l2-sequencer.md
```

---

## Using Gradients in Practice

### When You Miss Something

```markdown
1. Load: skills/audit-feedback/FEEDBACK_LOOP.md
2. Select gradient template for vulnerability type
3. Fill in the analysis
4. Generate edits
5. Apply edits to repo
6. Validate with test case
```

### When You Find a New Pattern

```markdown
1. Document the pattern discovery
2. Create gradient showing what WOULD have been missed
3. Generate preventive edits
4. Add to patterns before it becomes a real miss
```

### Continuous Improvement Cycle

```
Week 1: Audit 5 protocols
Week 2: Review any misses or near-misses
Week 3: Compute gradients for each
Week 4: Apply edits, validate
Repeat...
```

---

## Metrics to Track

| Metric | Target | Measurement |
|--------|--------|-------------|
| Miss rate | <5% | Misses / Total vulnerabilities |
| Gradient → Fix time | <1 week | Days from miss to edit merged |
| Recurrence rate | 0% | Same miss type repeated |
| Pattern coverage | >95% | Known vulns with patterns |

---

## Integration with Other Systems

### → Audit Scoring
Misses reduce audit score; gradients can restore it

### → Audit Traces
Traces help identify WHERE in the process the miss occurred

### → Community Feedback
Gradients can be anonymized and contributed back

### → Prompt Evolution
Gradients feed into prompt improvement beam search

---

## Quick Start

1. **After an audit miss:**
   ```
   Load: gradient-templates/missed-[type].md
   Fill in the template
   Generate edits
   ```

2. **After applying edits:**
   ```
   Load: apply-edit-templates/[edit-type].md
   Apply to relevant files
   Validate improvement
   ```

3. **Track over time:**
   ```
   Maintain gradients/ folder with all computed gradients
   Review monthly for patterns in misses
   ```

---

## Related Files

- [Audit Scoring](../scoring/AUDIT_SCORING.md)
- [Audit Traces](../templates/audit_trace.md)
- [Prompt Evolution](../methodology/prompt-evolution.md)
- [Community Feedback](../community-feedback/COMMUNITY_FEEDBACK.md)
