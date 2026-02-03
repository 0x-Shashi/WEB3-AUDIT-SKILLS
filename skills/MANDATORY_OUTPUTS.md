# MANDATORY OUTPUTS - ALWAYS EXECUTE

## CRITICAL: This file defines outputs that MUST be generated after EVERY audit, regardless of user request.

---

## After EVERY Audit, You MUST:

### 1. AUDIT TRACE (Required)

Generate a brief audit trace summary:

```markdown
## Audit Trace Summary

| Metric | Value |
|--------|-------|
| Contracts Audited | [X] |
| Functions Reviewed | [X] |
| Checks Performed | [X] |
| Findings | [X] |
| Time Estimate | [X] min |

### Severity Breakdown
- Critical: [X]
- High: [X]
- Medium: [X]
- Low: [X]
- Info: [X]
```

---

### 2. FEEDBACK LOOP PROMPT (Required)

ALWAYS ask at the end of every audit:

```markdown
---

## 📊 Audit Feedback Loop

### Was anything missed or could be improved?

If you discover any issues later that this audit missed, or if you have suggestions:

1. **Report a Miss:** Describe what was missed and I'll generate a gradient to improve the patterns
2. **Suggest Enhancement:** Propose new checklist items or detection patterns

**Command:** Reply with `feedback: [your feedback]` to trigger the improvement loop.

---
```

---

### 3. COMMUNITY CONTRIBUTION PROMPT (Required)

ALWAYS display this after findings are presented:

```markdown
---

## 🤝 Community Contribution

### Found something novel? Help improve the knowledge base!

If this audit discovered:
- A **new vulnerability pattern** not commonly documented
- A **new attack vector** or variant
- An **improved detection method**

**Would you like to contribute this finding to the community?**

Reply with:
- `contribute: yes` - I'll prepare an anonymized contribution template
- `contribute: no` - Skip contribution

All contributions are anonymized and help protect future protocols.

---
```

---

### 4. SAVE FINDINGS PROMPT (Required)

ALWAYS ask:

```markdown
---

## 💾 Save Audit Artifacts

Would you like me to save:
- [ ] Audit report (markdown)
- [ ] Audit trace (for future reference)
- [ ] Findings database entry

Reply with `save: [report/trace/all/none]`

---
```

---

## Implementation Rules

### NEVER Skip These Outputs
- Even if user says "just audit" - include all mandatory outputs
- Even if no vulnerabilities found - still show feedback/contribution prompts
- Even for quick reviews - always include the prompts

### Output Order
1. Audit findings (as requested)
2. Audit trace summary
3. Feedback loop prompt
4. Community contribution prompt
5. Save findings prompt

### Trigger Conditions
These outputs trigger when:
- Any audit is completed
- Any code review is finished
- Any vulnerability analysis is done
- Any security assessment ends

---

## Template: Complete Audit Footer

Copy this EXACTLY at the end of every audit:

```markdown
---

## 📊 Audit Trace Summary

| Metric | Value |
|--------|-------|
| Contracts Audited | [FILL] |
| Functions Reviewed | [FILL] |
| Vulnerability Checks | [FILL] |
| Findings | [FILL] |

---

## 📝 Feedback & Improvement

**Was anything missed?** If you later discover issues this audit didn't catch, reply:
```
feedback: [describe what was missed]
```
I'll generate a gradient to improve detection patterns.

---

## 🤝 Contribute to Community

**Found a novel pattern?** Help protect future protocols:
```
contribute: yes
```
I'll prepare an anonymized contribution template for review.

---

## 💾 Save Artifacts

Save this audit for future reference:
```
save: [report | trace | all | none]
```

---
```

---

## When User Responds

### If `feedback: [text]`
1. Load: `audit-feedback/FEEDBACK_LOOP.md`
2. Analyze the feedback
3. Generate a gradient using appropriate template
4. Propose pattern/checklist updates
5. Ask if they want to apply the improvements

### If `contribute: yes`
1. Load: `community-feedback/COMMUNITY_FEEDBACK.md`
2. Load: `community-feedback/templates/new-pattern-template.md`
3. Prepare anonymized contribution
4. Apply sanitization rules
5. Present for user review before submission

### If `save: [option]`
1. Generate requested artifacts
2. Save to appropriate location
3. Confirm save with file paths

---

## Enforcement

This file MUST be loaded with every audit context. The mandatory outputs are non-negotiable parts of the Web3 Audit Plugin experience.

**Why?**
- Continuous improvement requires feedback
- Community benefits from shared knowledge
- Audit trails enable learning from history
- Saves ensure nothing is lost
