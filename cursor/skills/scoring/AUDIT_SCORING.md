# Audit Scoring System

## Overview

The Audit Scoring System provides objective metrics to measure audit quality, track improvement over time, and identify areas needing attention.

---

## Core Metrics

### 1. Detection Score

Measures how many vulnerabilities were correctly identified.

```
Detection Score = (True Positives) / (True Positives + False Negatives) × 100

Where:
- True Positives = Vulnerabilities you found that were real
- False Negatives = Vulnerabilities you missed (found later)
```

| Score Range | Rating | Interpretation |
|-------------|--------|----------------|
| 95-100% | EXCELLENT | Top-tier detection |
| 85-94% | GOOD | Solid performance |
| 70-84% | ACCEPTABLE | Room for improvement |
| <70% | NEEDS WORK | Significant gaps |

### 2. Precision Score

Measures how many findings were actually valid.

```
Precision Score = (True Positives) / (True Positives + False Positives) × 100

Where:
- True Positives = Valid findings
- False Positives = Invalid findings (contested/rejected)
```

| Score Range | Rating | Interpretation |
|-------------|--------|----------------|
| 90-100% | EXCELLENT | Highly accurate |
| 80-89% | GOOD | Minimal noise |
| 70-79% | ACCEPTABLE | Some false positives |
| <70% | NEEDS WORK | Too many invalid findings |

### 3. Severity Accuracy

Measures if severity ratings were correct.

```
Severity Accuracy = (Correct Severity Ratings) / (Total Findings) × 100
```

| Score Range | Rating |
|-------------|--------|
| 90-100% | EXCELLENT |
| 75-89% | GOOD |
| 60-74% | ACCEPTABLE |
| <60% | NEEDS CALIBRATION |

### 4. Coverage Score

Measures how thoroughly the codebase was reviewed.

```
Coverage Score = (Functions Audited) / (Total Functions) × 100

Additional factors:
- All entry points covered: +10%
- All state-changing functions: +10%
- External dependencies reviewed: +5%
```

### 5. Efficiency Score

Measures time spent vs. findings produced.

```
Efficiency = (Weighted Findings) / (Hours Spent)

Where weighted findings:
- Critical = 10 points
- High = 5 points
- Medium = 2 points
- Low = 1 point
- Informational = 0.5 points
```

---

## Composite Audit Score

The overall audit score combines all metrics:

```
Audit Score = (0.35 × Detection) + (0.25 × Precision) + (0.15 × Severity) 
            + (0.15 × Coverage) + (0.10 × Efficiency)
```

### Score Card Template

```markdown
# Audit Score Card

**Protocol:** [Name]
**Date:** [Date]
**Auditor:** [Name/Team]

## Scores

| Metric | Score | Rating |
|--------|-------|--------|
| Detection | 92% | GOOD |
| Precision | 88% | GOOD |
| Severity Accuracy | 85% | GOOD |
| Coverage | 95% | EXCELLENT |
| Efficiency | 4.2 pts/hr | GOOD |

## Composite Score: **89/100** (GOOD)

## Breakdown

### Findings Summary
| Severity | Found | Confirmed | Accuracy |
|----------|-------|-----------|----------|
| Critical | 1 | 1 | 100% |
| High | 3 | 2 | 67% |
| Medium | 5 | 5 | 100% |
| Low | 4 | 4 | 100% |

### Misses
- 1 Medium missed (oracle manipulation variant)
- Gradient applied: GRAD-015

### False Positives
- 1 High downgraded to informational (design choice)

### Time Allocation
| Phase | Hours | % of Total |
|-------|-------|------------|
| Context | 2 | 10% |
| Review | 14 | 70% |
| Reporting | 4 | 20% |
| **Total** | **20** | **100%** |
```

---

## Reward Schema

### Per-Finding Rewards

Track value delivered per finding:

```yaml
finding_rewards:
  critical_confirmed: 100 points
  critical_contested: 20 points
  high_confirmed: 50 points
  high_contested: 10 points
  medium_confirmed: 20 points
  medium_contested: 5 points
  low_confirmed: 5 points
  low_contested: 1 point
  
penalties:
  false_positive_submitted: -5 points
  miss_discovered_later: -20 points
  severity_overrated: -5 points
  severity_underrated: -10 points
```

### Bonus Multipliers

```yaml
bonuses:
  first_to_find: 1.5x  # If in competitive audit
  novel_attack: 2.0x   # New attack vector
  root_cause_identified: 1.25x  # Found underlying issue
  complete_remediation: 1.1x  # Provided full fix
```

### Score Calculation Example

```markdown
## Audit Reward Calculation

### Findings
| Finding | Severity | Status | Base | Multiplier | Final |
|---------|----------|--------|------|------------|-------|
| F-01 | Critical | Confirmed | 100 | 1.0x | 100 |
| F-02 | High | Confirmed | 50 | 1.5x (first) | 75 |
| F-03 | Medium | Confirmed | 20 | 2.0x (novel) | 40 |
| F-04 | High | Contested | 10 | 1.0x | 10 |
| F-05 | Low | Confirmed | 5 | 1.0x | 5 |

**Subtotal:** 230 points

### Penalties
- 1 false positive: -5
- 1 miss discovered: -20

**Total Penalties:** -25 points

### Final Score: **205 points**
```

---

## Tracking Over Time

### Monthly Score Tracking

```markdown
## Monthly Performance: [Month Year]

| Audit | Detection | Precision | Composite | Points |
|-------|-----------|-----------|-----------|--------|
| Protocol A | 95% | 90% | 91 | 180 |
| Protocol B | 88% | 85% | 85 | 145 |
| Protocol C | 92% | 92% | 90 | 220 |

**Monthly Average:** 89/100
**Total Points:** 545
**Trend:** +5% vs. last month
```

### Improvement Tracking

```markdown
## Improvement Areas

### Weaknesses Identified
| Area | Score | Target | Gap |
|------|-------|--------|-----|
| Oracle checks | 75% | 90% | 15% |
| L2 specifics | 70% | 90% | 20% |
| Access control | 85% | 90% | 5% |

### Actions Taken
- [ ] Added L2 patterns to knowledge base
- [ ] Updated oracle checklist
- [ ] Created gradient for L2 misses

### Next Month Target: 92/100
```

---

## Category-Specific Scores

Track performance by vulnerability category:

```markdown
## Category Performance

| Category | Detection | Precision | Notes |
|----------|-----------|-----------|-------|
| Reentrancy | 95% | 92% | Strong |
| Access Control | 90% | 88% | Good |
| Oracle Issues | 75% | 85% | Needs work |
| Math/Precision | 88% | 80% | False positives |
| Logic Errors | 70% | 90% | Detection gap |
| DoS | 85% | 75% | Over-reporting |

### Priority Improvement Areas
1. Logic Errors (detection)
2. Oracle Issues (detection)
3. DoS (precision)
```

---

## Competitive Audit Scoring

For competitive audits with multiple auditors:

```markdown
## Competitive Audit Score

**Contest:** [Name]
**Your Rank:** [X] of [Y]

### Your Findings vs. Pool
| Severity | Your Finds | Total Pool | Your % |
|----------|------------|------------|--------|
| Critical | 1 | 2 | 50% |
| High | 3 | 8 | 37.5% |
| Medium | 5 | 20 | 25% |

### Unique Findings (yours only)
- F-02: Novel oracle attack (High)
- F-04: Edge case in liquidation (Medium)

### Duplicates
- 4 findings shared with other auditors

### Solo Score: **65%** of total findings
```

---

## Integration with Other Systems

### → Feedback Loop
```
Low detection score in category X
→ Triggers gradient analysis for X
→ Patterns improved
→ Score monitored for improvement
```

### → Audit Traces
```
Trace provides data for scoring:
- Time per phase (efficiency)
- Checks performed (coverage)
- Findings timeline (detection patterns)
```

### → Prompt Evolution
```
Prompts that lead to higher scores:
→ Promoted in evolution
→ Lower-scoring prompts deprecated
```

---

## Score Templates

### Quick Score (After Audit)
```markdown
# Quick Score: [Protocol]

- Detection: [X]%
- Precision: [X]%
- Composite: [X]/100
- Key miss: [if any]
- Action: [gradient to apply]
```

### Full Score Card
```markdown
# Detailed Score Card: [Protocol]
[Full breakdown with all metrics]
```

### Monthly Report
```markdown
# Monthly Performance Report
[Aggregate statistics and trends]
```

---

## Score Improvement Workflow

```
1. After each audit:
   - Calculate scores
   - Identify gaps
   
2. Weekly:
   - Review category scores
   - Identify patterns in misses
   
3. Monthly:
   - Aggregate performance
   - Set improvement targets
   - Update patterns/checklists
   
4. Quarterly:
   - Trend analysis
   - Major pattern updates
   - Knowledge base refinement
```

---

## Benchmarks

Industry benchmarks for self-assessment:

| Metric | Top 10% | Top 25% | Average |
|--------|---------|---------|---------|
| Detection | >95% | >90% | 80% |
| Precision | >92% | >85% | 78% |
| Composite | >90 | >85 | 75 |
| Points/Month | >500 | >300 | 150 |

---

## Related Files

- [Audit Trace](../templates/audit_trace.md)
- [Feedback Loop](../audit-feedback/FEEDBACK_LOOP.md)
- [Prompt Evolution](../methodology/prompt-evolution.md)
