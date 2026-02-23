# Audit Scoring

## Purpose

This directory provides the quantitative scoring framework for measuring audit quality. Use these metrics to objectively evaluate performance, track improvement over time, and identify areas needing attention.

## Available Files

| File | Description |
|------|-------------|
| [AUDIT_SCORING.md](AUDIT_SCORING.md) | Complete scoring system — detection, precision, severity accuracy, coverage, efficiency metrics, composite score formula, reward schema, tracking templates, and industry benchmarks |

## Core Metrics at a Glance

| Metric | Weight | What It Measures |
|--------|--------|-----------------|
| Detection Score | 35% | Vulnerabilities correctly identified vs. total real vulnerabilities |
| Precision Score | 25% | Valid findings vs. total findings submitted (false positive rate) |
| Severity Accuracy | 15% | Correct severity classification vs. total findings |
| Coverage Score | 15% | Functions/entry points audited vs. total codebase |
| Efficiency Score | 10% | Weighted findings produced per hour spent |

> **Composite Score** = `(0.35 × Detection) + (0.25 × Precision) + (0.15 × Severity) + (0.15 × Coverage) + (0.10 × Efficiency)`

## Severity Weights for Efficiency Scoring

These weights connect the scoring system to the [severity classification](../severity/):

| Severity | Points | Reference |
|----------|--------|-----------|
| Critical | 10 | Escalation required (not in standard severity files) |
| High | 5 | [high-severity.md](../severity/high-severity.md) |
| Medium | 2 | [medium-severity.md](../severity/medium-severity.md) |
| Low | 1 | [low-severity.md](../severity/low-severity.md) |
| Informational | 0.5 | Best-practice suggestions |
| Gas | 0 | [gas-optimizations.md](../severity/gas-optimizations.md) |

## How to Use

1. **After an audit** → Fill out the Score Card Template in [AUDIT_SCORING.md](AUDIT_SCORING.md)
2. **Classify findings** → Use [severity/](../severity/) files + [severity-scoring decision tree](../patterns/severity-scoring.md)
3. **Track monthly** → Use the Monthly Score Tracking template
4. **Identify gaps** → Category-specific scores highlight weak areas
5. **Improve** → Low category scores → update [checklists](../checklists/) and [patterns](../patterns/)

## Related Skills

- [Severity Classification](../severity/) — HIGH / MEDIUM / LOW / GAS finding databases
- [Severity Scoring Decision Tree](../patterns/severity-scoring.md) — How to assign severity levels
- [Feedback Loop](../audit-feedback/FEEDBACK_LOOP.md) — Scores feed back into skill improvement
- [Audit Report Templates](../methodology/audit-report-templates.md) — Report structure with severity sections
- [Prompt Evolution](../methodology/prompt-evolution.md) — Higher-scoring prompts get promoted
