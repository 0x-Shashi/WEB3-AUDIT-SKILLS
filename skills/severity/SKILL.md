# Severity Classification

## Purpose

This directory provides data-driven severity classification for smart contract audit findings. Each file contains statistical breakdowns of real vulnerability types at that severity level, plus 30 representative examples from top audit firms (Code4rena, Cyfrin, Spearbit, Pashov, MixBytes, Shieldify, OtterSec, Quantstamp).

## Severity Levels

| Level | File | Finding Count | % of All | Scoring Weight |
|-------|------|---------------|----------|----------------|
| HIGH | [high-severity.md](high-severity.md) | 8,022 | 15.88% | 5 points |
| MEDIUM | [medium-severity.md](medium-severity.md) | 13,814 | 27.34% | 2 points |
| LOW | [low-severity.md](low-severity.md) | 25,272 | 50.01% | 1 point |
| GAS | [gas-optimizations.md](gas-optimizations.md) | 3,422 | 6.77% | 0 points |

> Scoring weights reference the [Audit Scoring System](../scoring/AUDIT_SCORING.md) efficiency metric.

## How to Use

1. **Classifying a finding** → Use the [Severity Scoring Decision Tree](../patterns/severity-scoring.md) to determine the correct level
2. **Validating severity** → Compare your finding against the top vulnerability types table in each file
3. **Writing the report** → Reference representative examples for formatting and depth expectations
4. **Scoring the audit** → Apply severity weights from [AUDIT_SCORING.md](../scoring/AUDIT_SCORING.md) to calculate composite scores

## Quick Severity Decision Tree

```
Is there direct fund loss possible?
├── YES → Is it unconditional (anyone can exploit)?
│   ├── YES → CRITICAL (not in this dataset — escalate)
│   └── NO (needs conditions) → HIGH
└── NO → Is there indirect fund loss or protocol damage?
    ├── YES → Is the attack practical?
    │   ├── YES → HIGH
    │   └── NO (theoretical) → MEDIUM
    └── NO → Is there any functional impact?
        ├── YES → LOW
        └── NO → GAS / INFORMATIONAL
```

> Full decision tree with scoring matrix: [patterns/severity-scoring.md](../patterns/severity-scoring.md)

## Cross-Severity Vulnerability Migration

Some vulnerability types appear across multiple severity levels depending on conditions. Key crossovers:

| Vulnerability Type | HIGH Count | MEDIUM Count | LOW Count | Notes |
|---|---|---|---|---|
| Business Logic | 100 | 127 | 7 | Most common at every level |
| Validation | 52 | 75 | — | Severity depends on what's unvalidated |
| Reentrancy | 39 | 20 | — | HIGH when funds at risk, MEDIUM when state-only |
| Oracle | 24 | 34 | — | HIGH for price manipulation, MEDIUM for staleness |
| Access Control | 27 | 19 | 2 | HIGH for privilege escalation, LOW for missing events |
| Front-Running | 39 | 67 | — | MEDIUM unless sandwich causes fund loss |
| DOS | 23 | 43 | — | HIGH for permanent, MEDIUM for temporary |
| Overflow/Underflow | 21 | 22 | — | Severity = magnitude of miscalculation |

## Related Skills

- [Audit Scoring System](../scoring/AUDIT_SCORING.md) — Composite scoring using severity weights
- [Severity Scoring Decision Tree](../patterns/severity-scoring.md) — AI-optimized classification guide
- [Audit Report Templates](../methodology/audit-report-templates.md) — How to write findings at each severity
- [PoC Writing Guide](../methodology/poc-writing-guide.md) — Proving exploitability strengthens severity claims
- [Checklists](../checklists/) — Protocol-specific vulnerability checklists
