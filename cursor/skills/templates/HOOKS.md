# Hooks System for Audit Workflow

## Overview

The Hooks System provides automation points throughout the audit lifecycle, enabling consistent quality checks, automated actions, and integration with other systems.

---

## Core Concept: Lifecycle Hooks

Hooks are triggered at specific points in the audit workflow:

```
BEFORE_AUDIT → BEFORE_FILE → AFTER_FUNCTION → AFTER_FILE → BEFORE_REPORT → AFTER_AUDIT
```

Each hook can:
- Run validation checks
- Load additional context
- Trigger external actions
- Log to audit trace
- Block progression (if validation fails)

---

## Hook Types

### 1. BEFORE_AUDIT

Triggered when starting a new audit engagement.

```yaml
hook: BEFORE_AUDIT
trigger: Audit initialization
purpose: Setup and context loading

actions:
  - validate_scope_definition
  - load_protocol_patterns
  - initialize_trace
  - check_prerequisites
  
validations:
  - scope_files_exist: BLOCK
  - patterns_loaded: WARN
  - previous_audits_reviewed: WARN
```

**Implementation:**
```markdown
## BEFORE_AUDIT Checklist

Before proceeding, verify:
- [ ] Scope document received and reviewed
- [ ] All in-scope files accessible
- [ ] Protocol type identified
- [ ] Relevant patterns loaded
- [ ] Previous audits/findings reviewed (if any)
- [ ] Audit trace initialized

If any BLOCK validation fails, do not proceed until resolved.
```

### 2. BEFORE_FILE

Triggered before auditing each file.

```yaml
hook: BEFORE_FILE
trigger: Starting file review
purpose: File-specific preparation

actions:
  - identify_file_type
  - load_file_specific_patterns
  - check_dependencies
  - note_external_calls

validations:
  - file_compiles: BLOCK
  - imports_resolved: WARN
```

**Implementation:**
```markdown
## BEFORE_FILE Checklist

For file: [filename]

- [ ] File type identified (Token/Vault/Router/etc.)
- [ ] Inheritance chain traced
- [ ] Imports and dependencies noted
- [ ] File-specific patterns loaded
- [ ] Entry points identified
- [ ] State variables catalogued
```

### 3. AFTER_FUNCTION

Triggered after reviewing each function.

```yaml
hook: AFTER_FUNCTION
trigger: Completed function review
purpose: Function-level validation

actions:
  - log_checks_performed
  - record_findings
  - update_trace
  - check_coverage

validations:
  - all_checks_performed: WARN
  - findings_documented: BLOCK
```

**Implementation:**
```markdown
## AFTER_FUNCTION Record

Function: [name]
Visibility: [external/public/internal/private]

Checks Performed:
- [ ] Access control
- [ ] Input validation
- [ ] Reentrancy
- [ ] State changes
- [ ] External calls
- [ ] Return values

Findings: [none / list]
Confidence: [high/medium/low]
Time spent: [duration]
```

### 4. AFTER_FILE

Triggered after completing a file review.

```yaml
hook: AFTER_FILE
trigger: Completed file review
purpose: File-level summary and validation

actions:
  - summarize_findings
  - check_function_coverage
  - identify_cross_file_concerns
  - update_trace

validations:
  - all_functions_reviewed: WARN
  - findings_severity_assigned: BLOCK
```

**Implementation:**
```markdown
## AFTER_FILE Summary

File: [filename]
Functions: [X] reviewed / [Y] total
Time: [duration]

Findings:
| ID | Function | Severity | Status |
|----|----------|----------|--------|
| F1 | withdraw | HIGH | confirmed |
| F2 | deposit | MEDIUM | needs review |

Cross-file concerns:
- [ ] Interactions with other contracts noted
- [ ] Shared state dependencies documented
```

### 5. BEFORE_REPORT

Triggered before writing the final report.

```yaml
hook: BEFORE_REPORT
trigger: Starting report generation
purpose: Pre-report validation

actions:
  - compile_all_findings
  - verify_severity_ratings
  - check_duplicates
  - prepare_executive_summary

validations:
  - all_files_reviewed: BLOCK
  - findings_complete: BLOCK
  - severity_consistent: WARN
```

**Implementation:**
```markdown
## BEFORE_REPORT Checklist

- [ ] All scope files reviewed
- [ ] All findings documented with:
  - [ ] Severity rating
  - [ ] Description
  - [ ] Impact
  - [ ] Recommendation
  - [ ] Code references
- [ ] No duplicate findings
- [ ] Severity ratings consistent
- [ ] Executive summary drafted
```

### 6. AFTER_AUDIT

Triggered when audit is complete.

```yaml
hook: AFTER_AUDIT
trigger: Audit finalization
purpose: Post-audit actions and learning

actions:
  - finalize_trace
  - calculate_scores
  - identify_improvement_areas
  - archive_artifacts

validations:
  - report_complete: BLOCK
  - trace_closed: WARN
  - scores_calculated: WARN
```

**Implementation:**
```markdown
## AFTER_AUDIT Actions

- [ ] Report finalized and delivered
- [ ] Audit trace closed
- [ ] Scores calculated:
  - Detection: [X]%
  - Coverage: [X]%
  - Time: [X] hours
- [ ] Lessons learned documented
- [ ] Patterns updated (if new discoveries)
- [ ] Artifacts archived
```

---

## Hook Configuration

### Defining Custom Hooks

```yaml
# hooks.yaml
hooks:
  - name: BEFORE_AUDIT
    enabled: true
    blocking: true
    actions:
      - action: load_patterns
        params:
          pattern_dir: "patterns/"
      - action: initialize_trace
        params:
          output: "traces/"
    validations:
      - check: scope_defined
        severity: BLOCK
      - check: files_exist
        severity: BLOCK

  - name: AFTER_FUNCTION
    enabled: true
    blocking: false
    actions:
      - action: log_to_trace
    validations:
      - check: minimum_checks_performed
        params:
          minimum: 5
        severity: WARN
```

### Hook Actions Reference

| Action | Description | Parameters |
|--------|-------------|------------|
| `load_patterns` | Load pattern files | `pattern_dir`, `filter` |
| `initialize_trace` | Start audit trace | `output`, `format` |
| `log_to_trace` | Add entry to trace | `span_type`, `data` |
| `validate_coverage` | Check review coverage | `threshold` |
| `calculate_scores` | Compute audit scores | `metrics` |
| `send_notification` | External notification | `channel`, `message` |
| `archive` | Save artifacts | `destination` |

### Validation Severities

| Severity | Behavior |
|----------|----------|
| `BLOCK` | Stop progression until resolved |
| `WARN` | Log warning but continue |
| `INFO` | Log for information only |

---

## Hook Templates

### Minimal Hook Set

```markdown
## Minimal Hooks (Fast Audits)

### BEFORE_AUDIT
- [ ] Scope confirmed
- [ ] Patterns loaded

### AFTER_AUDIT
- [ ] Report delivered
- [ ] Time logged
```

### Standard Hook Set

```markdown
## Standard Hooks (Normal Audits)

### BEFORE_AUDIT
- [ ] Full scope validation
- [ ] Pattern loading
- [ ] Trace initialization

### BEFORE_FILE
- [ ] File type identification
- [ ] Dependency mapping

### AFTER_FILE
- [ ] Coverage check
- [ ] Findings summary

### BEFORE_REPORT
- [ ] Findings validation
- [ ] Severity consistency

### AFTER_AUDIT
- [ ] Score calculation
- [ ] Lessons learned
```

### Comprehensive Hook Set

```markdown
## Comprehensive Hooks (Critical Audits)

All hooks enabled with BLOCK validations on:
- Scope definition
- File coverage
- Function coverage
- Findings completeness
- Severity assignment
- Report sections
- Trace completion
- Score thresholds
```

---

## Integration with Other Systems

### → Audit Traces
```yaml
hook: AFTER_FUNCTION
action: log_to_trace
params:
  span_type: FUNCTION_AUDIT
  include:
    - checks_performed
    - findings
    - duration
```

### → Scoring
```yaml
hook: AFTER_AUDIT
action: calculate_scores
params:
  metrics:
    - detection
    - precision
    - coverage
    - efficiency
```

### → Feedback Loop
```yaml
hook: AFTER_AUDIT
action: trigger_gradient_analysis
condition: score.detection < 0.85
params:
  analyze_misses: true
```

### → Community Feedback
```yaml
hook: AFTER_AUDIT
action: prepare_contribution
condition: new_pattern_discovered
params:
  anonymize: true
  template: community-feedback/templates/
```

---

## Custom Hook Examples

### Pre-Commit Hook

```yaml
hook: PRE_COMMIT
trigger: Before committing finding to report
purpose: Quality gate for findings

validations:
  - has_severity: BLOCK
  - has_description: BLOCK
  - has_impact: BLOCK
  - has_recommendation: BLOCK
  - has_code_reference: WARN
  - has_poc: WARN
```

### Cross-Contract Hook

```yaml
hook: AFTER_CONTRACT_INTERACTION
trigger: When external call identified
purpose: Trace cross-contract flows

actions:
  - identify_target_contract
  - check_if_in_scope
  - load_target_patterns
  - note_trust_assumptions
```

### Time Check Hook

```yaml
hook: TIME_CHECK
trigger: Every 2 hours
purpose: Prevent time overruns

actions:
  - calculate_progress
  - estimate_completion
  - alert_if_behind
```

---

## Hook Execution Flow

```
┌─────────────────────────────────────────────────────────────┐
│                      AUDIT LIFECYCLE                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  [BEFORE_AUDIT] ─────────────────────────────────────────►  │
│        │                                                    │
│        ▼                                                    │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ FOR EACH FILE:                                       │   │
│  │   [BEFORE_FILE] ──────────────────────────────────►  │   │
│  │         │                                            │   │
│  │         ▼                                            │   │
│  │   ┌─────────────────────────────────────────────┐   │   │
│  │   │ FOR EACH FUNCTION:                           │   │   │
│  │   │   Review function                            │   │   │
│  │   │   [AFTER_FUNCTION] ─────────────────────►    │   │   │
│  │   └─────────────────────────────────────────────┘   │   │
│  │         │                                            │   │
│  │         ▼                                            │   │
│  │   [AFTER_FILE] ───────────────────────────────────►  │   │
│  └─────────────────────────────────────────────────────┘   │
│        │                                                    │
│        ▼                                                    │
│  [BEFORE_REPORT] ────────────────────────────────────────►  │
│        │                                                    │
│        ▼                                                    │
│  Generate Report                                            │
│        │                                                    │
│        ▼                                                    │
│  [AFTER_AUDIT] ──────────────────────────────────────────►  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Quick Reference

| Hook | When | Key Actions | Key Validations |
|------|------|-------------|-----------------|
| BEFORE_AUDIT | Start | Load patterns, init trace | Scope exists |
| BEFORE_FILE | Each file | ID type, load patterns | File compiles |
| AFTER_FUNCTION | Each function | Log checks, record | Checks done |
| AFTER_FILE | Each file | Summarize, coverage | All functions |
| BEFORE_REPORT | Pre-report | Compile, verify | Files complete |
| AFTER_AUDIT | End | Score, archive | Report done |

---

## Related Files

- [Audit Trace](audit_trace.md)
- [Audit Scoring](../scoring/AUDIT_SCORING.md)
- [LLM Audit Workflow](../methodology/llm-audit-workflow.md)
- [Feedback Loop](../audit-feedback/FEEDBACK_LOOP.md)
