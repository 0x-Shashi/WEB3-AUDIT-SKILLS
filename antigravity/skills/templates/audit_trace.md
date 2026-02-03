# Audit Trace System

## Overview

The Audit Trace system logs every step of an audit as structured spans, creating a complete record that can be analyzed, replayed, and used to improve future audits.

---

## Core Concept: Span-Based Tracing

Inspired by distributed systems tracing (OpenTelemetry, Jaeger), each audit action becomes a **span** with:
- Start/end time
- Parent span (for hierarchy)
- Action type
- Input/output
- Status (success/failure/skip)

```
AUDIT START
├── CONTEXT_LOAD (2 min)
│   ├── load_readme
│   ├── load_patterns
│   └── load_triggers
├── SCOPE_ANALYSIS (5 min)
│   ├── file_discovery
│   └── dependency_mapping
├── FILE_AUDIT: Contract.sol (45 min)
│   ├── function: deposit
│   │   ├── check: reentrancy → PASS
│   │   ├── check: access_control → FLAG
│   │   └── check: input_validation → PASS
│   └── function: withdraw
│       └── check: reentrancy → FLAG (CRITICAL)
└── REPORT_GENERATION (30 min)
```

---

## Trace Structure

### Span Schema

```yaml
span:
  id: "span-uuid-001"
  parent_id: "span-uuid-000"  # null for root
  trace_id: "audit-2024-01-15-protocol-x"
  name: "check_reentrancy"
  type: "VULNERABILITY_CHECK"
  status: "FLAG"  # PASS | FLAG | SKIP | ERROR
  
  timing:
    start: "2024-01-15T10:30:00Z"
    end: "2024-01-15T10:32:15Z"
    duration_ms: 135000
  
  context:
    file: "contracts/Vault.sol"
    function: "withdraw"
    lines: [45, 78]
    checklist_item: "reentrancy.cross_function"
  
  input:
    code_snippet: |
      function withdraw(uint256 amount) external {
          // ...
      }
    loaded_patterns: ["reentrancy-patterns.md"]
  
  output:
    finding: true
    severity: "HIGH"
    description: "Cross-function reentrancy via shared state"
    evidence: "State update on line 67 after external call on line 62"
  
  attributes:
    model: "gpt-4"
    confidence: 0.85
    tokens_used: 1250
```

### Span Types

| Type | Description | Example |
|------|-------------|---------|
| `AUDIT_START` | Root span for entire audit | Top level |
| `CONTEXT_LOAD` | Loading patterns, checklists | Load reentrancy patterns |
| `SCOPE_ANALYSIS` | Understanding codebase | Map contract dependencies |
| `FILE_AUDIT` | Auditing a specific file | Audit Vault.sol |
| `FUNCTION_AUDIT` | Auditing a specific function | Audit withdraw() |
| `VULNERABILITY_CHECK` | Specific vulnerability test | Check for reentrancy |
| `FINDING_DOCUMENT` | Writing up a finding | Document HIGH-001 |
| `REPORT_GENERATE` | Final report generation | Create PDF |

---

## Trace Template

### Start of Audit

```markdown
## Audit Trace: [Protocol Name]

**Trace ID:** audit-[date]-[protocol]
**Auditor:** [Name/Team]
**Start Time:** [ISO timestamp]
**Scope:** [Brief scope description]

---

### SPAN: AUDIT_START
- **ID:** span-001
- **Status:** IN_PROGRESS
- **Scope Files:** [list]
- **Loaded Context:** [list]
```

### During Audit

```markdown
### SPAN: FILE_AUDIT - Vault.sol
- **ID:** span-010
- **Parent:** span-001
- **Start:** 10:30:00
- **Status:** IN_PROGRESS

#### SPAN: FUNCTION_AUDIT - withdraw()
- **ID:** span-011
- **Parent:** span-010
- **Lines:** 45-78

##### SPAN: VULNERABILITY_CHECK - Reentrancy
- **ID:** span-012
- **Parent:** span-011
- **Checklist Item:** reentrancy.cross_function
- **Patterns Loaded:** reentrancy-patterns.md
- **Status:** FLAG
- **Finding:**
  - Severity: HIGH
  - Description: Cross-function reentrancy
  - Evidence: Line 67 state update after line 62 call
- **Duration:** 2m 15s
```

### End of Audit

```markdown
### SPAN: AUDIT_START (closed)
- **End Time:** [timestamp]
- **Total Duration:** [duration]
- **Status:** COMPLETE

---

## Trace Summary

| Metric | Value |
|--------|-------|
| Total Spans | 156 |
| Files Audited | 12 |
| Functions Audited | 89 |
| Checks Performed | 423 |
| Findings | 7 |
| Critical | 1 |
| High | 2 |
| Medium | 3 |
| Low | 1 |
| Duration | 6h 23m |
```

---

## Structured Trace Format (JSON)

For machine-readable traces:

```json
{
  "trace_id": "audit-2024-01-15-protocol-x",
  "protocol": "Protocol X",
  "auditor": "Auditor Name",
  "start_time": "2024-01-15T09:00:00Z",
  "end_time": "2024-01-15T15:23:00Z",
  "spans": [
    {
      "id": "span-001",
      "parent_id": null,
      "type": "AUDIT_START",
      "name": "Full Audit",
      "status": "COMPLETE",
      "children": ["span-002", "span-010", "span-100"]
    },
    {
      "id": "span-012",
      "parent_id": "span-011",
      "type": "VULNERABILITY_CHECK",
      "name": "Reentrancy Check",
      "status": "FLAG",
      "context": {
        "file": "Vault.sol",
        "function": "withdraw",
        "lines": [45, 78]
      },
      "output": {
        "severity": "HIGH",
        "description": "Cross-function reentrancy"
      },
      "timing": {
        "start": "2024-01-15T10:30:00Z",
        "duration_ms": 135000
      }
    }
  ],
  "findings_summary": {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 1
  }
}
```

---

## Using Traces

### During Audit: Real-Time Logging

```markdown
As you audit, log each action:

1. **Starting a file:** Create FILE_AUDIT span
2. **Checking a function:** Create FUNCTION_AUDIT span
3. **Running a check:** Create VULNERABILITY_CHECK span
4. **Finding something:** Update span with FLAG status and details
5. **Moving on:** Close span with PASS or SKIP status
```

### After Audit: Analysis

```markdown
## Trace Analysis Questions

1. **Where did I spend the most time?**
   - Sort spans by duration
   - Identify bottlenecks

2. **What checks found things?**
   - Filter spans where status = FLAG
   - Analyze which patterns were most useful

3. **What did I skip?**
   - Filter spans where status = SKIP
   - Review if skips were justified

4. **How complete was coverage?**
   - Compare functions audited vs total functions
   - Check if all checklist items were executed
```

### For Improvement: Trace Mining

```markdown
## Mining Traces for Gradients

If a vulnerability was missed:

1. Load the audit trace
2. Find the relevant FUNCTION_AUDIT span
3. Check which VULNERABILITY_CHECK spans were executed
4. Identify:
   - Was the right check performed?
   - Did the check have the right patterns loaded?
   - Was the span marked SKIP? Why?
5. Generate gradient based on trace analysis
```

---

## Trace Commands

### Initialize Trace
```markdown
[TRACE:START]
protocol: [name]
scope: [description]
auditor: [name]
```

### Log Span
```markdown
[SPAN:START type="FILE_AUDIT" name="Vault.sol"]
[SPAN:CHECK item="reentrancy" status="FLAG" severity="HIGH"]
[SPAN:END]
```

### Query Trace
```markdown
[TRACE:QUERY]
filter: status=FLAG
group_by: severity
```

---

## Integration with Other Systems

### → Feedback Loop
Traces identify WHERE misses occurred:
```
Trace shows: VULNERABILITY_CHECK for reentrancy was PASS
Reality: Reentrancy exploit occurred
Gradient: Why did the check pass incorrectly?
```

### → Audit Scoring
Traces provide data for scoring:
```
Score calculation uses:
- Number of checks performed
- Time efficiency
- Finding accuracy
```

### → Prompt Evolution
Traces show which prompts work:
```
Trace: Prompt A found 5 vulns in 2 hours
Trace: Prompt B found 3 vulns in 4 hours
Evolution: Favor Prompt A characteristics
```

### → Hooks
Traces can trigger hooks:
```
AFTER_FILE_AUDIT hook:
- Check if all mandatory spans completed
- Alert if coverage insufficient
```

---

## Trace Templates

### Quick Trace (Minimal)
```markdown
# Audit Trace: [Protocol]

| Time | Action | File | Status | Notes |
|------|--------|------|--------|-------|
| 09:00 | START | - | - | Loaded context |
| 09:15 | FILE | Token.sol | DONE | 2 findings |
| 10:30 | FILE | Vault.sol | DONE | 1 critical |
| 12:00 | FILE | Router.sol | DONE | Clean |
| 14:00 | REPORT | - | DONE | Final review |

**Summary:** 3 files, 3 findings, 5 hours
```

### Full Trace (Detailed)
```markdown
# Audit Trace: [Protocol]
[Full span hierarchy with all details]
```

### Machine Trace (JSON)
```json
{
  "trace_id": "...",
  "spans": [...]
}
```

---

## Trace Storage

```
audit-traces/
├── 2024/
│   ├── 01/
│   │   ├── protocol-x-trace.md
│   │   ├── protocol-x-trace.json
│   │   └── protocol-y-trace.md
│   └── 02/
│       └── ...
└── templates/
    ├── quick-trace.md
    └── full-trace.md
```

---

## Related Files

- [Feedback Loop](../audit-feedback/FEEDBACK_LOOP.md)
- [Audit Scoring](../scoring/AUDIT_SCORING.md)
- [Hooks System](HOOKS.md)
- [Prompt Evolution](../methodology/prompt-evolution.md)
