---
id: METH-AUDIT-SESSION-MANAGEMENT
title: Audit Session Management — 3-File Pattern
category: methodology
tier: workflow
audience: [auditors, ai-agents]
last_updated: 2026-02-25
description: >-
  Use when running multi-session security audits — covers the 3-file pattern
  for persistent audit state (plan, findings, progress), session recovery
  after context resets, hook-based workflow gates, and structured handoff
  between audit sessions. Adapted from the Manus-pattern planning-with-files
  framework.
---

# Audit Session Management — 3-File Pattern

## Why Session Management Matters for Audits

Security audits are inherently multi-session tasks. A typical audit involves:
- 50-200+ file reads across the codebase
- 10-50 vulnerability hypotheses tested
- Multiple context resets as context windows fill
- Handoffs between human reviewers and AI assistants

Without persistent session state, each context reset loses:
- Which contracts have been reviewed
- Which vulnerability hypotheses were tested and dismissed
- Partial findings that haven't been written up yet
- The current phase of the audit methodology

## The 3-File Pattern

For every audit engagement, maintain three files:

```
audit_plan.md       → Phases, scope, progress tracking
audit_findings.md   → Discovered vulnerabilities and notes
audit_progress.md   → Session log, errors, test results
```

### Core Principle

```
Context Window = RAM (volatile, limited)
Filesystem = Disk (persistent, unlimited)

→ Every finding, hypothesis, and decision gets written to disk immediately.
→ Never rely on context memory for audit state.
```

## File 1: audit_plan.md

The plan file tracks the audit methodology phases, scope boundaries, and
completion status. It is read at the START of every session and before every
major decision.

### Template

```markdown
# Audit Plan: [Protocol Name]

## Scope
- Repository: [repo URL]
- Commit: [hash]
- Contracts in scope: [list]
- Contracts out of scope: [list]
- Prior audits: [links]

## Phase Tracking

### Phase 1: Context Building ⬜
- [ ] Read README & docs
- [ ] Map contract architecture
- [ ] Identify entry points
- [ ] List external dependencies
- [ ] Review access control model

### Phase 2: Automated Analysis ⬜
- [ ] Run Slither/Aderyn/Clippy
- [ ] Review tool findings
- [ ] Filter false positives
- [ ] Flag for manual review

### Phase 3: Manual Review ⬜
- [ ] Check access control patterns
- [ ] Check reentrancy surfaces
- [ ] Check oracle dependencies
- [ ] Check upgrade mechanisms
- [ ] Check token handling (approve/transfer)
- [ ] Check math (overflow, precision loss, rounding)

### Phase 4: Attack Modeling ⬜
- [ ] Build attack trees
- [ ] Test cross-function attacks
- [ ] Test cross-contract attacks
- [ ] Test economic attacks (flash loans, MEV)

### Phase 5: PoC & Report ⬜
- [ ] Write PoCs for confirmed findings
- [ ] Classify severity (Critical/High/Medium/Low/Info)
- [ ] Write report
- [ ] Review with team

## Status Legend
⬜ Not started | 🔄 In progress | ✅ Complete | ⏸️ Blocked
```

## File 2: audit_findings.md

The findings file stores ALL vulnerability observations — confirmed, potential,
and dismissed. This prevents re-investigating the same hypothesis across sessions.

### Template

```markdown
# Audit Findings: [Protocol Name]

## Confirmed Findings

### [C-01] Title
- **Severity**: Critical
- **Contract**: `Contract.sol`
- **Function**: `function()`
- **Line**: 123
- **Description**: ...
- **Impact**: ...
- **PoC**: [link or inline]
- **Recommendation**: ...

## Potential Findings (Under Investigation)

### [P-01] Hypothesis: Title
- **Status**: Testing
- **Contract**: `Contract.sol`
- **Observation**: ...
- **Test needed**: ...

## Dismissed Hypotheses

### [D-01] Title — DISMISSED
- **Reason**: ...
- **Evidence**: ...
```

**Critical rule**: NEVER delete a dismissed hypothesis. Future sessions need to
know what was already investigated to avoid redundant work.

## File 3: audit_progress.md

The progress file is a session log. Each session appends entries. It captures
what was done, what failed, and what remains.

### Template

```markdown
# Audit Progress Log

## Session 1 — [Date] [Time]
### Completed
- Reviewed `Contract.sol` lines 1-200: access control looks correct
- Ran Slither: 12 findings, 8 false positives filtered
- Found potential reentrancy in `withdraw()` — added to P-01

### Errors / Blockers
- Could not compile with Foundry 0.8.30 — downgraded to 0.8.28
- Missing oracle mock for `PriceFeed.sol` testing

### Next Session
- Complete review of `Contract.sol` (lines 200-500)
- Write PoC for P-01
- Begin Phase 3 manual review

---

## Session 2 — [Date] [Time]
### Recovery
- Read audit_plan.md: Phase 2 complete, Phase 3 in progress
- Read audit_findings.md: 1 confirmed, 2 potential, 3 dismissed
- Continuing from: Contract.sol line 200

### Completed
- ...
```

## Session Recovery Protocol

When starting a new session (after context reset or `/clear`):

### Step 1: Read State (30 seconds)

```
1. Read audit_plan.md    → Know current phase & what's done
2. Read audit_findings.md → Know all findings & dismissed hypotheses
3. Read audit_progress.md → Know last session's context & next steps
```

### Step 2: Announce Recovery

```markdown
## Session Recovery
- Phase: [current phase from plan]
- Findings: [X confirmed, Y potential, Z dismissed]
- Last session ended at: [reference from progress]
- Continuing with: [next steps from progress]
```

### Step 3: Continue Work

Resume from exactly where the last session ended. No re-investigation of
dismissed hypotheses. No re-reading of already-reviewed contracts.

## Hook-Based Workflow Gates

### Pre-Write Gate

Before writing any finding to `audit_findings.md`:
1. Re-read the current findings file
2. Check for duplicates (same contract + function + vulnerability type)
3. Check dismissed hypotheses (don't re-add something already dismissed)
4. Write the finding with a unique ID

### Pre-Major-Decision Gate

Before starting a new audit phase or changing scope:
1. Re-read `audit_plan.md`
2. Verify the current phase is complete (all checkboxes checked)
3. Update the status emoji (⬜ → ✅)
4. Log the phase transition in `audit_progress.md`

### Pre-Stop Gate

Before ending a session:
1. Update `audit_plan.md` with current phase status
2. Flush all in-context findings to `audit_findings.md`
3. Write session summary to `audit_progress.md` with "Next Session" section

## Audit-Specific Adaptations

### Contract Coverage Tracking

Add a coverage matrix to `audit_plan.md`:

```markdown
## Contract Coverage

| Contract | Lines | Read | Findings | Status |
|----------|-------|------|----------|--------|
| Token.sol | 350 | 350/350 | C-01 | ✅ |
| Vault.sol | 800 | 400/800 | P-02 | 🔄 |
| Oracle.sol | 200 | 0/200 | — | ⬜ |
```

### Vulnerability Hypothesis Tracker

Add to `audit_findings.md`:

```markdown
## Hypothesis Tracker

| # | Hypothesis | Contract | Status | Outcome |
|---|-----------|----------|--------|---------|
| H-01 | Reentrancy in withdraw | Vault.sol | Tested | → C-01 |
| H-02 | Oracle manipulation | Oracle.sol | Tested | → D-01 |
| H-03 | Unchecked return value | Token.sol | Pending | — |
```

### Multi-Reviewer Handoff

When handing off between reviewers (human or AI):

```markdown
## Handoff Note — [Date]
- **Reviewer**: [name/AI model]
- **Completed**: Phases 1-3
- **Key findings**: C-01 (critical reentrancy), H-03 (still pending)
- **Recommended next**: Focus on Vault.sol cross-function interactions
- **Context**: [link to relevant documentation or prior reports]
```

## Integration with Quality Scoring

Each finding in `audit_findings.md` should include quality metadata:

```markdown
### [C-01] Reentrancy in withdraw()
- **Severity**: Critical
- **Confidence**: High (PoC confirmed)
- **Completeness**: Full (root cause identified, fix proposed)
- **Novelty**: Low (known pattern, not project-specific)
```

This metadata feeds into the audit quality scoring system.

## Anti-Patterns

| Anti-Pattern | Problem | Solution |
|-------------|---------|----------|
| Findings only in context | Lost on reset | Write to disk immediately |
| No dismissed hypotheses log | Re-investigate same paths | Log ALL hypotheses |
| No session recovery protocol | Start from scratch each session | Read 3 files first |
| Phase skipping | Miss systematic issues | Follow plan phases |
| No coverage tracking | Miss entire contracts | Coverage matrix |
| Bulk status updates | Lose granularity | Update per-item, not per-phase |

## Cross-References

- [audit-context-building/SKILL.md](../audit-context-building/SKILL.md) — Phase 1 context building methodology
- [report-writer/SKILL.md](../report-writer/SKILL.md) — Phase 5 report generation
- [methodology/SKILL.md](SKILL.md) — Parent methodology skill
- [quality-scoring.md](quality-scoring.md) — Finding quality assessment

## Sources

- Planning-with-files plugin (Manus pattern): https://github.com/OthmanAdi/planning-with-files
- 3-file pattern validated across 15+ IDE integrations (v2.13.0)
- Session recovery protocol: v2.2.0+ automatic recovery after `/clear`
