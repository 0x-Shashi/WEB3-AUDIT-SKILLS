# Audit Session Templates

Templates for structured security audit sessions. Use these to maintain context across long audits.

---

## Available Templates

| Template | Purpose | When to Create |
|----------|---------|----------------|
| [audit_plan.md](audit_plan.md) | Phases, attack tree progress, deliverables | **FIRST** - Before any code review |
| [threat_model.md](threat_model.md) | Actors, trust assumptions, attack surface | During Phase 1 |
| [findings_report.md](findings_report.md) | Discovered vulnerabilities (live doc) | During Phase 2+ |
| [progress.md](progress.md) | Session log, exploit attempts, PoCs | Throughout audit |

---

## Quick Start

### 1. Create Planning Files

```bash
# Copy templates to your audit directory
cp skills/templates/audit_plan.md ./audit/
cp skills/templates/threat_model.md ./audit/
cp skills/templates/findings_report.md ./audit/
cp skills/templates/progress.md ./audit/
```

### 2. Initialize Audit

1. Open `audit_plan.md`
2. Fill in Protocol Info section
3. Identify protocol type
4. Copy attack tree branches from `attack-trees/[type]-attack-tree.md`

### 3. Build Threat Model

1. Open `threat_model.md`
2. Document actors and trust assumptions
3. Map attack surface (entry points, high-value targets)
4. Identify protocol-specific risks

### 4. Start Hunting

Follow the workflow:
```
Read Plan → Review Code → Update Findings → Update Progress → Repeat
```

---

## The 2-Contract Rule

> **After reviewing 2 contracts or 2 major functions, IMMEDIATELY update findings_report.md.**

This prevents discoveries from being lost when context resets.

---

## The 2-Action Rule

> **After every 2 view/browser/search operations, IMMEDIATELY save key findings to files.**

Visual/multimodal content doesn't persist in context. Write it down immediately.

---

## The 5-Question Reboot Test

If context resets, you should be able to answer:

| Question | Answer Source |
|----------|---------------|
| Where am I? | Current phase in `audit_plan.md` |
| Where am I going? | Remaining phases |
| What's the goal? | Goal statement in plan |
| What have I learned? | `threat_model.md`, `findings_report.md` |
| What have I tried? | Exploit attempts in `progress.md` |

---

## Workflow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    AUDIT SESSION WORKFLOW                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Phase 1: Protocol Understanding                                │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │ Read Docs   │───►│ Identify    │───►│ Create      │         │
│  │ Whitepaper  │    │ Protocol    │    │ threat_model│         │
│  └─────────────┘    │ Type        │    │ .md         │         │
│                     └─────────────┘    └─────────────┘         │
│                                                                 │
│  Phase 2: Attack Surface Mapping                                │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │ Load Attack │───►│ Review      │───►│ Update      │         │
│  │ Tree        │    │ 2 Contracts │    │ findings_   │         │
│  └─────────────┘    └─────────────┘    │ report.md   │         │
│                           │            └─────────────┘         │
│                           ▼                                     │
│                     ┌─────────────┐                             │
│                     │ Apply Anti- │ ◄── Load anti-patterns/*.md │
│                     │ Patterns    │                             │
│                     └─────────────┘                             │
│                                                                 │
│  Phase 3: PoC Development                                       │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │ Write       │───►│ Test        │───►│ Log in      │         │
│  │ Foundry PoC │    │ Exploit     │    │ progress.md │         │
│  └─────────────┘    └─────────────┘    └─────────────┘         │
│                           │                                     │
│                    ✓ Success? ───► Update findings_report.md    │
│                    ✗ Failure? ───► Log attempt, try next vector │
│                                                                 │
│  Phase 4: Report Generation                                     │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │ Compile     │───►│ Add CVSS    │───►│ Write       │         │
│  │ Findings    │    │ Scores      │    │ Recs/Fixes  │         │
│  └─────────────┘    └─────────────┘    └─────────────┘         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Template File Relationships

```
audit_plan.md (MASTER)
    │
    ├── threat_model.md (Phase 1 output)
    │
    ├── findings_report.md (Phase 2-3 output)
    │       │
    │       └── Links to: anti-patterns/*.md
    │                     exploit-forensics/*.md
    │                     patterns/*.md
    │
    └── progress.md (Session tracking)
            │
            └── Exploit Attempts table
```

---

## Related Resources

- **Attack Trees:** `attack-trees/INDEX.md`
- **Anti-Patterns:** `anti-patterns/INDEX.md`
- **Exploit Forensics:** `exploit-forensics/index.md`
- **Methodology:** `methodology/llm-audit-workflow.md`

---

*Create planning files FIRST, before any code review.*
*A structured audit is a thorough audit.*
