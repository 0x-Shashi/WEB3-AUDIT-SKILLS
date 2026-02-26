# Skill Authoring Guide

How to create, structure, and maintain high-quality audit skills. Covers progressive disclosure, the three creation paths, and the quality guarantee loop.

---

## Three Creation Paths

### Path A: Documentation-Based

Start from existing reference material (docs, specs, post-mortems):

```
1. Gather source documentation
2. Extract key patterns, code examples, and decision trees
3. Organize into SKILL.md (overview) + references/ (details)
4. Run quality scoring (>= 8.0)
5. Test with real audit queries
```

**Best for**: Scanner skills, pattern libraries, cheatcode references, chain guides

**Example**: The Foundry resources were built this way — 15 source files from claude-plugins condensed into 5 targeted reference files.

### Path B: Custom Workflow (TDD)

Build from scratch using Test-Driven Documentation:

```
1. Design pressure scenarios
2. Run WITHOUT skill — document failures
3. Write minimal skill addressing failures
4. Test WITH skill — verify compliance
5. Close rationalization loopholes
6. Score and deploy
```

**Best for**: Methodology skills, discipline enforcement, audit workflows

**Example**: The LLM Audit Workflow was built this way — tested under time pressure to ensure agents follow all phases.

See [Skill TDD Methodology](skill-tdd.md) for the complete process.

### Path C: Hybrid

Combine documentation scraping with TDD refinement:

```
1. Scrape/extract documentation (Path A)
2. Identify gaps through pressure testing
3. Fill gaps with TDD approach (Path B)
4. Unify, score (>= 8.0), deploy
```

**Best for**: Protocol-specific skills that need both reference data AND behavioral enforcement

---

## Progressive Disclosure

### The Problem

Your context window is shared across ALL loaded skills, conversation history, system prompt, and the user's actual request. Every token in a skill competes with everything else.

**Your current project**: Some consolidated files are 399KB — too large to load without significant context cost.

### The Solution

Keep SKILL.md as a concise overview. Move details to reference files that Claude loads only when needed.

### Structure Pattern

```
skill-name/
├── SKILL.md              # < 500 lines — overview, quick reference, links
├── resources/            # Detailed reference material
│   ├── patterns.md       # Loaded only when pattern lookup needed
│   ├── cheatcodes.md     # Loaded only for cheatcode queries
│   └── config.md         # Loaded only for configuration help
└── workflows/            # Step-by-step procedures
    ├── quick-scan.md     # Loaded for triage requests
    └── full-audit.md     # Loaded for comprehensive audit requests
```

### Rules

1. **SKILL.md under 500 lines** — overview + quick reference + links
2. **References one level deep** — SKILL.md → reference file (never reference → reference)
3. **Reference files > 100 lines get their own TOC**
4. **No context penalty for unloaded files** — 50 reference files cost 0 tokens until accessed

### How It Works in Practice

```
User: "How do I test for reentrancy with Foundry?"

Claude's loading sequence:
1. [Always loaded] Skill metadata: "solidity-scanner - Analyze Solidity contracts..."
2. [Triggered]     Reads SKILL.md → sees "Foundry Security" in resources table
3. [On-demand]     Reads foundry-security.md → finds reentrancy PoC section
4. [NOT loaded]    gas-security.md, foundry-ci-cd.md — not relevant, zero cost
```

### Applying to This Project

| Current Issue | Fix |
|---------------|-----|
| 399KB consolidated files | Split into focused reference files per topic |
| All content in SKILL.md | Move detailed catalogs to resources/ |
| Flat file structure | Organize: SKILL.md + resources/ + workflows/ |
| No lazy loading benefit | References loaded only when queries match |

---

## File Naming Conventions

| Convention | Rule | Example |
|-----------|------|---------|
| Skill directories | `lowercase-with-hyphens` | `solidity-scanner/` |
| Skill files | `SKILL.md` (uppercase) | `solidity-scanner/SKILL.md` |
| Resource files | `lowercase-with-hyphens.md` | `vulnerability-patterns.md` |
| Script files | `lowercase-with-hyphens.ext` | `quality-check.py` |
| Paths | Unix-style forward slashes | `resources/patterns.md` |

---

## Frontmatter Template

```yaml
---
id: skill-name
title: Human Readable Title
category: scanner | methodology | patterns | ...
difficulty: beginner | intermediate | advanced
triggers:
  - keyword one
  - keyword two
  - phrase trigger
related_skills:
  - other-skill/SKILL.md
tags:
  - relevant
  - search
  - terms
last_updated: 2026-02-26
description: >-
  Specific description of what this skill does.
  Use when [specific trigger conditions].
  Covers [key topics] for [target audience].
---
```

---

## Content Guidelines

### Write for Claude, Not Humans

Claude is already very smart. Only add context Claude doesn't already have.

```markdown
# ❌ Over-explains (wastes tokens)
Reentrancy is a vulnerability where a malicious contract
calls back into the calling contract before the first
invocation is complete. This can lead to unexpected state
changes. The Checks-Effects-Interactions pattern prevents
this by ensuring all state changes happen before external
calls. Let me explain how this works...

# ✅ Concise (trusts Claude's knowledge)
## Reentrancy Detection

Check all variants:
1. Classic: state change after external call
2. Cross-function: shared state across functions
3. Cross-contract: callback to different contract
4. Read-only: view functions during reentrant state

nonReentrant does NOT cover cross-contract or read-only.
```

### Concrete Over Abstract

```solidity
// ✅ Real code — immediately useful
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    (bool ok,) = msg.sender.call{value: amount}("");
    balances[msg.sender] -= amount;  // ← BUG: state after call
}

// ❌ Placeholder — wastes tokens
function example() external {
    // vulnerable code here
}
```

### Consistent Terminology

Pick one term and use it everywhere:

| Correct | Avoid Mixing |
|---------|-------------|
| "skill" | skill, plugin, extension, module |
| "finding" | finding, issue, bug, vulnerability, defect |
| "scanner" | scanner, analyzer, detector, checker |
| "resource" | resource, reference, document, file |

---

## Quality Guarantee Loop

Every skill in this project must score >= 8.0/10:

```
while score < 8.0 AND iterations < 5:
    score, issues = evaluate_skill(skill_file)

    for issue in issues:
        if "vague_description":    → add specific triggers
        if "too_long":             → apply progressive disclosure
        if "missing_examples":     → add concrete code
        if "poor_structure":       → reorganize sections
        if "time_sensitive":       → remove dates, use versions
        if "inconsistent_terms":   → standardize vocabulary

    score = re-evaluate()

if score < 8.0:
    flag for manual review
```

See [Quality Scoring](quality-scoring.md) for the complete 10-point framework.

---

## Version Tracking

### Per-Skill Versioning

Track changes to each skill with version comments in frontmatter:

```yaml
last_updated: 2026-02-26
# v9.0 — Added Foundry security testing resources
# v8.0 — Added Solana security sub-skill
# v7.0 — Added attack trees and anti-patterns
```

### Project-Level Versioning

The [XREF.md](../XREF.md) version tracks the overall project state:
- v10.0 — Skill-Factory merge (quality scoring, TDD, authoring guide)
- v9.0 — Foundry-Solidity Plugin merge
- v8.0 — Solana Security Sub-Skill merge

### Changelog

The [CHANGELOG.md](../CHANGELOG.md) records what changed and when, organized by version.

---

## Commit Standards

Use conventional commits for clear history:

```
feat(solidity-scanner): add Foundry security testing resources
fix(severity): correct CVSS mapping for medium findings
docs(methodology): add quality scoring framework
refactor(patterns): split 800-line file into 4 focused resources
chore(scripts): add quality-check.py validation script
```

| Prefix | When |
|--------|------|
| `feat` | New skill, resource, or workflow added |
| `fix` | Correction to existing content |
| `docs` | Documentation-only changes |
| `refactor` | Restructuring without behavior change |
| `chore` | Scripts, configs, tooling |
| `test` | Test additions or modifications |

---

## Related Files

- [Quality Scoring](quality-scoring.md) — 10-point scoring framework
- [Skill TDD Methodology](skill-tdd.md) — Test-driven creation process
- [Quality Check Script](../../scripts/quality-check.py) — Automated scorer

---

*Source: claude-plugins skill-factory — best-practices.md, overview.md, SKILL.md (February 2026)*
