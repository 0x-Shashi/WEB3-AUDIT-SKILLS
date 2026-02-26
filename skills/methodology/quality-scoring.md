# Quality Scoring Framework

10-point scoring system for evaluating audit skill quality, adapted from Anthropic best practices.

---

## Scoring Criteria (10.0 Total)

| # | Criterion | Weight | What to Check |
|---|-----------|--------|---------------|
| 1 | Description Quality | 2.0 | Specific, includes when_to_use, third-person, < 1024 chars |
| 2 | Name Convention | 0.5 | Lowercase-with-hyphens, descriptive, not generic |
| 3 | Conciseness | 1.5 | SKILL.md < 500 lines OR uses progressive disclosure |
| 4 | Progressive Disclosure | 1.0 | Main file is overview/TOC; details in references/ |
| 5 | Examples & Workflows | 1.0 | Concrete code examples, input/output pairs, real patterns |
| 6 | Degree of Freedom | 0.5 | High freedom for flexible tasks, low for fragile operations |
| 7 | Dependencies | 0.5 | All dependencies documented with installation steps |
| 8 | Structure | 1.0 | Clear headings, logical flow, consistent formatting |
| 9 | Error Handling | 0.5 | Scripts handle errors; clear error messages; validation loops |
| 10 | Anti-Patterns Avoided | 1.0 | No time-sensitive info, consistent terminology, Unix paths |
| — | Testing Evidence | 0.5 | Tested with real queries; evaluation examples present |

---

## Detailed Criteria

### 1. Description Quality (2.0 points)

The `description` field drives skill discovery — Claude uses it to select the right skill from 100+ options.

**Scoring breakdown:**
- 0.5 — Specific (not vague), > 50 characters
- 0.5 — Includes "when to use" guidance
- 0.5 — Written in third person (not "I" or "you")
- 0.5 — Contains key domain terms for matching

**Examples:**

```yaml
# ❌ 0.0/2.0 — Vague, no triggers
description: Helps with auditing

# ⚠️ 1.0/2.0 — Specific but missing when-to-use
description: Detects reentrancy, oracle manipulation, and access control issues in Solidity

# ✅ 2.0/2.0 — Specific + triggers + third person
description: >-
  Analyze Solidity smart contracts for security vulnerabilities including
  reentrancy, oracle manipulation, access-control, and flash-loan issues.
  Use when auditing EVM-compatible contracts on Ethereum, Arbitrum,
  Optimism, Base, Polygon, or BSC.
```

### 2. Name Convention (0.5 points)

- `lowercase-with-hyphens` only
- Descriptive (not `helper`, `utils`, `tool`)
- Gerund form preferred: `solidity-scanner`, `exploit-forensics`
- Maximum 64 characters

### 3. Conciseness (1.5 points)

| Lines | Score | Action |
|-------|-------|--------|
| < 300 | 1.5 | Excellent — concise and focused |
| 300-500 | 1.0 | Good — consider splitting if growing |
| 500-800 | 0.5 | Apply progressive disclosure |
| > 800 | 0.0 | Must split into reference files |

**The core principle**: Claude is already very smart. Only add context Claude doesn't already have. Challenge each line:
- "Does Claude need this explanation?"
- "Can I assume Claude knows this?"
- "Does this token justify its context cost?"

### 4. Progressive Disclosure (1.0 points)

SKILL.md is an overview that points to detailed references as needed:

```
solidity-scanner/
├── SKILL.md                          # < 500 lines overview
├── resources/
│   ├── vulnerability-patterns.md     # Detailed vuln catalog
│   ├── foundry-security.md           # PoC testing guide
│   ├── foundry-cheatcodes.md         # 150+ cheatcodes
│   └── gas-security.md              # Gas optimization
└── workflows/
    ├── quick-scan.md                 # 15-min triage
    ├── comprehensive-audit.md        # Full audit
    └── competitive-audit.md          # Contest mode
```

**Rules:**
- Keep references ONE level deep from SKILL.md (no nested references)
- Reference files > 100 lines should have their own TOC
- Claude loads reference files only when needed — no context penalty

### 5. Examples & Workflows (1.0 points)

- Minimum 3 concrete code examples (not `/* your code here */`)
- Input/output pairs for clarity
- Real patterns from actual audits, not placeholders
- Workflows with sequential steps and feedback loops

```solidity
// ✅ Concrete — shows exactly what to look for
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    (bool ok,) = msg.sender.call{value: amount}("");  // ← external call
    balances[msg.sender] -= amount;  // ← state update AFTER call = reentrancy
}

// ❌ Abstract — wastes tokens
function doSomething() external {
    // Check for reentrancy here
}
```

### 6. Degree of Freedom (0.5 points)

Match specificity to task fragility:

| Task Type | Freedom | Example |
|-----------|---------|---------|
| Creative analysis | High | "Analyze the code structure and identify potential issues" |
| Standard workflow | Medium | "Follow the checklist; adapt to protocol type" |
| Critical operation | Low | "Run exactly: `slither . --detect reentrancy`" |

### 7. Dependencies (0.5 points)

All external tools and versions documented:

```yaml
dependencies:
  - Foundry (forge, cast, anvil, chisel)
  - Slither >= 0.10.0
  - OpenZeppelin v5.x (for test imports)
  - Python 3.10+ (for quality scripts)
```

### 8. Structure (1.0 points)

- Clear section headings (`##` hierarchy without skips)
- Logical flow: Overview → Usage → Details → Troubleshooting
- Consistent formatting throughout
- Unix-style forward-slash paths only (`/` not `\`)

### 9. Error Handling (0.5 points)

Scripts must handle errors explicitly:

```python
# ✅ Handles errors, provides useful output
def process_finding(path):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Finding file not found: {path}")
        return None
    except json.JSONDecodeError as e:
        print(f"Invalid JSON in {path}: {e}")
        return None
```

### 10. Anti-Patterns Avoided (1.0 points)

| Anti-Pattern | Penalty | Fix |
|-------------|---------|-----|
| Time-sensitive info ("as of Jan 2025") | -0.5 | Use versioning, not dates |
| Inconsistent terminology (skill vs plugin) | -0.5 | Pick one term, use everywhere |
| Windows-style paths (`C:\Users\...`) | -0.4 | Always use forward slashes |
| Too many options without guidance | -0.3 | Provide a default, then escape hatches |
| Deeply nested references (3+ levels) | -0.3 | Keep references one level deep |

---

## Quality Tiers

| Tier | Score Range | Meaning |
|------|------------|---------|
| Excellent | 8.0 – 10.0 | Production-ready, follows all best practices |
| Good | 6.0 – 7.9 | Usable, minor improvements needed |
| Fair | 4.0 – 5.9 | Needs review, several issues |
| Poor | 0.0 – 3.9 | Not recommended for deployment |

**Quality threshold**: All skills in this project should score **>= 8.0**.

---

## Quality Guarantee Loop

When creating or revising any skill file, apply this loop:

```python
max_iterations = 5
iteration = 0

while iteration < max_iterations:
    score, issues = score_skill(skill_path)

    if score >= 8.0:
        print(f"Quality threshold met: {score}/10")
        break

    # Apply fixes for each issue
    for issue in issues:
        if "vague_description" in issue:
            improve_description_specificity()
        elif "too_long" in issue:
            apply_progressive_disclosure()
        elif "missing_examples" in issue:
            add_concrete_code_examples()
        elif "poor_structure" in issue:
            reorganize_with_clear_headings()

    iteration += 1

if score < 8.0:
    flag_for_manual_review()
```

---

## Automated Scoring

Run the quality checker against any SKILL.md:

```bash
python scripts/quality-check.py skills/solidity-scanner/SKILL.md
```

Output:
```
8.5/10

Issues found:
  - Anti-patterns: Contains time-sensitive information
```

Exit code 0 if score >= 8.0, exit code 1 otherwise (for CI integration).

---

## Quick Validation Checklist

Before committing any skill file:

- [ ] Description specific and under 1024 chars?
- [ ] Name follows lowercase-hyphen convention?
- [ ] SKILL.md under 500 lines (or uses progressive disclosure)?
- [ ] Has 3+ concrete code examples?
- [ ] No time-sensitive information?
- [ ] Dependencies documented?
- [ ] Unix-style paths only?
- [ ] Tested with real queries?
- [ ] References are one level deep max?
- [ ] Error handling present in scripts?

---

## Related Files

- [Skill TDD Methodology](skill-tdd.md) — Test-driven approach to creating audit skills
- [Skill Authoring Guide](skill-authoring-guide.md) — Creation paths, progressive disclosure, best practices
- [Quality Check Script](../../scripts/quality-check.py) — Automated scorer

---

*Source: claude-plugins skill-factory — anthropic-best-practices.md, quality-loops.md (February 2026)*
