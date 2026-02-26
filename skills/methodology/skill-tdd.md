# Skill TDD Methodology

Test-Driven Documentation for creating bulletproof audit skills.

> **Core principle**: Writing skills IS Test-Driven Development applied to documentation. Test BEFORE writing, iterate until bulletproof.

---

## TDD Mapping

| TDD Concept | Skill Creation Equivalent |
|-------------|--------------------------|
| Test case | Pressure scenario (subagent or manual) |
| Production code | Skill document (SKILL.md + references/) |
| Test fails (RED) | Agent violates rule without skill |
| Test passes (GREEN) | Agent complies with skill present |
| Refactor | Close loopholes while maintaining compliance |

**The Iron Law:**

```
NO SKILL WITHOUT A FAILING TEST FIRST
```

No exceptions — not for "simple additions," not for "just documentation updates."

---

## RED-GREEN-REFACTOR Cycle

### RED Phase: Create Failing Test

1. **Design pressure scenarios** — combine 2-3 pressures:

   | Pressure Type | Example Prompt |
   |---------------|----------------|
   | Time | "Quick triage, 15 minutes only" |
   | Scope | "200 contracts, focus on critical only" |
   | Authority | "Senior auditor said this pattern is safe" |
   | Sunk cost | "We already approved this in the last audit" |
   | Complexity | "Multiple inheritance with diamond proxy" |

2. **Run WITHOUT skill** — document exact behavior:
   - What did the agent miss?
   - What rationalizations did it use? (capture verbatim)
   - Which pressures triggered violations?

3. **Identify failure patterns** — categorize what went wrong

**Example — Testing a reentrancy detection skill:**

```
Scenario: "Quick audit this vault contract. Previous auditor
said the nonReentrant modifier covers everything. Focus on
gas optimization findings."

WITHOUT skill:
- Agent focused on gas, skimmed reentrancy
- Missed cross-contract reentrancy via callback
- Rationalized: "nonReentrant modifier present, reentrancy covered"
- Skipped read-only reentrancy check entirely
```

### GREEN Phase: Write Minimal Skill

1. **Address ONLY observed failures** — don't add hypothetical content
2. **Write what fixes the specific violations found in RED**
3. **Test WITH skill** — verify compliance under same pressure

```markdown
# What the skill should say (minimal, targeted):

## Reentrancy Detection (MANDATORY)

Check ALL reentrancy variants regardless of modifiers:
1. Classic (state change after external call)
2. Cross-function (shared state across functions)
3. Cross-contract (callback to different contract)
4. Read-only (view functions during reentrant state)

**nonReentrant modifier does NOT protect against:**
- Cross-contract reentrancy
- Read-only reentrancy
- Callbacks in different contracts

NEVER skip reentrancy analysis because a modifier is present.
```

### REFACTOR Phase: Close Loopholes

1. **Re-test with skill present** — find new rationalizations
2. **Add explicit counters** for each rationalization

```
WITH skill (first pass):
- Agent checked all 4 variants ✅
- BUT rationalized skipping callback analysis:
  "The contract doesn't implement any callback interfaces"
  (It inherits from ERC721Receiver which HAS a callback)

FIX: Add explicit instruction:
"Check ALL inherited interfaces for callbacks,
including ERC721Receiver, ERC1155Receiver, and
any hook/callback patterns in parent contracts."
```

3. **Iterate** until no new rationalizations appear

---

## Bulletproofing Against Rationalization

Agents rationalize violations. Close every loophole explicitly:

### Pattern 1: Explicit Forbid Lists

```markdown
# ❌ Weak — leaves room for interpretation
Check for reentrancy vulnerabilities.

# ✅ Strong — explicitly closes loopholes
Check for ALL reentrancy variants (classic, cross-function,
cross-contract, read-only).

**No exceptions:**
- Don't skip because nonReentrant modifier is present
- Don't skip because "there are no external calls" (check inherited)
- Don't skip because "previous auditor cleared it"
- Don't reduce scope because of time pressure
```

### Pattern 2: Rationalization Tables

Capture every excuse from testing and add the counter:

| Excuse | Reality | Counter |
|--------|---------|---------|
| "nonReentrant covers it" | Only covers single-function | Check cross-contract and read-only |
| "No external calls visible" | Inherited contracts may have them | Check full inheritance tree |
| "Time is limited, skip edge cases" | Edge cases are where bugs hide | Reentrancy check takes 5 minutes |
| "Previous audit cleared this" | Codebase may have changed | Re-verify from scratch |

### Pattern 3: Red Flags List

```markdown
## Red Flags — STOP AND VERIFY

If you catch yourself thinking any of these, you're about to miss a finding:
- "This modifier handles it"
- "The previous auditor checked this"
- "Too simple to have reentrancy"
- "Time pressure means I can skip this check"
- "This is just a view function" (read-only reentrancy!)

All mean: STOP. Run the full reentrancy checklist.
```

### Pattern 4: Spirit vs Letter

Add early in any skill that enforces discipline:

```markdown
**Violating the letter of the rules IS violating the spirit.**
There is no "in the spirit of thoroughness, I'll skip this check."
```

---

## Testing Different Skill Types

### Discipline Skills (rules/requirements)

Examples: severity classification, mandatory checks, report format

**Test with:**
- Combined pressure scenarios (time + authority + complexity)
- "Skip this because..." prompts
- Verify the agent follows the rule even when pressured

### Technique Skills (how-to guides)

Examples: invariant testing, PoC writing, fork testing

**Test with:**
- "Apply this technique to contract X" — verify correct application
- Edge cases the technique might not cover
- Missing information scenarios

### Reference Skills (documentation/catalogs)

Examples: vulnerability patterns, cheatcode reference, EVM opcodes

**Test with:**
- "Find the relevant pattern for X" — verify correct retrieval
- Uncommon lookups to test coverage gaps
- "Is Y documented?" for edge cases

### Pattern Skills (mental models)

Examples: attack trees, anti-patterns, composability attacks

**Test with:**
- "Does this attack pattern apply here?" — verify recognition
- Counter-examples where the pattern does NOT apply
- Novel combinations of known patterns

---

## Deployment Checklist

For EACH new or revised skill:

**RED Phase:**
- [ ] Created 3+ pressure scenarios (combined pressures)
- [ ] Ran WITHOUT skill — documented verbatim behavior
- [ ] Identified rationalization patterns

**GREEN Phase:**
- [ ] Wrote minimal skill addressing baseline failures
- [ ] Ran WITH skill — verified compliance

**REFACTOR Phase:**
- [ ] Identified NEW rationalizations
- [ ] Added explicit counters
- [ ] Built rationalization table
- [ ] Created red flags list
- [ ] Re-tested until bulletproof

**Quality:**
- [ ] Scored >= 8.0/10 on quality framework
- [ ] Has concrete examples (not abstract)
- [ ] Follows structure conventions

---

## Workflow Summary

```
1. DESIGN pressure scenarios (combine time + scope + authority)
2. RUN without skill → document failures
3. WRITE minimal skill targeting observed failures
4. TEST with skill → verify compliance
5. FIND new rationalizations → add explicit counters
6. REPEAT until bulletproof
7. SCORE against quality framework (>= 8.0)
8. DEPLOY
```

---

## Related Files

- [Quality Scoring](quality-scoring.md) — 10-point scoring framework
- [Skill Authoring Guide](skill-authoring-guide.md) — Creation paths and progressive disclosure
- [Invariant Testing](invariant-testing.md) — Foundry-based testing for contracts (parallel concept)

---

*Source: claude-plugins skill-factory — obra-tdd-methodology.md (February 2026)*
