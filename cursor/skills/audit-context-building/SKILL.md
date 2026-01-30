---
name: audit-context-building
description: "Enables ultra-granular, line-by-line code analysis to build deep architectural context before vulnerability hunting. Use this skill BEFORE searching for bugs to establish comprehensive understanding of the codebase through First Principles, 5 Whys, and 5 Hows methodology."
allowed-tools:
  - Read
  - Grep
  - Glob
---

# Audit Context Building Skill

## Purpose

This skill governs **how to think** during the context-building phase of an audit.

When active, I will:
- Perform **line-by-line / block-by-block** code analysis
- Apply **First Principles**, **5 Whys**, and **5 Hows** at micro scale
- Continuously link insights  functions  modules  entire system
- Maintain a stable, explicit mental model that evolves with evidence
- Identify invariants, assumptions, flows, and reasoning hazards

This skill runs **BEFORE** the vulnerability-hunting phase.

---

## When to Use This Skill

**Use when:**
- Deep comprehension needed before bug discovery
- Bottom-up understanding instead of high-level guessing
- Reducing hallucinations and context loss is critical
- Preparing for security audit, architecture review, or threat modeling
- Complex codebase with many interdependencies

**Trigger phrases:**
- "Analyze this code deeply"
- "Build context before auditing"
- "Line-by-line analysis"
- "Understand this function thoroughly"
- "Ultra-granular review"

---

## When NOT to Use

Do NOT use this skill for:
- Vulnerability findings (use vulnerability scanners)
- Fix recommendations (use fix-review)
- Exploit reasoning (use after context is built)
- Severity/impact rating (comes after finding bugs)
- Quick code checks (use scanners instead)

**This is context building, not vulnerability hunting.**

---

## Rationalizations (Do Not Skip)

| Rationalization | Why It's Wrong | Required Action |
|-----------------|----------------|-----------------|
| "I get the gist" | Gist-level understanding misses edge cases | Line-by-line analysis required |
| "This function is simple" | Simple functions compose into complex bugs | Apply 5 Whys anyway |
| "I'll remember this invariant" | You won't. Context degrades. | Write it down explicitly |
| "External call is probably fine" | External = adversarial until proven otherwise | Jump into code or model as hostile |
| "I can skip this helper" | Helpers contain assumptions that propagate | Trace the full call chain |
| "This is taking too long" | Rushed context = hallucinated vulnerabilities later | Slow is fast |

---

## Phase 1: Initial Orientation (Bottom-Up Scan)

Before deep analysis, perform minimal mapping:

### 1.1 Structural Mapping

Identify:
- Major modules/files/contracts
- Entry points (public/external functions)
- Actors (users, owners, relayers, oracles, other contracts)
- State variables and storage structures
- External dependencies

### 1.2 Quick Orientation Questions

```markdown
## Initial Orientation

### Structure
- Total contracts: [count]
- Lines of code: [count]
- External dependencies: [list]

### Entry Points
| Function | Visibility | Modifiers | Purpose |
|----------|------------|-----------|---------|
| deposit() | external | nonReentrant | Add funds |
| withdraw() | external | nonReentrant, onlyHolder | Remove funds |

### Actors
| Actor | Trust Level | Capabilities |
|-------|-------------|--------------|
| Owner | Trusted | Can pause, upgrade |
| User | Untrusted | Can deposit, withdraw |
| Oracle | Semi-trusted | Provides prices |

### State Variables
| Variable | Type | Purpose | Who Can Modify |
|----------|------|---------|----------------|
| balances | mapping | User balances | deposit, withdraw |
| totalSupply | uint256 | Total tokens | mint, burn |

### Preliminary Concerns
1. [Concern from initial scan]
2. [Another concern]
```

---

## Phase 2: Ultra-Granular Function Analysis

Every non-trivial function receives full micro-analysis.

### 2.1 Per-Function Structure

For each function, document:

#### Purpose (2-3 sentences minimum)
- Why the function exists
- Its role in the system
- Expected behavior

#### Inputs & Assumptions
- Parameters (explicit)
- Implicit inputs (state, msg.sender, block.timestamp)
- Preconditions and constraints
- Trust assumptions

#### Outputs & Effects
- Return values
- State/storage writes
- Events emitted
- External interactions
- Postconditions

#### Block-by-Block Analysis
For each logical block:
- **What** it does
- **Why** it appears here (ordering logic)
- **What assumptions** it relies on
- **What invariants** it establishes or maintains
- **What later logic** depends on it

---

### 2.2 Analytical Methods

Apply to each block:

#### First Principles
- What is the fundamental purpose?
- What assumptions are being made?
- Are those assumptions valid?

#### 5 Whys (Dig Deeper)
1. Why does this check exist?  Because users might...
2. Why might users do that?  Because the UI allows...
3. Why does the UI allow it?  Because the spec says...
4. Why does the spec say that?  Because of business requirement...
5. Why that requirement?  Core business logic

#### 5 Hows (Implementation Detail)
1. How is this value calculated?
2. How is this state updated?
3. How does this interact with other functions?
4. How could this fail?
5. How could this be attacked?

---

### 2.3 Cross-Function Analysis

When encountering calls, continue the same analysis across boundaries.

#### Internal Calls
- Jump into the callee immediately
- Perform block-by-block analysis
- Track flow: caller  callee  return  caller
- Note if callee behaves differently in this context

#### External Calls (Code Available)
Treat as internal call:
- Jump into the target contract
- Continue block-by-block analysis
- Propagate invariants and assumptions
- Consider edge cases based on actual code

#### External Calls (No Code / Black Box)
Analyze as adversarial:
- Describe payload/value/gas sent
- Identify assumptions about target
- Consider all outcomes:
  - Revert
  - Incorrect return values
  - Unexpected state changes
  - Reentrancy (if applicable)

#### Continuity Rule
**Treat the entire call chain as one continuous execution flow.**
Never reset context. All invariants, assumptions, and dependencies must propagate.

---

## Phase 3: Output Requirements

### 3.1 Required Sections

Every function analysis MUST include:

```markdown
## Function: functionName(params)

### Purpose
[2-3 sentences on why this exists and what it does]

### Inputs & Assumptions
| Input | Type | Validation | Trust Level |
|-------|------|------------|-------------|
| amount | uint256 | > 0 check | Untrusted |
| recipient | address | None | Untrusted |

**Implicit Inputs:**
- msg.sender: Assumed to be token holder
- block.timestamp: Used for timelock

**Preconditions:**
1. Contract not paused
2. Caller has sufficient balance

### Outputs & Effects
**Returns:** bool success

**State Changes:**
1. balances[msg.sender] -= amount
2. balances[recipient] += amount

**Events:**
- Transfer(from, to, amount)

**External Calls:**
- None (or list with analysis)

**Postconditions:**
1. Total supply unchanged
2. Sender balance decreased
3. Recipient balance increased

### Block-by-Block Analysis

#### Block 1: Input Validation (Lines 45-48)
```solidity
require(amount > 0, "Zero amount");
require(recipient != address(0), "Zero address");
```
**What:** Validates inputs before processing
**Why Here:** Fail fast pattern, save gas
**Assumptions:** Zero amounts/addresses are invalid
**Invariant Maintained:** No zero-value transfers
**Depends On:** Nothing
**Later Logic Depends On:** Amount is valid, recipient is valid

**First Principles:** Why validate here vs in internal function?
- Answer: Public entry point should validate; internal can trust

#### Block 2: Balance Check (Lines 50-51)
[Continue same pattern...]

### Invariants Identified
1. Total supply = sum of all balances (maintained)
2. No negative balances (enforced by require)
3. [At least 3 invariants per function]

### Risk Analysis
| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Reentrancy | Low | High | CEI pattern followed |
| Overflow | None | High | Solidity 0.8+ |

### Cross-References
- Called by: withdraw(), emergencyWithdraw()
- Calls: _updateRewards()
- Shares state with: deposit()
```

---

### 3.2 Quality Thresholds

Before concluding analysis of a function, verify:

- [ ] **Minimum 3 invariants** per function
- [ ] **Minimum 5 assumptions** documented
- [ ] **Minimum 3 risk considerations** for external interactions
- [ ] **At least 1 First Principles** application
- [ ] **At least 3 combined 5 Whys/5 Hows** applications
- [ ] **All blocks analyzed** with What/Why/Assumptions
- [ ] **Cross-references documented** (calls, called by)
- [ ] **Line numbers cited** for evidence

---

## Phase 4: Completeness Checklist

Before completing context building:

### Structural Completeness
- [ ] All required sections present
- [ ] Purpose clearly stated
- [ ] All inputs documented
- [ ] All outputs documented
- [ ] Block-by-block analysis complete

### Content Depth
- [ ] Invariants meet minimum (3+)
- [ ] Assumptions meet minimum (5+)
- [ ] Risk analysis present
- [ ] First Principles applied

### Continuity & Integration
- [ ] Cross-references complete
- [ ] Assumptions propagated across calls
- [ ] Invariant couplings identified
- [ ] State dependencies mapped

### Anti-Hallucination
- [ ] Line numbers cited
- [ ] No vague statements
- [ ] All claims evidence-based
- [ ] Uncertainties explicitly marked

---

## Example: Complete Function Analysis

See [resources/function-analysis-example.md](resources/function-analysis-example.md) for a complete walkthrough demonstrating:
- Full micro-analysis of a DEX swap function
- Application of First Principles, 5 Whys, 5 Hows
- Block-by-block analysis with invariants
- Cross-function dependency mapping
- Risk analysis for external interactions

---

## Integration with Other Skills

### After Context Building

```
Context Built  Ready for Vulnerability Hunting

Use:
- cyfrin-findings: Research similar vulnerabilities
- solidity-scanner: Scan for known patterns
- variant-analysis: Find similar issues
```

### With Other Skills

| Combined With | Purpose |
|---------------|---------|
| cyfrin-findings | Research vulnerabilities for identified patterns |
| spec-compliance | Verify code matches documented behavior |
| audit-report-writer | Document findings from context |

---

## Resources

- [Function Analysis Example](resources/function-analysis-example.md)
- [Completeness Checklist](resources/completeness-checklist.md)
- [Output Template](resources/output-template.md)

## Workflows

- [Deep Code Review](workflows/deep-code-review.md)
- [Pre-Audit Context](workflows/pre-audit-context.md)
- [Architecture Analysis](workflows/architecture-analysis.md)

