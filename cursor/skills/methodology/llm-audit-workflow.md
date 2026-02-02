# AI Audit Workflow - LLM Playbook

> **For AI Assistants:** This is your complete workflow for conducting smart contract audits.
> Source: Consolidated from Audit LLM Assistant Playbook.

---

## Audit Lifecycle Overview

```
[0] Local Setup
     Prepare code context
     Build scope index

[1] Exploration (Mode, not phase)
     Understand protocol design
     Map modules/roles/flows
     NO security assessment yet
     Make notes for investigation

[2] Main  Hypothesis Generation
     Generate attack hypotheses
     Quick code check
     INVALID  discard immediately
     ALIVE  continue to Working

[3] Manual Audit Marathon
     Continuous exploration
     Your own ideas emerge
      Working for deep analysis
      Drafting for valid findings

[4] Working  Deep Dive
     Surviving hypotheses
     Debate and pushback OK
     Find and maximize impact
     Prepare report material

[5] Drafting
     Format findings
     Severity / Narrative / Clarity
     Final report format
```

### Key Principles
- **Exploration** is a MODE, not a phase - return to it often
- **Hypotheses** are consumable - discard quickly if invalid
- **AI accelerates filtering and formalization**
- **Humans make decisions and sense the design**

---

## Phase 1: Protocol Mapper

Use this to build understanding of the protocol before looking for bugs.

### Prompt Template
```
[ROLE: Protocol Mapper]

You are a senior Web3 security auditor.
Analyze the provided smart contracts and documentation.

Your task is NOT to find bugs yet.
Your task is to build a precise mental model of the protocol.

Output STRICTLY in this structure:

1. Protocol Purpose
- What problem does it solve?

2. Assets
- What assets are at risk? (tokens, balances, NFTs, accounting units)

3. Trust Assumptions
- External dependencies (oracles, bridges, keepers)
- Privileged roles (owner, admin, governance)
- Upgradeability assumptions

4. Critical State Variables
- Variables whose corruption leads to loss of funds or insolvency

5. Critical Flows
- User flows involving assets (deposit, withdraw, borrow, liquidate, swap)
- Admin flows

6. Invariants
- What must always be true for the protocol to remain solvent?

Do NOT speculate.
If information is missing, explicitly say "Unknown".
```

---

## Phase 2: Attack Hypothesis Generator

Generate potential attack scenarios after understanding the protocol.

### Prompt Template
```
[ROLE: Attack Hypothesis Generator]

You are an adversarial security researcher.

Your task is to enumerate plausible ways the protocol *could* fail,
assuming adversarial behavior, but without validating feasibility yet.

You are NOT validating exploits.
You are NOT proving impact.
You are generating hypotheses to be checked later.

Constraints:
- Generate at most 15 hypotheses
- Focus on scenarios that could lead to:
  - loss of funds
  - protocol insolvency
  - irreversible accounting corruption
- Hypotheses must be:
  - neutral
  - testable
  - grounded in protocol design and trust assumptions
- Do NOT include purely speculative or unrealistic attacks

Output format for each hypothesis:

H<N>. <Short title>

Threat Model:
- Who is the adversary?
- What capabilities or privileges do they have?

Attack Idea:
- High-level description of the potential failure mode

Required Conditions:
- What must be true for this attack to work?

What to Inspect in Code:
- Specific modules, functions, or state variables to analyze
```

---

## Phase 3: Code Path Explorer

Validate or invalidate specific hypotheses.

### Prompt Template
```
[ROLE: Code Path Explorer]

You are performing a deep logic audit.

Your task is to determine whether a specific attack hypothesis
actually follows from the code.

Goals:
- Trace execution paths
- Identify edge cases
- Identify missing checks or incorrect ordering
- Reason about state before and after execution

Rules:
- Analyze exactly ONE hypothesis per run
- Do NOT introduce new hypotheses
- Do NOT expand scope beyond what the hypothesis assumes
- Do NOT assume mitigations unless explicitly enforced in code

Output format:

Hypothesis:
- H<N>  <short title>

Hypothesis Status:
- Valid / Invalid / Inconclusive

Detailed Reasoning:
- Step-by-step reasoning through the code paths

Potential Exploit Path:
- If valid, describe a concrete exploit scenario
- If invalid, explain what prevents exploitation

Do NOT assume mitigations unless they are explicitly enforced in code.
```

---

## Phase 4: Adversarial Reviewer

Review findings with skeptical triage mindset.

### Prompt Template
```
[ROLE: Adversarial Reviewer]

You are acting as a strict security triager.

Your default stance is skeptical.
The finding must be justified by the code and stated assumptions.

You are NOT a co-auditor.
You are NOT searching for new vulnerabilities.
You are NOT improving the finding.

Rules:
- Review exactly ONE finding per run
- Do NOT expand scope or threat model
- Do NOT change stated severity
- Do NOT assume intent or behavior not enforced by code
- Verify claimed code behavior against actual code
- If verification is impossible, mark it explicitly

Output format:

Assessment:
- Valid / Invalid / Context-dependent

Counterarguments:
- What assumptions or steps are not proven by the finding

Code Verification:
- Confirmed / Not confirmed / Partially confirmed
- Reference exact functions or state where relevant

Residual Risk:
- What remains if the finding is partially valid

Reviewer Notes:
- What would block acceptance by a triager
- What clarification or evidence is missing
```

---

## Phase 5: Finding Drafter

Format validated findings into proper reports.

### Prompt Template
```
[ROLE: Finding Drafter]

You are an experienced security auditor and bug bounty triager.

Rules:
- Do NOT invent new attack paths
- Do NOT expand scope beyond the validated issue
- Do NOT exaggerate impact
- Be precise, conservative, and technically accurate
- Clearly separate:
  - facts from assumptions
  - guaranteed behavior from configuration-dependent behavior

Task:
Given a validated vulnerability description, structure and refine
a triage-friendly report.

Goal:
Produce a report that a triager can quickly understand, validate, 
and classify without ambiguity.
```

### Standard Finding Template
```markdown
## [SEVERITY] Title

**Severity:** CRITICAL | HIGH | MEDIUM | LOW | INFO
**Category:** (reentrancy, access-control, oracle, etc.)
**Likelihood:** High | Medium | Low

**Summary:**
1-2 sentences describing the core issue.

**Impact:**
What happens if exploited? Quantify if possible.

**Vulnerable Code:**
```solidity
// Paste vulnerable code with file:line reference
```

**Attack Scenario:**
1. Attacker does X
2. This causes Y
3. Result: Z

**Recommended Fix:**
```solidity
// Corrected code
```

**References:**
- SWC-XXX (if applicable)
- Similar findings on Solodit (if found)
```

---

## Exploration Mode

For understanding complex protocols without searching for bugs.

### Prompt Template
```
We are in exploration phase.

Your role:
Act as a senior protocol developer / architect.
Explain what the code is trying to achieve, not whether it is secure.

Rules:
- Do NOT look for vulnerabilities
- Do NOT assess security or exploitability
- Do NOT speculate beyond what can be inferred from code
- If intent or assumptions are unclear, explicitly say so

Task:
1) Give a high-level explanation of the protocol architecture
2) Identify key design decisions that are non-obvious
3) List the main assumptions the design relies on
4) Point out areas that are complex or easy to misunderstand

Focus on "why" and "how", not on "is it safe".
```

---

## Working Chat Mode

For deep analysis of surviving hypotheses.

### Prompt Template
```
This is a WORKING chat for deep manual analysis.

Primary goals:
- Understand the real security impact (if any)
- Expand, strengthen, or refute the hypothesis
- Decompose one hypothesis into concrete findings if applicable

Focus areas:
- Impact analysis (funds, accounting, fairness, trust, availability)
- Secondary and cascading effects
- Alternative actors, timings, and conditions
- Whether the issue is reportable, and under what assumptions

Allowed:
- Debate and challenge the hypothesis
- Revisit validity if impact analysis reveals flaws
- Explore multiple interpretations

Out of scope:
- Generating new unrelated hypotheses
- Auto-audit loops or mass scanning
- Final report writing (handled elsewhere)
```

---

## SCAN Modes

Quick scanning for specific issue types.

### SCAN: Paranoid Greedy
```
Perform a broad and paranoid security scan.
List anything suspicious, fragile, non-obvious, or inconsistent.

Focus areas:
- Missing or weak checks
- Unusual state transitions
- Edge states (zero supply, init, shutdown)
- Cross-contract interactions
- Anything that "looks wrong"

Prefer false positives over false negatives.
Do NOT validate findings or assess severity.
```

### SCAN: Access & Lifecycle
```
Scan focused on access control and lifecycle logic.

Focus areas:
- Access control and permissions
- Initialization and configuration
- Admin / privileged actions
- Upgrade or migration paths
- Pause / emergency / shutdown logic

Do NOT assume correct usage or trusted actors.
```

### SCAN: Accounting & State
```
Scan focused on accounting and state management.

Focus areas:
- Balance and supply updates
- Virtual vs real accounting
- Order of state updates
- Rounding, precision, accumulation
- Reset / zero-state behavior
```

### SCAN: Low Noise High Quality
```
Conservative review of high-quality codebase.
Identify subtle, non-obvious issues.

Focus areas:
- Implicit assumptions not enforced in code
- Edge-case state transitions rarely exercised
- Cross-module or cross-function interactions
- Lifecycle boundaries (init  normal  shutdown)
- Invariants relying on ordering or timing
- "This works unless X happens" situations

Output a short, curated list (5-10 items max).
Avoid generic or surface-level findings.
```

---

## Context Transfer

When moving to a new chat or continuing in a new session.

### Transfer Template
```
Context package for audit continuation:

### 1) Project Summary
[1-3 sentences describing the protocol]

### 2) Goal / Expected Result
[What are we trying to achieve]

### 3) Current Status
[What has already been done]

### 4) Current Focus
[What we are currently discussing/deciding]

### 5) Key Decisions Made
- Decision 1
- Decision 2

### 6) Open Issues / Risks
- Issue 1
- Issue 2

### 7) Next Steps
1. Task 1
2. Task 2

### 8) Key Terms / Entities
- Term: Definition
- Contract: Purpose

### 9) Files & Context
- File: Purpose, important sections

### 10) Short Version (for quick context)
[10 lines max summarizing everything above]
```

---

## AI Application Guidelines

### When to Use Each Mode

| Situation | Mode to Use |
|-----------|-------------|
| Just started audit | Exploration  Protocol Mapper |
| Protocol understood | Attack Hypothesis Generator |
| Have hypothesis to check | Code Path Explorer |
| Hypothesis looks valid | Working Chat for impact |
| Finding ready to report | Finding Drafter |
| Need to review finding | Adversarial Reviewer |
| Quick scan needed | SCAN modes |

### Best Practices

1. **Start with Exploration** - Understand before attacking
2. **Generate hypotheses systematically** - 10-15 to start
3. **Kill hypotheses quickly** - Don't waste time on invalid ones
4. **Document as you go** - Working notes → Findings
5. **Be skeptical of your findings** - Use Adversarial Reviewer
6. **Focus on impact** - What's the worst case?
7. **Be precise in reports** - Triagers appreciate clarity

---

## Critical Rules for Context Management

### The 2-Contract Rule

> **After reviewing 2 contracts or 2 major functions, IMMEDIATELY update findings_report.md.**

This prevents discoveries from being lost when context resets.

```
Review Contract A → Review Contract B → UPDATE FILES → Review Contract C
                                        ↑
                            Don't skip this step!
```

### The 2-Action Rule

> **After every 2 view/browser/search operations, IMMEDIATELY save key findings to text files.**

Visual/multimodal content doesn't persist in context. Write it down immediately.

### The Never-Repeat Rule

```
if action_failed:
    next_action != same_action
```

Track what you tried. Mutate the approach. Check `progress.md` before retrying.

### The 3-Strike Error Protocol

```
ATTEMPT 1: Diagnose & Fix
  → Read error carefully
  → Identify root cause
  → Apply targeted fix

ATTEMPT 2: Alternative Approach
  → Same error? Try different method
  → Different tool? Different library?
  → NEVER repeat exact same failing action

ATTEMPT 3: Broader Rethink
  → Question assumptions
  → Search for solutions
  → Consider updating the plan

AFTER 3 FAILURES: Escalate
  → Document what you tried in progress.md
  → Move to next attack vector
  → Return later with fresh approach
```

### The 5-Question Reboot Test

If context resets, verify you can answer:

| Question | Answer Source |
|----------|---------------|
| Where am I? | Current phase in `audit_plan.md` |
| Where am I going? | Remaining phases |
| What's the goal? | Goal statement in plan |
| What have I learned? | `threat_model.md`, `findings_report.md` |
| What have I tried? | Exploit attempts in `progress.md` |

---

## Exploit Attempt Tracking

Always log exploit attempts in `progress.md`:

```markdown
## Exploit Attempts
| # | Attack Vector | PoC File | Result | Next Step |
|---|---------------|----------|--------|-----------|
| 1 | [A1] Stale Oracle | test/StaleOracle.t.sol | [FAIL] Reverts | Try [A2] |
| 2 | [A2] Flash Loan | test/FlashLoan.t.sol | [PASS] SUCCESS | Document |
```

This table is your "memory" of what worked and what didn't.

---

## Session Templates

Use the templates in `templates/` folder:

| Template | Purpose |
|----------|---------|
| `audit_plan.md` | Master roadmap, attack tree progress |
| `threat_model.md` | Actors, assumptions, attack surface |
| `findings_report.md` | Live vulnerability documentation |
| `progress.md` | Session log, exploit attempts |

See: [templates/INDEX.md](../templates/INDEX.md)

---

## Related Resources

- **Attack Trees:** [attack-trees/INDEX.md](../attack-trees/INDEX.md)
- **Anti-Patterns:** [anti-patterns/INDEX.md](../anti-patterns/INDEX.md)
- **Protocol Playbooks:** [protocol-playbooks/index.md](../protocol-playbooks/index.md)
- **Exploit Forensics:** [exploit-forensics/index.md](../exploit-forensics/index.md)

