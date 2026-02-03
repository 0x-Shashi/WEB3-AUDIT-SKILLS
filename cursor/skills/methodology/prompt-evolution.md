# Prompt Evolution System

## Overview

The Prompt Evolution System uses iterative refinement (inspired by beam search) to improve audit prompts over time. Better prompts lead to better detection rates and fewer misses.

---

## Core Concept: Prompt as Optimization Target

Just as machine learning optimizes model weights, we optimize prompt text:

```
INITIAL PROMPT → EVALUATE → GENERATE VARIANTS → SELECT BEST → ITERATE
```

The "fitness function" is audit performance:
- Higher detection rate = better prompt
- Fewer false positives = better prompt
- Faster audits = better prompt

---

## Beam Search for Prompts

### What is Beam Search?

Instead of keeping one prompt, maintain multiple "candidate" prompts (the beam) and evolve the best ones:

```
Generation 0: [Prompt A]
               ↓
Generation 1: [Prompt A1, Prompt A2, Prompt A3]  ← Generate variants
               ↓ Evaluate
Generation 2: [Prompt A2, Prompt A2a, Prompt A2b]  ← Keep top K, generate variants
               ↓ Evaluate  
Generation 3: [Prompt A2a-1, Prompt A2a-2, ...]
```

### Beam Parameters

```yaml
beam_search:
  beam_width: 3  # Number of candidates to keep
  variants_per_candidate: 2  # Variants generated per candidate
  generations: 5  # How many iterations
  selection_criteria: "detection_score"  # Fitness function
```

---

## Prompt Structure

### Audit Prompt Template

```markdown
# Audit Prompt v[VERSION]

## Role Definition
[Who the LLM should act as]

## Context Loading Instructions
[How to load and use patterns/checklists]

## Audit Process
[Step-by-step audit methodology]

## Output Format
[How to structure findings]

## Quality Checks
[Self-verification steps]
```

### Example Prompt (v1.0)

```markdown
# Audit Prompt v1.0

## Role
You are a senior smart contract security auditor with expertise in DeFi protocols.

## Context
Load relevant patterns based on protocol type:
- DeFi: reentrancy, oracle, flash loan patterns
- NFT: royalty, metadata, access patterns
- Governance: voting, timelock patterns

## Process
1. Understand the protocol architecture
2. Map all entry points and state changes
3. For each function, check against loaded patterns
4. Document all findings with evidence

## Output
For each finding:
- Severity: CRITICAL/HIGH/MEDIUM/LOW
- Title: Brief description
- Description: Detailed explanation
- Impact: What could go wrong
- Proof of Concept: Attack scenario
- Recommendation: How to fix
```

---

## Evolution Process

### Step 1: Establish Baseline

```markdown
## Baseline Measurement

**Prompt:** v1.0 (current production)
**Test Set:** 10 historical audits with known vulnerabilities

| Audit | Vulns | Detected | Missed | FP | Score |
|-------|-------|----------|--------|----|----|
| A | 5 | 4 | 1 | 0 | 80% |
| B | 3 | 3 | 0 | 1 | 90% |
| ... | ... | ... | ... | ... | ... |

**Baseline Detection Score:** 85%
**Baseline Precision:** 88%
```

### Step 2: Generate Variants

Create variations of the prompt:

```markdown
## Variant Generation Strategies

### Strategy 1: Add Detail
Original: "Check for reentrancy"
Variant: "Check for classic, cross-function, cross-contract, and read-only reentrancy"

### Strategy 2: Add Examples
Original: "Check access control"
Variant: "Check access control (missing modifiers, incorrect modifier logic, unprotected initialize)"

### Strategy 3: Reorder Steps
Original: "1. Load patterns 2. Review code 3. Document"
Variant: "1. Skim code 2. Load targeted patterns 3. Deep review 4. Document"

### Strategy 4: Add Constraints
Original: "Document all findings"
Variant: "Document findings only if confidence > 80%. Include confidence score."

### Strategy 5: Change Persona
Original: "Senior security auditor"
Variant: "Red team attacker looking for maximum damage vectors"
```

### Step 3: Evaluate Variants

Run each variant against the test set:

```markdown
## Variant Evaluation

| Variant | Detection | Precision | Time | Composite |
|---------|-----------|-----------|------|-----------|
| v1.0 (base) | 85% | 88% | 1.0x | 86.5 |
| v1.1 (detail) | 89% | 86% | 1.1x | 87.0 |
| v1.2 (examples) | 92% | 84% | 1.2x | 87.5 |
| v1.3 (reorder) | 87% | 90% | 0.9x | 88.5 |
| v1.4 (constraints) | 83% | 95% | 0.8x | 88.0 |
| v1.5 (persona) | 90% | 82% | 1.1x | 85.5 |

**Top 3 for next generation:** v1.3, v1.4, v1.2
```

### Step 4: Select and Iterate

```markdown
## Generation 2

Keep top 3, generate 2 variants each = 6 new candidates

### From v1.3 (reorder):
- v2.1: Add pattern pre-loading step
- v2.2: Add post-review verification

### From v1.4 (constraints):
- v2.3: Lower confidence threshold to 70%
- v2.4: Add severity-specific confidence

### From v1.2 (examples):
- v2.5: Add more reentrancy examples
- v2.6: Add oracle examples

[Evaluate all 6...]
```

### Step 5: Converge

After N generations, select the best performing prompt:

```markdown
## Final Selection

**Winning Prompt:** v3.2
**Lineage:** v1.0 → v1.3 → v2.2 → v3.2

**Performance:**
- Detection: 94%
- Precision: 91%
- Time: 0.95x
- Composite: 92.5

**Key Improvements from v1.0:**
1. Added pre-review pattern targeting
2. Added post-review verification step
3. Refined confidence threshold to 75%
4. Added specific examples for top 5 vuln types
```

---

## Prompt Library

Maintain a library of evolved prompts:

```
prompts/
├── production/
│   └── audit-prompt-v3.2.md  # Current best
├── experimental/
│   ├── audit-prompt-v4.0-draft.md
│   └── audit-prompt-specialized-defi.md
├── archive/
│   ├── audit-prompt-v1.0.md
│   ├── audit-prompt-v2.0.md
│   └── audit-prompt-v3.0.md
└── evaluation/
    ├── test-set.md
    └── results/
        ├── v3.2-results.md
        └── v4.0-draft-results.md
```

---

## Specialized Prompt Evolution

Evolve prompts for specific domains:

### DeFi-Specific Prompt

```markdown
## DeFi Audit Prompt v2.0

Specialized for:
- Lending protocols
- DEXs
- Yield aggregators
- Stablecoins

Additional checks:
- Flash loan attack surface
- Price oracle dependencies
- Liquidation mechanisms
- Interest rate models
```

### NFT-Specific Prompt

```markdown
## NFT Audit Prompt v1.5

Specialized for:
- ERC721/1155
- Marketplaces
- Royalty systems
- Metadata handling

Additional checks:
- Royalty bypass
- Metadata manipulation
- Signature replay
- Bulk operations
```

---

## Evolution Triggers

When to trigger prompt evolution:

```markdown
## Evolution Triggers

### Automatic Triggers
- Detection score drops below 85%
- 3+ misses of same vulnerability type
- New vulnerability class discovered
- Major protocol type not covered

### Manual Triggers
- New audit framework released
- Community feedback on prompt quality
- Significant codebase pattern shift
```

---

## Integration with Other Systems

### ← From Feedback Loop
```
Gradient computed → Informs prompt improvement
"Missed read-only reentrancy because prompt didn't specify variant"
→ Add to variant generation: "specify all reentrancy variants"
```

### ← From Audit Traces
```
Trace shows: Time spent on false positives
→ Add constraint: "Verify before reporting"
```

### ← From Scoring
```
Score data: Low precision for oracle findings
→ Evolve oracle-specific section of prompt
```

### → To Production
```
Evolved prompt passes threshold
→ Deploy to production
→ Monitor real-world performance
```

---

## Prompt Evolution Record

Track all evolutions:

```markdown
## Evolution Log

### v3.2 (Current Production)
- **Date:** 2024-01-15
- **Parent:** v3.1
- **Change:** Added confidence scoring
- **Detection Δ:** +2%
- **Precision Δ:** +4%

### v3.1
- **Date:** 2024-01-01
- **Parent:** v3.0
- **Change:** Expanded reentrancy variants
- **Detection Δ:** +3%
- **Precision Δ:** -1%

### v3.0
- **Date:** 2023-12-15
- **Parent:** v2.5
- **Change:** Restructured audit process
- **Detection Δ:** +5%
- **Precision Δ:** +2%
```

---

## Quick Evolution Workflow

```markdown
1. **Measure:** Run current prompt against test set
2. **Identify:** Find weakest performance areas
3. **Generate:** Create 3-5 variants targeting weaknesses
4. **Evaluate:** Test variants against same test set
5. **Select:** Keep top performers
6. **Iterate:** Repeat 2-3 times
7. **Deploy:** Promote best to production
8. **Monitor:** Track real-world performance
```

---

## Prompt A/B Testing

For production validation:

```markdown
## A/B Test: v3.2 vs v4.0-draft

**Duration:** 10 audits
**Split:** 5 each

### Results

| Metric | v3.2 | v4.0-draft |
|--------|------|------------|
| Detection | 92% | 95% |
| Precision | 91% | 88% |
| Time | 1.0x | 1.15x |

**Decision:** v4.0-draft has higher detection but more FPs.
**Action:** Evolve v4.0-draft to improve precision before promotion.
```

---

## Related Files

- [Audit Scoring](../scoring/AUDIT_SCORING.md)
- [Feedback Loop](../audit-feedback/FEEDBACK_LOOP.md)
- [Audit Workflow](llm-audit-workflow.md)
