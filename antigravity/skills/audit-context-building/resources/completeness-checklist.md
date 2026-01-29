# Completeness Checklist

Use this checklist to verify your context-building analysis meets quality standards.

---

## Pre-Analysis Checklist

### Preparation
- [ ] Identified all contracts/files in scope
- [ ] Listed all external dependencies
- [ ] Mapped actors and trust levels
- [ ] Documented entry points
- [ ] Noted protocol type (DEX, lending, NFT, etc.)

### Environment Understanding
- [ ] Solidity version noted
- [ ] Compiler optimizations considered
- [ ] Upgrade patterns identified (if applicable)
- [ ] Access control model understood
- [ ] External integrations mapped

---

## Per-Function Checklist

### Structure (Required Sections)
- [ ] Purpose statement (2-3 sentences minimum)
- [ ] Inputs & Assumptions table
- [ ] Implicit inputs documented
- [ ] Preconditions listed
- [ ] Outputs & Effects documented
- [ ] State changes listed
- [ ] Events documented
- [ ] External calls listed
- [ ] Postconditions defined
- [ ] Block-by-block analysis complete

### Content Depth
| Requirement | Minimum | Achieved |
|-------------|---------|----------|
| Invariants | 3+ per function | [ ] |
| Assumptions | 5+ per function | [ ] |
| Risk considerations | 3+ for external calls | [ ] |
| First Principles applications | 1+ per function | [ ] |
| 5 Whys/5 Hows applications | 3+ combined | [ ] |

### Block Analysis Quality
For each logical block:
- [ ] **What** it does
- [ ] **Why** it appears at this position
- [ ] **Assumptions** it relies on
- [ ] **Invariants** it maintains
- [ ] **Dependencies** (what it depends on)
- [ ] **Dependents** (what depends on it)

### Cross-References
- [ ] Internal calls traced
- [ ] External calls analyzed
- [ ] Shared state identified
- [ ] Call graph documented

---

## Analytical Methods Checklist

### First Principles Applied
- [ ] Questioned fundamental purpose
- [ ] Identified core assumptions
- [ ] Validated assumption correctness
- [ ] Considered alternative implementations

### 5 Whys Applied
For at least one critical aspect:
- [ ] Level 1 Why
- [ ] Level 2 Why
- [ ] Level 3 Why
- [ ] Level 4 Why
- [ ] Level 5 Why (root cause)

### 5 Hows Applied
For at least one implementation:
- [ ] How is it calculated?
- [ ] How is state updated?
- [ ] How does it interact with others?
- [ ] How could it fail?
- [ ] How could it be attacked?

---

## External Call Analysis Checklist

### For Each External Call (Code Available)
- [ ] Jumped into target code
- [ ] Analyzed target block-by-block
- [ ] Propagated invariants
- [ ] Considered edge cases
- [ ] Tracked return value handling

### For Each External Call (Black Box)
- [ ] Described payload/value/gas
- [ ] Listed assumptions about target
- [ ] Considered: Revert scenarios
- [ ] Considered: Incorrect return values
- [ ] Considered: Unexpected state changes
- [ ] Considered: Reentrancy potential
- [ ] Considered: Gas griefing

---

## Anti-Hallucination Checklist

### Evidence-Based Claims
- [ ] Every claim has line number reference
- [ ] No vague statements like "probably" or "might"
- [ ] Uncertainties explicitly marked with ⚠️
- [ ] All code references verified against actual source
- [ ] No assumptions stated as facts

### Context Preservation
- [ ] No context loss between function analyses
- [ ] Invariants from previous functions carried forward
- [ ] Assumption dependencies tracked
- [ ] Cross-function state relationships documented

### Verification Steps
- [ ] Re-read key code sections before finalizing
- [ ] Verified all line number references
- [ ] Confirmed variable names match source
- [ ] Double-checked mathematical formulas

---

## Integration Checklist

### Module-Level Analysis
- [ ] All public/external functions analyzed
- [ ] Internal helper functions traced
- [ ] State variable access patterns mapped
- [ ] Constructor/initializer analyzed
- [ ] Modifier effects documented

### Cross-Module Analysis
- [ ] Inter-contract calls mapped
- [ ] Inheritance hierarchy understood
- [ ] Library usage analyzed
- [ ] Interface compliance verified

### System-Level Synthesis
- [ ] Global invariants identified
- [ ] Actor interaction model complete
- [ ] Trust boundaries defined
- [ ] Value flow mapped
- [ ] Critical paths identified

---

## Quality Gates

### Before Completing Function Analysis
Must answer "Yes" to all:
1. Could I explain this function to another auditor? [ ]
2. Are all assumptions explicitly documented? [ ]
3. Are all invariants identified? [ ]
4. Are all external interaction risks considered? [ ]
5. Is the block-by-block analysis complete? [ ]

### Before Completing Module Analysis
Must answer "Yes" to all:
1. Are all entry points analyzed? [ ]
2. Are all internal dependencies traced? [ ]
3. Is the state model complete? [ ]
4. Are cross-function invariants documented? [ ]
5. Is the risk summary complete? [ ]

### Before Completing Full Context
Must answer "Yes" to all:
1. Is the system architecture understood? [ ]
2. Are all trust boundaries defined? [ ]
3. Are all value flows mapped? [ ]
4. Are all external dependencies analyzed? [ ]
5. Am I ready to begin vulnerability hunting? [ ]

---

## Final Verification

### Self-Review Questions
1. What would I miss if I skipped any section?
2. Where did I make assumptions without evidence?
3. What external factors could invalidate my analysis?
4. What would a fresh auditor question about my analysis?
5. What edge cases haven't I considered?

### Peer Review Readiness
- [ ] Analysis is self-contained and readable
- [ ] Technical terms are defined or obvious
- [ ] References are traceable
- [ ] Conclusions follow from evidence
- [ ] Uncertainties are clearly marked

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────┐
│           COMPLETENESS QUICK CHECK                  │
├─────────────────────────────────────────────────────┤
│ Per Function:                                       │
│   □ Purpose (2-3 sentences)                        │
│   □ Inputs & Assumptions (5+)                      │
│   □ Outputs & Effects                              │
│   □ Block-by-Block Analysis                        │
│   □ Invariants (3+)                                │
│   □ Risk Analysis                                  │
│   □ Cross-References                               │
├─────────────────────────────────────────────────────┤
│ Per Block:                                          │
│   □ What / Why / Assumptions                       │
│   □ Invariant / Depends On / Dependents            │
├─────────────────────────────────────────────────────┤
│ Methods Applied:                                    │
│   □ First Principles (1+)                          │
│   □ 5 Whys + 5 Hows (3+ combined)                  │
├─────────────────────────────────────────────────────┤
│ Quality Gates:                                      │
│   □ Line numbers cited                             │
│   □ No vague statements                            │
│   □ Uncertainties marked                           │
│   □ Cross-refs complete                            │
└─────────────────────────────────────────────────────┘
```
