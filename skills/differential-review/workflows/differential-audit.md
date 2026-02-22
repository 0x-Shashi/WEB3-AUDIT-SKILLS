---
id: DIFF-WF-AUDIT
title: Differential Audit Workflow
parent: differential-review
type: workflow
last_updated: 2025-01-31
---

# Differential Audit Workflow

Step-by-step workflow for auditing code changes between two versions. This is more efficient than a full re-audit when most code is unchanged.

---

## Prerequisites

| Requirement | Details |
|-------------|----------|
| Base version | Previously audited commit/tag |
| New version | Current commit to review |
| Previous audit report | Findings from base version |
| Git access | Ability to generate diffs |

---

## Step 1: Diff Generation

Generate a clean diff of security-relevant files:

```bash
# Full diff (contracts only, exclude tests)
git diff v1.0..v2.0 -- 'contracts/**/*.sol' ':!contracts/test' ':!contracts/mock'

# File-level summary
git diff v1.0..v2.0 --stat -- '*.sol'

# Show only changed file names
git diff v1.0..v2.0 --name-only -- 'contracts/'

# Show changes with context
git diff v1.0..v2.0 -U10 -- 'contracts/'  # 10 lines context
```

**Output:** List of modified/added/deleted files with exact changes.

---

## Step 2: Change Classification

For each changed file, classify the changes:

| Category | Description | Action |
|----------|-------------|--------|
| **Logic** | Modified calculations, conditions, state transitions | FULL REVIEW |
| **Access Control** | Changed modifiers, role checks, permissions | CRITICAL REVIEW |
| **State** | New/modified/removed storage variables | STORAGE LAYOUT CHECK |
| **Configuration** | Changed constants, thresholds, addresses | VERIFY VALUES |
| **Dependencies** | Updated imports, library versions | CHECK CHANGELOGS |
| **Formatting** | Whitespace, comments, naming | SKIP |
| **New Code** | Entirely new functions or contracts | FULL AUDIT as new code |
| **Removed Code** | Deleted functions or contracts | VERIFY NO ORPHANS |

### Classification Template

```
File: contracts/Pool.sol
- Line 45: LOGIC - Changed fee calculation from fixed to dynamic
- Line 78: ACCESS - Added onlyAdmin modifier to setFee()
- Line 92: STATE - New variable `uint256 public dynamicFee`
- Line 15: DEP - Updated OZ import from 4.8 to 5.0
- Line 30: FORMAT - Renamed local variable (no-op)
```

---

## Step 3: Impact Assessment

For each logic change, perform impact analysis:

### Questions to Answer

1. **What was the intent?** Why was this changed?
2. **What did it do before?** Precise behavior of V1
3. **What does it do now?** Precise behavior of V2
4. **What could go wrong?** Unintended consequences
5. **What depends on this?** Other functions affected
6. **Were tests updated?** Does test coverage match changes

### Impact Template

```
Change: Pool.sol:45 - Fee calculation
Intent: Support dynamic fees based on utilization
Before: fee = amount * 30 / 10000 (fixed 0.3%)
After:  fee = amount * dynamicFee / 10000
Risks:
  - dynamicFee could be set to 10000 (100% fee = drain)
  - dynamicFee could be set to 0 (no fees = protocol insolvent)
  - Division precision loss if amount * dynamicFee < 10000
Dependencies: withdraw(), swap(), all functions calling _calculateFee()
Tests: test_dynamic_fee_calculation() added ✔
       test_fee_bounds() NOT added ✖
```

---

## Step 4: New Code Audit

All newly added functions and contracts require a **full audit** as if they're new:

- [ ] Apply standard audit methodology to all new code
- [ ] Check access control on new functions
- [ ] Verify new state variables properly initialized
- [ ] Check for reentrancy in new external call patterns
- [ ] Verify new events emitted correctly
- [ ] Check new code integrates safely with existing code

---

## Step 5: Modified Code Audit

For each modified function:

- [ ] Verify the change achieves its stated intent
- [ ] Check if modified function still satisfies its invariants
- [ ] Look for introduced edge cases (zero values, overflow, underflow)
- [ ] Verify callers of modified function still work correctly
- [ ] Check if modified function's return values changed
- [ ] Verify events still emitted correctly after changes

---

## Step 6: Removed Code Analysis

For each deleted function or contract:

- [ ] Was the removed code security-critical? (Access control, reentrancy guard, etc.)
- [ ] Are there orphaned references to removed code? (Will cause compile errors or silent failures)
- [ ] Was the removed code replaced by something equivalent?
- [ ] Did any integrations depend on removed functions?

---

## Step 7: Storage Layout Verification

For upgradeable contracts:

```bash
# Compare storage layouts
forge inspect ContractV1 storage-layout > v1.json
forge inspect ContractV2 storage-layout > v2.json
jq -r '.storage[] | [.slot, .offset, .type, .label] | @tsv' v1.json > v1.tsv
jq -r '.storage[] | [.slot, .offset, .type, .label] | @tsv' v2.json > v2.tsv
diff v1.tsv v2.tsv
```

- [ ] No existing slots changed type or position
- [ ] New variables appended after existing ones (or use gap slots)
- [ ] `__gap` reduced appropriately
- [ ] Inherited contract storage unchanged
- [ ] See [Upgrade Safety](resources/upgrade-safety.md) for detailed checks

---

## Step 8: Integration Testing

- [ ] Existing test suite passes on new version
- [ ] New tests added for changed functionality
- [ ] Edge case tests added for new parameters/values
- [ ] Integration tests verify unchanged behavior where expected
- [ ] Upgrade test simulates the actual upgrade process

---

## Step 9: Report

### Differential Report Structure

```markdown
# Differential Audit Report: V1 → V2

## Overview
- Base version: [commit/tag]
- New version: [commit/tag]
- Files changed: [count]
- Functions modified: [count]
- New functions: [count]
- Removed functions: [count]

## Change Summary
| File | Changes | Category | Reviewed |
|------|---------|----------|----------|
| Pool.sol | Fee logic | Logic | ✔ |
| Admin.sol | New role | Access | ✔ |

## Findings
[Standard finding format]

## Storage Layout Verification
[✔ Compatible / ✖ Incompatible with details]

## Previous Findings Status
| ID | V1 Finding | Status in V2 |
|----|-----------|---------------|
| H-01 | Reentrancy in withdraw | Fixed |
| M-01 | Missing zero check | Still present |
```

### Key: Always verify previous findings are still fixed (or newly introduced by the changes).
