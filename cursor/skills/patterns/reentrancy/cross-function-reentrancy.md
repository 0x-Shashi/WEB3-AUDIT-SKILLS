---
id: PAT-REENTRANCY-CROSS-FUNCTION
title: Cross-Function Reentrancy
category: reentrancy
severity: critical
difficulty: advanced
chains: [ethereum, arbitrum, optimism, polygon, bsc]
tags: [reentrancy, cross-function, shared-state, invariant]
related_patterns: [reentrancy, external-call, cei, invariant-testing]
finding_count: null
last_updated: 2026-01-31
---

# Cross-Function Reentrancy

## Summary
An external call in one function enables reentry into a different function that mutates shared state, breaking invariants across the contract.

## Typical attack flow
1. Function A makes an external call before finalizing state.
2. Attacker reenters Function B that uses shared state.
3. Shared accounting or limits are bypassed.

## Detection signals
- Multiple entry points touching the same storage without a shared guard.
- Checks spread across functions instead of centralized.
- View or helper functions used for validation can be called mid-execution.

## Mitigations
- Apply a shared reentrancy guard across all related entry points.
- Consolidate invariant checks in a single pre- and post-state layer.
- Use internal state locks for multi-function sequences.

## Audit checklist
- Map all shared storage and entry points.
- Confirm guards cover all relevant functions, not just the caller.
- Verify invariants at the end of each external call boundary.

## Test ideas
- Reenter into a different function with shared accounting.
- Reenter into a function that updates limits or roles.
- Reenter during multi-step workflows (deposit → stake → withdraw).
