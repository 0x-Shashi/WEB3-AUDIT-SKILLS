---
id: PAT-REENTRANCY-READ-ONLY
title: Read-Only Reentrancy
category: reentrancy
severity: high
difficulty: advanced
chains: [ethereum, arbitrum, optimism, polygon, bsc]
tags: [read-only-reentrancy, oracle, price-manipulation, view-state]
related_patterns: [read-only-reentrancy, oracle, reentrancy]
finding_count: null
last_updated: 2026-01-31
---

# Read-Only Reentrancy

## Summary
A view or read-only function observes transient state during reentrancy, leading to incorrect pricing, collateral ratios, or validation decisions.

## Typical attack flow
1. Contract updates state, then makes an external call.
2. Attacker reenters a view or pricing function.
3. The view reads transient state and returns a manipulated result.

## Detection signals
- View functions used for critical checks within the same transaction.
- Price or ratio calculations that depend on mutable state.
- Use of external calls in the middle of sensitive updates.

## Mitigations
- Use cached values or snapshots for pricing/ratios.
- Avoid calling critical view functions after external calls.
- Recompute or validate invariants at the end of execution.

## Audit checklist
- Identify view functions used in validation logic.
- Check for transient state exposure during external calls.
- Verify final invariants after external call boundaries.

## Test ideas
- Reenter into a pricing function during update.
- Manipulate reported ratios used for liquidation checks.
- Simulate reentry through hooks while view reads state.
