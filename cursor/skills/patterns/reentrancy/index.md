---
id: PAT-REENTRANCY-INDEX
title: Reentrancy Fractal Map
category: reentrancy
severity: critical
difficulty: intermediate
chains: [ethereum, arbitrum, optimism, polygon, bsc]
tags: [reentrancy, external-call, state-update, callback, invariant]
related_patterns: [reentrancy, external-call, cei, read-only-reentrancy]
finding_count: null
last_updated: 2026-01-31
---

# Reentrancy Fractal Map

## Purpose
This folder decomposes reentrancy into variants with focused checklists, tests, and remediation.

## Variants
- [Classic reentrancy](classic-reentrancy.md)
- [Cross-function reentrancy](cross-function-reentrancy.md)
- [Cross-contract reentrancy](cross-contract-reentrancy.md)
- [Read-only reentrancy](read-only-reentrancy.md)
- [Reentrancy via token receiver hooks](callback-hook-reentrancy.md)

## Shared preconditions
- External call before finalizing state.
- Re-entrant capability via callback, fallback, or hook.
- Missing or incomplete reentrancy guard/CEI.

## Shared controls
- Apply CEI strictly.
- Use reentrancy guards on all entry points touching shared state.
- Pull-payment or escrow patterns for external transfers.
- Snapshot state used across functions or contracts.

## Audit checklist
- Identify all external calls and their reachable callbacks.
- Enumerate shared state touched across functions and contracts.
- Validate that view functions do not depend on mutable state exposed to reentry.
- Confirm hooks (ERC777/721/1155) are guarded.

## Test ideas
- Reenter via fallback and via token hooks.
- Reenter through a different function to violate invariants.
- Trigger reentry across contracts with shared accounting.
