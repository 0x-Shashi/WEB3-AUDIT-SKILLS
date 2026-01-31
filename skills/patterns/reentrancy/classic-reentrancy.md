---
id: PAT-REENTRANCY-CLASSIC
title: Classic Reentrancy (Single-Function)
category: reentrancy
severity: critical
difficulty: intermediate
chains: [ethereum, arbitrum, optimism, polygon, bsc]
tags: [reentrancy, external-call, state-update, withdrawal]
related_patterns: [reentrancy, external-call, cei, withdraw-pattern]
finding_count: null
last_updated: 2026-01-31
---

# Classic Reentrancy (Single-Function)

## Summary
Occurs when a function performs an external call before updating its own state, allowing the callee to reenter the same function and drain funds or bypass limits.

## Typical attack flow
1. User calls a withdraw-like function.
2. Contract makes an external call.
3. Attacker reenters before state update.
4. Balance checks are bypassed or repeated.

## Detection signals
- External call placed before balance decrement.
- No reentrancy guard on withdraw paths.
- Multiple external calls in a single path.

## Mitigations
- Apply CEI: update state before external calls.
- Add reentrancy guards on all exit paths.
- Use pull-based withdrawals with internal escrow.

## Audit checklist
- Verify state updates precede external calls.
- Confirm `nonReentrant` on all withdraw-like functions.
- Ensure accounting uses cached balances.

## Test ideas
- Reenter the same function twice.
- Reenter after partial state updates.
- Reenter via fallback on low-level `call`.
