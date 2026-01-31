---
id: PAT-REENTRANCY-CROSS-CONTRACT
title: Cross-Contract Reentrancy
category: reentrancy
severity: critical
difficulty: advanced
chains: [ethereum, arbitrum, optimism, polygon, bsc]
tags: [reentrancy, external-call, external-contract, callback]
related_patterns: [reentrancy, external-contract, external-call, cei]
finding_count: null
last_updated: 2026-01-31
---

# Cross-Contract Reentrancy

## Summary
Reentrancy occurs through interactions between contracts that share accounting or rely on callbacks, enabling reentry through an external dependency.

## Typical attack flow
1. Contract A calls Contract B before finalizing state.
2. Contract B calls back into Contract A (directly or via another contract).
3. Contract A executes with inconsistent or unfinalized state.

## Detection signals
- External integrations that include callbacks or hooks.
- Shared state split across multiple contracts without shared locks.
- Assumptions that an external contract is "trusted".

## Mitigations
- Guard all external entry points, not only internal ones.
- Use explicit callback interfaces with strict invariants.
- Separate accounting updates from external integration calls.

## Audit checklist
- Trace every external call chain for callbacks.
- Confirm guards span cross-contract entry points.
- Validate that shared state is finalized before leaving the contract.

## Test ideas
- Create a malicious integration contract that reenters.
- Reenter via a proxy or delegate call path.
- Trigger reentry after partial cross-contract state sync.
