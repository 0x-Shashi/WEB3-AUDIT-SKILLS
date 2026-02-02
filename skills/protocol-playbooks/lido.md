---
id: PLAY-LIDO
title: Lido Secure Integration Guide
protocol: lido
version: core
category: staking
chains: [ethereum]
integration_type: [staking, withdrawals, accounting]
common_mistakes: [rebasing-miscalculation, share-inflation, withdrawal-queue-assumptions]
secure_patterns: [share-accounting, rebasing-guards, withdrawal-validation]
difficulty: advanced
prerequisites: [staking-basics, token-accounting]
audit_checklist_items: 10
last_updated: 2026-01-31
---

# Lido Secure Integration Guide

> **Attack Surface:** See [attack-trees/liquid-staking-attack-tree.md](../attack-trees/liquid-staking-attack-tree.md)

## Summary
Guidance for integrating staking and withdrawal flows with Lido.

## Integration checklist
- Handle rebasing correctly (shares vs. balance).
- Avoid assuming 1:1 share conversions across time.
- Validate withdrawal queue assumptions and delays.
- Track rounding and precision in share math.
- Guard against share inflation edge cases.

## Common mistakes
- Treating stETH as fixed-supply ERC20.
- Ignoring share math when calculating user balances.

## Related patterns
- Rebasing tokens
- Share inflation
- Precision loss
