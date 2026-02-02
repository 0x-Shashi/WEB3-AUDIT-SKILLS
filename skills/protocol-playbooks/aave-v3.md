---
id: PLAY-AAVE-V3
title: Aave V3 Secure Integration Guide
protocol: aave
version: v3
category: lending
chains: [ethereum, arbitrum, optimism, polygon]
integration_type: [deposit, borrow, repay, liquidation]
common_mistakes: [oracle-misuse, wrong-decimals, missing-e-mode-checks, interest-rate-assumptions]
secure_patterns: [oracle-validation, health-factor-checks, e-mode-guardrails]
difficulty: advanced
prerequisites: [lending-basics, oracle-patterns]
audit_checklist_items: 12
last_updated: 2026-01-31
---

# Aave V3 Secure Integration Guide

> **Attack Surface:** See [attack-trees/lending-attack-tree.md](../attack-trees/lending-attack-tree.md)

## Summary
Integration guidance for deposit, borrow, and liquidation flows using Aave V3.

## Integration checklist
- Validate oracle feeds and decimals for all assets.
- Check health factor before and after operations.
- Respect E-Mode constraints per asset category.
- Avoid assumptions about interest rate modes.
- Ensure liquidation paths handle price changes safely.

## Common mistakes
- Using stale oracles.
- Incorrect decimals leading to bad accounting.
- Ignoring E-Mode or isolation mode rules.

## Related patterns
- Oracle
- Decimals
- Liquidation
- Validation
