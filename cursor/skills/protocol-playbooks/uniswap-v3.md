---
id: PLAY-UNISWAP-V3
title: Uniswap V3 Secure Integration Guide
protocol: uniswap
version: v3
category: dex
chains: [ethereum, arbitrum, optimism, polygon, base]
integration_type: [swap, liquidity, oracle]
common_mistakes: [slippage-not-set, deadline-not-enforced, price-manipulation, callback-reentrancy]
secure_patterns: [exact-input-single, twap-oracle, deadline-validation]
difficulty: advanced
prerequisites: [defi-basics, amm-mechanics, oracle-patterns]
audit_checklist_items: 12
last_updated: 2026-01-31
---

# Uniswap V3 Secure Integration Guide

## Summary
Guidance for safe swaps, liquidity positions, and oracle usage when integrating Uniswap V3.

## Integration checklist
- Always enforce a deadline and maximum slippage.
- Use TWAP for pricing decisions; avoid spot price dependency.
- Ensure callbacks (`uniswapV3SwapCallback`) cannot reenter sensitive state.
- Validate token ordering and fee tiers.
- Sanitize recipient addresses for swaps and collects.

## Common mistakes
- Missing deadline checks.
- Using spot prices for collateral or liquidation.
- Reentrancy through callback paths.

## Related patterns
- Slippage
- TWAP
- External call ordering
- Read-only reentrancy
