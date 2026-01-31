---
id: PAT-REENTRANCY-CALLBACK-HOOKS
title: Reentrancy via Token Receiver Hooks
category: reentrancy
severity: high
difficulty: advanced
chains: [ethereum, arbitrum, optimism, polygon, bsc]
tags: [erc777, erc721, erc1155, hooks, reentrancy]
related_patterns: [reentrancy, external-call, erc777, erc721, erc1155]
finding_count: null
last_updated: 2026-01-31
---

# Reentrancy via Token Receiver Hooks

## Summary
Tokens with receiver hooks (ERC777, ERC721, ERC1155) can trigger callbacks mid-transfer, enabling reentrancy into the token sender or recipient contract.

## Typical attack flow
1. Contract transfers tokens to an attacker-controlled receiver.
2. Receiver hook executes and reenters the sender.
3. Sender state is inconsistent, enabling double-withdraw or bypassed checks.

## Detection signals
- Token transfers that occur before final state updates.
- No reentrancy guard on functions that transfer tokens.
- Hooks used as part of business logic validation.

## Mitigations
- Apply CEI around token transfers.
- Use reentrancy guards on token transfer entry points.
- Prefer pull-based token distribution where feasible.

## Audit checklist
- Identify all token transfers with hooks.
- Confirm hook callbacks cannot reenter sensitive functions.
- Validate state after token transfer completion.

## Test ideas
- Reenter via ERC777 `tokensReceived` hook.
- Reenter via ERC721 `onERC721Received` hook.
- Reenter via ERC1155 `onERC1155Received` hook.
