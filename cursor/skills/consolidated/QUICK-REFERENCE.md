---
id: PAT-QUICK-REFERENCE
title: QUICK REFERENCE Security Patterns
category: general
severity: medium
difficulty: intermediate
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - security
  - vulnerability


last_updated: 2026-01-31
---
# Quick Reference - Web3 Security Patterns

A rapid lookup guide for AI auditors. Each pattern has a one-line summary to quickly identify vulnerabilities.

---

## How to Use

1. **Scan this file first** to identify potential vulnerability categories
2. **Load the relevant consolidated file** for detailed analysis with real-world examples

---

## Consolidated Files Reference

| File | Focus Area | Size |
|------|------------|------|
| token-patterns.md | ERC20/721/777/1155, fee-on-transfer, rebasing, approvals | 387 KB |
| defi-patterns.md | Flash loans, oracles, vaults, liquidation, AMMs | 685 KB |
| reentrancy-patterns.md | All reentrancy types, CEI, external calls | 140 KB |
| access-control-patterns.md | Auth, admin, ownership, pause, blacklists | 197 KB |
| math-precision-patterns.md | Rounding, overflow, decimals, truncation | 239 KB |
| validation-patterns.md | Input checks, missing logic, limits | 202 KB |
| dos-gas-patterns.md | DoS, gas griefing, loops, dust attacks | 275 KB |
| upgrade-storage-patterns.md | Proxy, storage collision, initialization | 127 KB |
| signature-crypto-patterns.md | Signatures, replay, EIP-712, Merkle | 76 KB |
| cross-chain-l2-patterns.md | Bridges, L2, sequencer, LayerZero | 125 KB |
| nft-governance-patterns.md | NFT, royalties, voting, DAO, auctions | 128 KB |
| misc-patterns.md | Timing, events, code quality, other | 330 KB |

---

## Token Vulnerabilities

| Pattern | One-Line Summary | Severity |
|---------|------------------|----------|
| Fee-on-Transfer | Tokens that take fees reduce actual received amount vs expected | High |
| Rebasing Tokens | Token balance changes without transfers breaks accounting | High |
| ERC777 Hooks | Reentrancy via tokensReceived/tokensToSend callbacks | Critical |
| Double-Spend Approve | approve() race condition allows spending old + new allowance | Medium |
| Missing Return Value | Some tokens don't return bool on transfer (USDT) | Medium |
| Blacklist Tokens | USDC/USDT can freeze addresses, breaking withdrawals | Medium |
| Pausable Tokens | Token can be paused, blocking all transfers | Medium |
| Decimals Assumption | Assuming 18 decimals when tokens have 6 or other | High |
| Zero Address Transfer | Some tokens allow transfer to address(0) | Medium |
| SafeTransfer Missing | Using transfer() instead of safeTransfer() for ERC721 | Medium |

---

## DeFi Vulnerabilities

| Pattern | One-Line Summary | Severity |
|---------|------------------|----------|
| Flash Loan Attack | Manipulate prices/state within single atomic transaction | Critical |
| First Depositor | Attacker inflates share price to steal from next depositors | High |
| Oracle Manipulation | Stale/manipulated price data leads to incorrect valuations | Critical |
| Sandwich Attack | Front-run + back-run user's swap for profit | High |
| Slippage Not Checked | No minAmountOut allows MEV extraction | High |
| Chainlink Stale Price | Using outdated price when oracle hasn't updated | High |
| TWAP Manipulation | Low liquidity allows price manipulation over time window | Medium |
| Share Inflation | Donate to vault to inflate share price | High |
| Liquidation Bonus | Incorrect liquidation incentive calculation | High |
| Vault Rounding | Rounding errors in deposit/withdraw favor attacker | Medium |

---

## Reentrancy

| Pattern | One-Line Summary | Severity |
|---------|------------------|----------|
| Classic Reentrancy | External call before state update allows re-entry | Critical |
| Read-Only Reentrancy | View function reads stale state during callback | High |
| Cross-Function | Reentrancy across multiple functions sharing state | Critical |
| Cross-Contract | Reentrancy between different contracts | Critical |
| ERC777 Callback | tokensReceived hook enables reentrancy | High |
| ERC721 onReceived | safeTransfer callback enables reentrancy | High |
| ERC1155 Callback | onERC1155Received enables reentrancy | High |
| Modifier Bypass | Reentrancy guard not on internal functions | High |
| CEI Violation | Checks-Effects-Interactions pattern not followed | Critical |

---

## Access Control

| Pattern | One-Line Summary | Severity |
|---------|------------------|----------|
| Missing Access Control | Critical function callable by anyone | Critical |
| tx.origin Auth | Using tx.origin instead of msg.sender for auth | Critical |
| Centralization Risk | Single admin can rug/freeze all funds | High |
| Missing Zero Check | Admin can be set to address(0) | High |
| Privilege Escalation | Lower role can gain higher privileges | Critical |
| Front-Run Initialize | Attacker initializes proxy before owner | Critical |
| Renounce Ownership | Owner can't be recovered after renouncing | Medium |
| Delegatecall to User | User-controlled address in delegatecall | Critical |

---

## Math & Precision

| Pattern | One-Line Summary | Severity |
|---------|------------------|----------|
| Division Before Multiply | Precision loss from dividing before multiplying | High |
| Rounding Direction | Rounding should favor protocol, not attacker | Medium |
| Phantom Overflow | Unchecked math in loops/calculations | High |
| Truncation | Casting larger type to smaller loses data | Medium |
| Decimals Mismatch | Different token decimals not normalized | High |
| Zero Division | Division by zero reverts entire transaction | Medium |
| 1/64 Rule | Only 63/64 gas forwarded to subcalls | Medium |

---

## Validation Issues

| Pattern | One-Line Summary | Severity |
|---------|------------------|----------|
| Missing Zero Check | address(0) or amount=0 not validated | Medium |
| Array Length Mismatch | Two arrays expected same length but not checked | High |
| Unchecked Return | External call return value ignored | High |
| from == to | Transfer to self can break logic | Medium |
| Duplicate Items | Array can contain duplicates causing issues | Medium |
| Bounds Check Missing | Array index can exceed length | High |
| Timestamp Manipulation | block.timestamp can be manipulated by miners | Low |

---

## DoS & Gas

| Pattern | One-Line Summary | Severity |
|---------|------------------|----------|
| Unbounded Loop | Loop over user-controlled array causes gas limit | High |
| Push Over Pop | Array grows but never shrinks | Medium |
| External Call in Loop | Single failed call reverts entire batch | High |
| Block Gas Limit | Transaction too large to fit in block | High |
| Dust Attack | Sending tiny amounts to grief gas costs | Low |
| Griefing | Attacker makes operations expensive for others | Medium |
| Fund Lock | Funds become permanently unwithdrawable | Critical |

---

## Upgrade & Storage

| Pattern | One-Line Summary | Severity |
|---------|------------------|----------|
| Storage Collision | Proxy and implementation storage slots overlap | Critical |
| Missing Storage Gap | No __gap for future storage in upgradeable | High |
| Initializer Missing | initialize() can be called multiple times | Critical |
| Uninitialized Proxy | Proxy deployed but not initialized | Critical |
| Selfdestruct in Impl | Implementation can be destroyed | Critical |
| Immutable in Proxy | Immutable variables don't work in proxies | High |

---

## Signatures & Crypto

| Pattern | One-Line Summary | Severity |
|---------|------------------|----------|
| Signature Malleability | Same signature can have multiple valid forms | High |
| Missing Nonce | Signature can be replayed | Critical |
| Cross-Chain Replay | Signature valid on multiple chains | High |
| Missing Deadline | Signature never expires | Medium |
| ecrecover Returns 0 | Invalid signature returns address(0) not revert | High |
| EIP-712 Domain | Missing chainId or contract address in domain | High |

---

## Cross-Chain & L2

| Pattern | One-Line Summary | Severity |
|---------|------------------|----------|
| Sequencer Down | L2 sequencer offline breaks price feeds | High |
| Message Replay | Cross-chain message replayed on same/different chain | Critical |
| Bridge Double-Spend | Withdraw same funds on multiple chains | Critical |
| L2 Gas Price | Gas pricing different on L2 vs mainnet | Medium |
| Reorg Risk | Block reorgs on L2 can reverse transactions | High |

---

## NFT & Governance

| Pattern | One-Line Summary | Severity |
|---------|------------------|----------|
| Flash Loan Governance | Borrow tokens, vote, return in same block | Critical |
| Vote Manipulation | Voting power calculated incorrectly | High |
| Royalty Bypass | Marketplace avoids paying creator royalties | Medium |
| Unsafe Mint | mint() doesn't check recipient can receive | Medium |
| Checkpoint Missing | Historical balance not tracked for voting | High |

---

## Quick Detection Checklist

```
REENTRANCY
[ ] External calls before state updates?  Reentrancy risk
[ ] Using transfer/send for ETH?  Reentrancy safe but DoS risk
[ ] Callback functions (onERC721Received, etc.)?  Check for reentrancy
[ ] ReentrancyGuard on all external functions?  May have gaps

MATH
[ ] Division before multiplication?  Precision loss
[ ] Unchecked blocks in Solidity 0.8+?  Intentional overflow risk
[ ] Different token decimals?  Normalization needed
[ ] Rounding in share calculations?  Check direction favors protocol

ACCESS CONTROL
[ ] Critical function without modifier?  Anyone can call
[ ] Using tx.origin?  Phishing vulnerability
[ ] initialize() without initializer modifier?  Can reinitialize
[ ] Single owner with no timelock?  Centralization risk

VALIDATION
[ ] Unchecked external call return?  Silent failures
[ ] Missing zero address check?  Permanent loss
[ ] Array iteration without bounds?  DoS risk
[ ] User input used directly in calculations?  Manipulation risk

ORACLE
[ ] Single price source?  Manipulation risk
[ ] No staleness check on Chainlink?  Using outdated price
[ ] TWAP with short window?  Easily manipulated
[ ] Spot price from AMM?  Flash loan manipulation

TOKENS
[ ] Assuming 18 decimals?  Check actual decimals
[ ] Not using SafeERC20?  Missing return value
[ ] Hardcoded token addresses?  Inflexible
[ ] No fee-on-transfer handling?  Accounting mismatch
```

---

## Severity Guide

| Severity | Definition |
|----------|------------|
| Critical | Direct loss of funds, complete protocol compromise |
| High | Significant fund loss, major functionality break |
| Medium | Limited fund loss, workarounds exist |
| Low | Minor issues, informational |

---

*Total: 207 vulnerability patterns from 50,530 real audit findings*
