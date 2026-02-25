---
id: PAT-ACCOUNTING
title: Accounting Security Patterns
category: defi
severity: high
difficulty: intermediate
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - accounting
  - balance-tracking
  - internal-state
  - fee-calculation
  - share-price
related_patterns:
  - precision-loss-patterns
  - rounding-patterns
  - erc4626-patterns
  - deposit-reward-tokens-patterns
finding_count: 45
last_updated: 2026-02-24
---
# Accounting Security Patterns

## Overview

**Frequency**: 45 occurrences (0.09% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 5 | 19 | 17 | 4 | 0 |

**Common Sources**: Code4rena, Sherlock, Spearbit, Cyfrin

---

## Detection Checklist

- [ ] Verify internal accounting matches actual token balances (no donation attack vectors)
- [ ] Check that fee deductions are applied before state updates, not after
- [ ] Review all share/asset conversion math for precision loss in both directions
- [ ] Analyze rebasing token and fee-on-transfer token compatibility with accounting logic
- [ ] Test state consistency after partial fills, failed transfers, and edge cases (0, max, 1 wei)

---

## Key Vulnerability Classes

### 1. Balance vs Internal Accounting Desync

The most fundamental accounting bug: using `token.balanceOf(address(this))` directly instead of tracking internal state, or vice versa, failing to reconcile the two.

```solidity
// VULNERABLE: Using balanceOf for accounting
function deposit(uint256 amount) external {
    token.transferFrom(msg.sender, address(this), amount);
    shares[msg.sender] = token.balanceOf(address(this)); // ⚠ Includes all tokens, not just this deposit
}

// VULNERABLE: Internal tracking without reconciliation
function withdraw(uint256 shares) external {
    uint256 amount = (shares * totalDeposited) / totalShares;
    totalDeposited -= amount;
    totalShares -= shares;
    token.transfer(msg.sender, amount);
    // ⚠ If fee-on-transfer token, actual sent < amount, but state already updated
}
```

**Core principle**: Internal state should track deposits/withdrawals. Use `balanceOf` only for sanity checks or donation-resistant patterns that compute deltas.

### 2. Donation Attack (Direct Transfer Manipulation)

An attacker sends tokens directly to a contract (bypassing `deposit()`) to inflate the asset-per-share ratio, causing rounding errors that steal from subsequent depositors.

```solidity
// Attack flow:
// 1. Deposit 1 wei → receive 1 share
// 2. Donate 10_000e18 tokens directly to contract
// 3. Now: 1 share = 10_000e18 + 1 assets
// 4. Victim deposits 9_999e18 → receives 0 shares (rounds down)
// 5. Attacker withdraws 1 share → gets 20_000e18

// FIX: Track deposits internally, ignore donation
function deposit(uint256 amount) external {
    shares = (amount * totalShares) / totalTrackedAssets; // Use internal, not balanceOf
    totalTrackedAssets += amount;
}
```

### 3. Fee Calculation Ordering

Whether fees are deducted before or after share calculation drastically affects outcomes.

```solidity
// Method A: Fee before shares (safer for protocol)
uint256 netAmount = amount - fee;
uint256 shares = (netAmount * totalShares) / totalAssets;

// Method B: Fee after shares (safer for user)
uint256 shares = (amount * totalShares) / totalAssets;
uint256 feeShares = (shares * feeRate) / 10000;
shares -= feeShares;

// ⚠ Inconsistency between deposit/withdraw fee application
// creates arbitrage: deposit via cheaper method, withdraw via cheaper method
```

### 4. Multi-Token Accounting Drift

Protocols managing multiple tokens (LP pools, multi-collateral vaults) must maintain consistent accounting across all tokens. Drift occurs when:

- One token's balance updates but the corresponding token's accounting doesn't
- Fractional token shares vs base token shares diverge (Caviar)
- Protocol fees are deducted from one token but not reflected in pair accounting

```solidity
// VULNERABLE: Asymmetric fee application
function removeLiquidity(uint256 lpTokens) external {
    uint256 amount0 = (lpTokens * reserve0) / totalSupply;
    uint256 amount1 = (lpTokens * reserve1) / totalSupply;
    uint256 fee0 = amount0 * exitFee / 10000;
    // ⚠ fee1 not calculated — asymmetric fee application
    _transfer(token0, msg.sender, amount0 - fee0);
    _transfer(token1, msg.sender, amount1);
}
```

### 5. Rebasing Token Incompatibility

Rebasing tokens (stETH, AMPL) change balances in-place. Protocols using `balanceOf` will see phantom gains/losses; protocols using internal tracking will lose sync with reality.

```solidity
// Both approaches fail with rebasing tokens:

// Internal tracking: misses rebase events
totalDeposited = 100e18; // Tracked
// stETH rebases: balanceOf is now 105e18
// 5e18 is stuck — accounting doesn't know about it

// BalanceOf tracking: vulnerable to donation
uint256 assets = stETH.balanceOf(address(this));
// Anyone can wrap/unwrap or donate to manipulate this
```

**Fix**: Use wrapper tokens (wstETH) or implement rebase-aware accounting with periodic sync.

---

## Real-World Examples

### Example 1: [H-01] Internal accounting desync allows fund extraction

**Source**: Code4rena
**Protocol**: Multiple DeFi Protocols
**Impact**: CRITICAL

**Details**:

Protocol tracked deposits in an internal `totalAssets` variable but used `balanceOf()` for share price calculations. An attacker donated tokens to inflate `balanceOf` relative to `totalAssets`, causing share minting to use inflated values. Subsequent withdrawals using `totalAssets` returned less than deposited.

---

### Example 2: [H-03] Fee-on-transfer token breaks accounting

**Source**: Sherlock
**Protocol**: Various
**Impact**: HIGH

**Details**:

When a user deposits a fee-on-transfer token, the contract credits them for `amount` but only receives `amount - fee`. The deficit accumulates with each deposit. Eventually the last withdrawers cannot withdraw because the contract's actual balance is less than the internal accounting claims.

```solidity
// deposits 100 USDT (2% fee), contract receives 98
// internal: userBalance[user] = 100
// actual: balanceOf(this) = 98
// After 50 deposits of 100: internal says 5000, actual has 4900
// Last depositors can't withdraw
```

---

### Example 3: [M-01] Precision loss in share-to-asset conversion creates extractable rounding error

**Source**: Code4rena
**Protocol**: Numoen (Invariant function)
**Impact**: MEDIUM

**Details**:

The invariant function `L^2 = x * y` introduces squared precision loss. When converting between shares and assets, the protocol lost precision in intermediate calculations. Repeated deposit/withdraw cycles could extract value through accumulated rounding in the user's favor.

---

## Interaction with Other Patterns

| Combined With | Creates Risk |
|---------------|-------------|
| ERC4626 vaults | Share inflation via donation attacks |
| Fee-on-transfer tokens | Internal balance desync |
| Rebasing tokens | Phantom balance changes break tracking |
| Flash loans | Temporary balance inflation for share manipulation |
| Precision loss | Accumulated rounding creates extractable arbitrage |

---

## Recommended Secure Patterns

1. **Internal tracking with delta**: Track deposits/withdrawals internally; use `balanceOf` delta for actual received amount
2. **Virtual offset (dead shares)**: Initialize vaults with virtual assets/shares to prevent donation attacks
3. **Check-then-update**: Always measure actual received (`balanceAfter - balanceBefore`) before updating state
4. **Consistent fee direction**: Round fees against the user (in favor of protocol) on both deposit and withdraw
5. **Rebasing wrappers**: Use non-rebasing wrappers (wstETH, not stETH) for all internal accounting
6. **Invariant assertions**: Add `assert(totalInternalBalance <= token.balanceOf(this))` as sanity checks
