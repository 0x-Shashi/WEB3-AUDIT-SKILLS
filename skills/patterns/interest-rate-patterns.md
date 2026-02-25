---
id: PAT-INTEREST-RATE
title: Interest Rate Security Patterns
category: defi
severity: high
difficulty: advanced
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - interest-rate
  - utilization
  - lending
  - borrowing
  - rate-model
related_patterns:
  - lending-pool-patterns
  - oracle-patterns
  - precision-loss-patterns
  - flash-loan-patterns
finding_count: 24
last_updated: 2026-02-24
---
# Interest Rate Security Patterns

## Overview

**Frequency**: 24 occurrences (0.05% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 1 | 10 | 11 | 2 | 0 |

**Common Sources**: Code4rena, Sherlock, Spearbit

---

## Detection Checklist

- [ ] Verify interest accrual handles zero-duration and max-duration intervals correctly
- [ ] Check utilization rate calculation for manipulation via flash loans or donation
- [ ] Review rate model boundaries (0% utilization, 100% utilization, kink transitions)
- [ ] Analyze compound interest precision loss over long intervals without accrual
- [ ] Test interest index updates for correctness after admin parameter changes

---

## Key Vulnerability Classes

### 1. Utilization Rate Manipulation

Interest rates in lending protocols are typically a function of utilization: `utilization = totalBorrows / totalSupply`. Flash loans can temporarily change utilization to game interest rates.

```solidity
// VULNERABLE: Instantaneous utilization drives rate
function getInterestRate() public view returns (uint256) {
    uint256 utilization = totalBorrows * 1e18 / totalSupply;
    if (utilization < kink) {
        return baseRate + utilization * slope1 / 1e18;
    } else {
        return baseRate + kink * slope1 / 1e18
             + (utilization - kink) * slope2 / 1e18;
    }
    // ⚠ A flash loan deposit can drop utilization to near-zero
    //    and a flash loan borrow can spike it to near-100%
}
```

**Attack scenarios**:
- Flash deposit → lower utilization → lower borrow rate → borrow cheaply → repay flash deposit
- Flash borrow → spike utilization → force rate into high-slope region → grief existing borrowers

### 2. Compound Interest Precision Loss

When interest accrues block-by-block or per-second, precision loss compounds. Protocols that don't accrue frequently enough lose precision.

```solidity
// VULNERABLE: Per-second compounding with small rates
function accrueInterest() external {
    uint256 elapsed = block.timestamp - lastAccrual;
    uint256 interestFactor = ratePerSecond * elapsed;
    // ⚠ If ratePerSecond = 1 (very small), and elapsed = 1:
    //    interestFactor = 1, but totalBorrows * 1 / 1e18 = 0
    //    Interest is lost for small balances
    
    uint256 interest = totalBorrows * interestFactor / 1e18;
    totalBorrows += interest;
    lastAccrual = block.timestamp;
}
```

**Fix**: Use exponential math (`exp(rate * time)`) or accumulate index multipliers:
```solidity
// SECURE: Index-based accrual
borrowIndex = borrowIndex * (1e18 + ratePerSecond * elapsed) / 1e18;
// User's debt = principalBorrow * currentIndex / userIndex
```

### 3. Rate Model Kink Transition Bugs

Two-slope rate models have a "kink" at an optimal utilization. Bugs at the kink boundary:

```solidity
// VULNERABLE: Gap at kink
function getRate(uint256 util) public view returns (uint256) {
    if (util < kink) {
        return baseRate + util * slope1 / 1e18;
    }
    if (util > kink) { // ⚠ What about util == kink? Off-by-one gap
        return baseRate + kink * slope1 / 1e18 + (util - kink) * slope2 / 1e18;
    }
    return baseRate; // Wrong rate at exactly kink utilization
}
```

### 4. Interest Accrual on Admin Parameter Change

When admin updates interest rate model parameters (slopes, kink, base rate), interest must be accrued up to the current moment using old parameters before new parameters take effect.

```solidity
// VULNERABLE: Parameters changed without accruing
function setRateModel(uint256 newSlope1, uint256 newSlope2) external onlyAdmin {
    slope1 = newSlope1; // ⚠ All unaccrued interest retroactively uses new rate
    slope2 = newSlope2;
}

// SECURE: Accrue before changing
function setRateModel(uint256 newSlope1, uint256 newSlope2) external onlyAdmin {
    accrueInterest(); // Settle all interest at old rate first
    slope1 = newSlope1;
    slope2 = newSlope2;
}
```

### 5. Variable Rate Borrow Index Rounding

Borrow index accumulation is multiplicative. With each accrual, the index is multiplied by `(1 + rate * dt)`. Rounding direction matters:

```solidity
// Each user's debt = principal * currentIndex / userBorrowIndex
// If currentIndex rounds DOWN by 1 wei each accrual:
//   Over 1 year at per-second accrual = 31.5M accruals
//   Accumulated loss can be significant

// FIX: Always round interest accrual UP (against borrower)
uint256 interestFactor = (ratePerSecond * elapsed + ROUND_UP_OFFSET);
```

---

## Real-World Examples

### Example 1: [H-01] Interest rate manipulation via flash loan deposit

**Source**: Sherlock
**Protocol**: Various Lending Protocols
**Impact**: HIGH

**Details**:

Attacker flash-loans a large amount, deposits into the lending pool (drastically reducing utilization), borrows at the now-lowered interest rate in a subsequent transaction, then the flash loan deposit is removed. The borrower locked in a rate set during the manipulated utilization.

---

### Example 2: [M-03] Stale interest accrual leads to incorrect liquidation threshold

**Source**: Code4rena
**Protocol**: Compound Fork
**Impact**: MEDIUM

**Details**:

Interest accrual was not called before checking health factors. Borrowers with positions near the liquidation threshold could avoid liquidation because their accrued interest wasn't reflected in the health factor check. Conversely, healthy positions could appear liquidatable if supply interest wasn't accrued.

---

### Example 3: [H-02] Rate model parameter change retroactively applies to unaccrued interest

**Source**: Spearbit
**Protocol**: Custom Lending Protocol
**Impact**: HIGH

**Details**:

Admin changed the interest rate slope from 5% to 50% without calling `accrueInterest()` first. All interest accumulated since the last accrual (potentially hours) was retroactively calculated at the 50% rate, causing borrowers to be instantly undercollateralized and liquidatable.

---

## Interaction with Other Patterns

| Combined With | Creates Risk |
|---------------|-------------|
| Flash loans | Utilization rate manipulation |
| Oracle manipulation | Interest calculated on manipulated asset values |
| Precision loss | Compound interest truncation over time |
| Admin actions | Retroactive rate changes without accrual |
| Liquidation | Stale interest makes health factors incorrect |

---

## Recommended Secure Patterns

1. **Accrue before state change**: Always call `accrueInterest()` before any parameter update
2. **Index-based tracking**: Use multiplicative index for debt tracking, not absolute amounts
3. **Round against user**: Interest accrual rounds up (against borrower), share conversion rounds down (against depositor)
4. **Flash loan resistance**: Use time-weighted utilization or restrict rate changes within same block
5. **Bounded rates**: Enforce `minRate <= rate <= maxRate` to prevent extreme manipulation
6. **Continuous accrual**: Call `accrueInterest()` in all external functions that read or write supply/borrow state
