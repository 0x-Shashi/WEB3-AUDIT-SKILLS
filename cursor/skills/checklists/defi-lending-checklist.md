---
id: CHECKLIST-DEFI-LENDING
title: DeFi Lending Protocol Audit Checklist
category: checklists
difficulty: intermediate
tags: [lending, borrowing, liquidation, collateral, interest-rate]
last_updated: 2026-01-31
---

# DeFi Lending Protocol Audit Checklist

Quick-reference checklist for auditing lending protocols like Aave, Compound, and custom implementations.

---

## 🔴 Critical Checks

### Collateral & Borrowing
```
[ ] Can users borrow more than their collateral allows?
[ ] Is collateral factor properly enforced?
[ ] Can collateral be withdrawn while loan is outstanding?
[ ] Are all collateral types properly valued?
[ ] Is there a maximum borrow limit per asset/user?
```

### Liquidation
```
[ ] Can healthy positions be liquidated?
[ ] Can underwater positions avoid liquidation?
[ ] Is liquidation incentive reasonable (5-15%)?
[ ] Can liquidator extract more than allowed?
[ ] Are bad debt positions handled?
[ ] Is there a liquidation threshold vs collateral factor gap?
```

### Price Oracles
```
[ ] What oracle is used? (Chainlink, TWAP, custom)
[ ] Can oracle be manipulated within one block?
[ ] Is there a fallback oracle?
[ ] Are stale prices rejected?
[ ] Is there price deviation check between sources?
[ ] L2: Is sequencer uptime checked?
```

---

## 🟠 High Priority Checks

### Interest Rate Model
```
[ ] Can interest rate be manipulated?
[ ] Is utilization calculated correctly?
[ ] Can rates go to infinity (div by zero)?
[ ] Are rates updated atomically with borrows/repays?
[ ] Is there a maximum interest rate cap?
```

### Share/Token Accounting
```
[ ] First depositor attack possible? (share inflation)
[ ] Rounding: Always in protocol's favor?
[ ] Can total shares/assets desync?
[ ] Are virtual assets/shares used for protection?
[ ] ERC4626 compliant if using vault standard?
```

### Flash Loans
```
[ ] Is flash loan fee enforced?
[ ] Can flash loans manipulate internal state?
[ ] Reentrancy during flash loan callback?
[ ] Can flash loan bypass borrow limits?
```

---

## 🟡 Medium Priority Checks

### Token Handling
```
[ ] Fee-on-transfer tokens handled?
[ ] Rebasing tokens handled?
[ ] ERC-777 reentrancy via hooks?
[ ] Token with multiple addresses?
[ ] Tokens with non-standard decimals?
[ ] Return value of transfer checked?
```

### Access Control
```
[ ] Who can pause the protocol?
[ ] Who can update interest rates?
[ ] Who can add/remove collateral types?
[ ] Who can update oracle addresses?
[ ] Are there timelocks on admin functions?
[ ] Can admin drain funds directly?
```

### Edge Cases
```
[ ] Zero amount deposits/withdrawals?
[ ] Maximum uint256 amounts?
[ ] Empty markets (no deposits)?
[ ] First deposit to market?
[ ] Last withdrawal from market?
[ ] Dust amounts left behind?
```

---

## 🟢 Standard Checks

### Math & Precision
```
[ ] Correct order of operations (mul before div)?
[ ] Precision loss in interest calculations?
[ ] Overflow possible with large values?
[ ] Underflow on subtraction?
[ ] Consistent decimals across calculations?
```

### State Management
```
[ ] Interest accrued before state changes?
[ ] All relevant indices updated?
[ ] Correct before/after balance checks?
[ ] Events emitted for all state changes?
[ ] Storage vs memory usage correct?
```

---

## Common Vulnerability Patterns

### 1. Oracle Manipulation
```solidity
// VULNERABLE: Spot price
uint256 price = pair.getReserves().token0 / pair.getReserves().token1;

// SECURE: TWAP or Chainlink
uint256 price = oracle.consult(token, TWAP_PERIOD);
```

### 2. Liquidation Front-running
```solidity
// VULNERABLE: Liquidator takes all
function liquidate(address user) external {
    // Liquidate entire position
}

// SECURE: Close factor limit
function liquidate(address user, uint256 repayAmount) external {
    require(repayAmount <= maxClose * debt, "Too much");
}
```

### 3. Interest Rate Manipulation
```solidity
// VULNERABLE: Large deposit/withdraw changes rate
function borrow() external {
    uint256 rate = getRate(); // Can be manipulated
    // Borrow at manipulated rate
}

// SECURE: Use time-weighted rates
```

### 4. Share Inflation Attack
```solidity
// VULNERABLE: First depositor attack
function deposit(uint256 assets) {
    shares = assets * totalShares / totalAssets; // 0/0 on first
}

// SECURE: Virtual offset
function deposit(uint256 assets) {
    shares = assets * (totalShares + 1) / (totalAssets + 1);
}
```

---

## Integration Points

### Aave V3 Specifics
```
[ ] E-Mode configurations correct?
[ ] Isolation mode limits enforced?
[ ] Siloed borrowing checked?
[ ] Supply/borrow caps enforced?
```

### Compound V3 (Comet) Specifics
```
[ ] Base asset vs collateral distinction?
[ ] Absorb mechanism for bad debt?
[ ] Collateral reserves handling?
[ ] Price feed decimals correct?
```

---

## Quick Reference Formulas

```
Health Factor = Σ(Collateral * Price * LiqThreshold) / Σ(Debt * Price)
Healthy if: Health Factor > 1

Max Borrow = Σ(Collateral * Price * CollateralFactor)

Utilization = TotalBorrows / TotalSupply

Interest Rate = BaseRate + Utilization * Slope1  (if U < Optimal)
Interest Rate = BaseRate + Optimal * Slope1 + (U - Optimal) * Slope2  (if U >= Optimal)
```

---

## Red Flags 🚩

- [ ] No oracle price staleness check
- [ ] Single oracle source
- [ ] Interest not accrued before operations
- [ ] No bad debt handling mechanism
- [ ] Admin can set arbitrary parameters
- [ ] Liquidation bonus > 20%
- [ ] No close factor limiting liquidation size
- [ ] Share calculation vulnerable to first depositor
