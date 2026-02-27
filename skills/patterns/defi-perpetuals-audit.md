---
id: PAT-DEFI-PERPETUALS-AUDIT
title: DeFi Perpetuals Audit Patterns
category: patterns
severity: critical
chains: [ethereum, solana, arbitrum, all]
languages: [solidity, rust, typescript]
tags:
  - perpetuals
  - derivatives
  - funding-rate
  - liquidation
  - oracle
  - precision
  - cross-margin
  - order-types
  - percolator
  - drift
last_updated: 2026-02-27
description: >-
  Use when auditing perpetual futures protocols, derivatives exchanges,
  or any protocol with synthetic leverage — covers precision constant
  mismatches, funding rate manipulation, order type edge cases,
  cross-margining risks, oracle price delivery, anti-DoS gating, and
  CPI-matcher identity binding. Derived from Drift Protocol SDK patterns
  and Percolator formal verification proof catalog.
---

# DeFi Perpetuals Audit Patterns

## Overview

Perpetual futures protocols are among the most complex DeFi systems to audit.
They combine oracle dependency, precision-sensitive math, multi-party
interactions (traders, LPs, liquidators, keepers), and real-time funding
mechanisms. A single precision error can create unbounded economic exploits.

**Core risk**: Perp protocols handle LEVERAGED positions. A 10x leveraged
position means a 1% precision error becomes a 10% actual value error.

### Perp Protocol Architecture

```
┌──────────────────────────────────────────────────┐
│                    PERP ENGINE                     │
│                                                    │
│  ┌──────────┐   ┌──────────┐   ┌──────────────┐  │
│  │ Order     │   │ Position │   │ Liquidation  │  │
│  │ Matching  │──▶│ Manager  │──▶│ Engine       │  │
│  └─────┬────┘   └────┬─────┘   └──────┬───────┘  │
│        │              │                │           │
│  ┌─────▼────┐   ┌────▼─────┐   ┌──────▼───────┐  │
│  │ Oracle   │   │ Funding  │   │ Insurance    │  │
│  │ Module   │   │ Rate     │   │ Fund         │  │
│  └──────────┘   └──────────┘   └──────────────┘  │
└──────────────────────────────────────────────────┘
```

## Precision Constant Vulnerabilities

### The Precision Constant Map

Perpetual protocols use MULTIPLE precision constants. Mixing them up is
the #1 source of Critical bugs.

| Constant | Typical Value | What It Represents |
|----------|--------------|-------------------|
| QUOTE_PRECISION | 10^6 | USDC/USDT amounts (6 decimals) |
| BASE_PRECISION | 10^9 | Base asset amounts (SOL, BTC in fractional units) |
| PRICE_PRECISION | 10^6 | Price per unit of base asset |
| PERCENTAGE_PRECISION | 10^6 | Percentages (100% = 1_000_000) |
| MARGIN_PRECISION | 10^4 | Margin ratios (100% = 10_000) |
| FUNDING_PRECISION | 10^9 | Funding rate per period |
| PEG_PRECISION | 10^3 | AMM peg multiplier |

### Pattern 1: Cross-Precision Multiplication

**Vulnerability**: Multiplying two values with different precisions without
normalizing the result.

```rust
// ❌ DANGEROUS: base_amount (10^9) × price (10^6) = result in 10^15
let value = base_amount * price; // This is NOT in QUOTE_PRECISION

// ✅ SAFE: Normalize after multiplication
let value = base_amount
    .checked_mul(price)?
    .checked_div(BASE_PRECISION)?; // Now in QUOTE_PRECISION (10^6)
```

**Audit checklist**:
- [ ] For EVERY multiplication: what precision is the result in?
- [ ] Is the result divided by the correct normalizing constant?
- [ ] Is the division AFTER the multiplication? (precision loss if reversed)
- [ ] Are checked operations used? (`checked_mul`, `checked_div`)
- [ ] Does overflow checking account for intermediate 10^15 values?

### Pattern 2: Precision Loss in Sequential Operations

**Vulnerability**: Each division introduces rounding. Sequential divisions
compound the error.

```rust
// ❌ DANGEROUS: Two divisions → 2 rounding errors
let fee = amount / precision_a / precision_b;

// ✅ SAFE: Single division with combined constant
let fee = amount * precision_b / (precision_a * precision_b);
// Or use 128-bit intermediate
let fee = (amount as u128 * multiplier as u128 / divisor as u128) as u64;
```

### Pattern 3: Rounding Direction Inconsistency

**Vulnerability**: Protocol sometimes rounds in favor of the user, sometimes
against. Arbitrageurs exploit the favorable direction.

```rust
// Rounding rules for perp protocols:
// - Fees: round UP (protocol collects at least the fee)
// - Collateral required: round UP (user must post at least this much)
// - Withdrawal amounts: round DOWN (user receives at most this much)
// - Liquidation threshold: round DOWN (liquidation triggers sooner, safer)

fn round_up(value: u128, precision: u128) -> u128 {
    (value + precision - 1) / precision
}

fn round_down(value: u128, precision: u128) -> u128 {
    value / precision
}
```

## Order Type Attack Vectors

### Supported Order Types and Risks

| Order Type | Risk | Attack Vector |
|-----------|------|---------------|
| Market | Slippage extraction | Sandwich attack between submission and execution |
| Limit | Front-running | MEV bot detects limit order, front-runs fill |
| Post-Only | Rejection grief | Submit, cancel before opponent can fill |
| Trigger (Stop-Loss) | Oracle manipulation | Flash-manipulate price to trigger stops |
| TWAP | Partial fill gaming | Adversary fills only profitable segments |
| IOC (Immediate-or-Cancel) | Dust fills | Fill minimum amount to grief gas/CU costs |

### Pattern 4: Post-Only Order Crossing

**Vulnerability**: Post-only order that would immediately match is rejected.
Attacker submits aggressive limit orders then cancels, causing all opposing
post-only orders to fail.

```
Attack flow:
1. Attacker places aggressive limit buy at $100
2. Victim's post-only sell at $99 is REJECTED (it would cross)
3. Attacker cancels their buy order immediately
4. Victim never got filled; attacker paid nothing
```

**Audit check**: Does the protocol charge a fee for canceled orders that
caused post-only rejections?

### Pattern 5: Trigger Order Price Manipulation

**Vulnerability**: Trigger orders (stop-loss, take-profit) activate when
oracle price crosses a threshold. Flash manipulation can trigger them.

```
Attack:
1. Trader has stop-loss at $90 on a long position
2. Attacker flash-loans, crashes oracle price to $89
3. Stop-loss triggers, trader's position is closed at loss
4. Price recovers; attacker profits from the forced liquidation

Mitigations:
- Use TWAP/EMA for trigger evaluation, not spot price
- Require price to remain below threshold for N blocks
- Cross-check multiple oracles before triggering
```

## Funding Rate Manipulation

### How Funding Works

Funding rates keep perpetual prices aligned with spot:
- When perp price > spot: longs pay shorts (positive funding)
- When perp price < spot: shorts pay longs (negative funding)

### Pattern 6: Funding Rate Extraction

**Vulnerability**: Attacker opens opposing positions on perp and spot to
earn funding rate with near-zero directional risk.

```
Attack:
1. Open 100 SOL short on perp (earns positive funding)
2. Buy 100 SOL on spot (hedges directional risk)
3. Collect funding every period
4. Risk: funding rate flips negative → close positions

Audit focus:
- Is the funding rate formula manipulation-resistant?
- Can a single large trader skew the funding rate?
- Is funding calculated on mark price, oracle price, or TWAP?
```

### Pattern 7: Funding Rate Calculation Errors

```rust
// ❌ DANGEROUS: Integer division truncation in funding
let funding_per_unit = total_funding / total_base_amount;
// If total_funding = 999 and total_base_amount = 1000
// funding_per_unit = 0 (truncated!)
// 999 tokens of funding are lost

// ✅ SAFE: Scale up before division
let funding_per_unit = total_funding
    .checked_mul(FUNDING_PRECISION)?
    .checked_div(total_base_amount)?;
// funding_per_unit = 999_000_000 (preserves precision)
```

## Liquidation Engine Vulnerabilities

### Pattern 8: Liquidation Price Calculation Mismatch

**Vulnerability**: Liquidation price calculated differently by the engine
vs the liquidator bot vs the user interface.

```
Audit check: Verify that these ALL use the same formula:
1. On-chain liquidation check (canBeLiquidated())
2. Position health display calculation
3. Liquidator bot's off-chain calculation
4. SDK's liquidationPrice() function

Common inconsistency sources:
- Different precision handling
- Including/excluding unrealized funding
- Including/excluding accumulated interest
- Different oracle price sources
```

### Pattern 9: Partial Liquidation Gaming

**Vulnerability**: Attacker opens position just above liquidation threshold,
knowing the partial liquidation will be profitable for the liquidator.

```
Attack:
1. Open maximum leverage position ($10,000 at 20x → $200,000 notional)
2. Position drops to maintenance margin → partial liquidation
3. Liquidator closes 50% of position, earns liquidation fee
4. Remaining 50% is now ABOVE margin requirement
5. Repeat: position drops again → another partial liquidation

Risk: The protocol (insurance fund) may subsidize these fees
```

### Pattern 10: Insurance Fund Drain

```
Scenario: Position underwater → loss exceeds collateral
1. Liquidation leaves negative PnL
2. Insurance fund covers the deficit
3. If insurance fund depletes → socialized losses to other traders

Audit focus:
- Is there a cap on per-liquidation insurance fund usage?
- Can an attacker deliberately create underwater positions?
- Is the insurance fund size proportional to total open interest?
- What happens when the insurance fund is empty? (cascade risk)
```

## Anti-DoS Gating (from Percolator Model)

### The Gate Pattern

Perpetual protocols need anti-DoS mechanisms that prevent manipulation
while allowing legitimate risk reduction.

**Core rule**: Risk-REDUCING operations must ALWAYS be allowed. Only
risk-INCREASING operations can be gated.

```rust
// Percolator gate logic (formally verified)
fn gate_decision(gate_active: bool, risk_increase: bool) -> bool {
    // Accept IFF: gate is inactive OR risk is decreasing
    !(gate_active && risk_increase)
}

// This means:
// gate_active=false → always accept (normal operation)
// gate_active=true, risk_increase=false → accept (closing/reducing)
// gate_active=true, risk_increase=true → REJECT (blocked)
```

**Audit checklist for gating**:
- [ ] Can risk-reducing operations (close position, add collateral) be blocked?
- [ ] Is the gate activation threshold set correctly?
- [ ] Can the gate be permanently activated by an attacker? (DoS)
- [ ] Does gate status persist across transactions?

## CPI-Matcher Identity Binding (Solana-Specific)

### Pattern 11: Matcher Return Data Trust

On Solana, perpetual protocols often use a CPI (cross-program invocation)
pattern where a matcher program evaluates order matching and returns
a decision.

**Vulnerability**: Trusting CPI return data without verifying the caller's
identity.

```rust
// Formally verified identity binding (from Percolator):
// 1. Verify matcher program is executable
// 2. Verify matcher context is NOT executable (it's data)
// 3. Verify context is owned by the matcher program
// 4. Verify context data length is sufficient
// 5. Verify LP program/context match provided accounts
// 6. Verify PDA derivation matches expected key

// All 6 checks must pass. Formally proven: failure of ANY single
// check causes rejection regardless of all other inputs.
```

**Audit checklist for CPI matchers**:
- [ ] Is the matcher program ID hardcoded or configurable?
- [ ] Is the return data ABI version checked?
- [ ] Is `exec_size` used (not `req_size`) for the actual trade?
- [ ] Is nonce incremented only on successful execution?
- [ ] Can the matcher be replaced with a malicious program?

## Nonce Monotonicity

### Pattern 12: Nonce State Transitions

```
Formally verified properties (from Percolator):
1. Rejection → nonce UNCHANGED (prevents replay of failed trades)
2. Acceptance → nonce += 1 (wraps at u64::MAX to 0)
3. req_id == nonce + 1 on success (links request to state)
4. CPI uses exec_size, NOT requested size (prevents inflation)
```

**Audit checklist for nonces**:
- [ ] Is the nonce incremented atomically with the state change?
- [ ] Can nonce be decremented (replay attack)?
- [ ] What happens at nonce overflow (u64::MAX)?
- [ ] Is the nonce checked before processing?
- [ ] Can parallel transactions reuse the same nonce?

## Cross-Margining Risks

### Pattern 13: Cross-Margin Contagion

**Vulnerability**: In cross-margin mode, one position's loss can liquidate
ALL positions.

```
Scenario (cross-margin):
- User has: SOL-PERP long (+$5,000 profit)
             BTC-PERP short (-$4,500 loss)
             ETH-PERP long (-$800 loss)
- Total: +$5,000 - $4,500 - $800 = -$300 net PnL

If BTC-PERP loss grows to -$5,500:
- Net PnL: +$5,000 - $5,500 - $800 = -$1,300
- ALL positions may be liquidated (including profitable SOL-PERP)
```

**Audit checks**:
- [ ] Can users switch between isolated and cross-margin?
- [ ] Are sub-accounts properly isolated?
- [ ] Can cross-margin calculations overflow with many positions?
- [ ] Is margin calculation O(n) in number of positions? (gas/CU DoS)

### Pattern 14: Sub-Account Transfer Exploits

```rust
// Attack: Transfer profit from sub-account 0 to sub-account 1,
// then use sub-account 0's negative balance for cheap liquidation

// Audit check: Do transfer operations verify BOTH accounts remain healthy?
// deposit transfer: from.health >= min AND to.health >= min
// position transfer: from.margin_ok AND to.margin_ok
```

## Comprehensive Audit Checklist

### Oracle Integration
- [ ] Staleness check on every oracle read
- [ ] Confidence interval check (Pyth) or std dev check (Switchboard)
- [ ] Zero/negative price guard
- [ ] Multi-oracle fallback if primary is stale
- [ ] Oracle price used for funding ≠ manipulable spot

### Position Management
- [ ] All precision conversions are correct
- [ ] Rounding favors the protocol (not the user)
- [ ] Position limits enforced (max open interest)
- [ ] Leverage limits enforced per-market and per-user
- [ ] Unrealized PnL correctly included in margin calculations

### Liquidation
- [ ] Liquidation threshold formula matches documentation
- [ ] Partial liquidation leaves remaining position healthy
- [ ] Insurance fund drain rate is bounded
- [ ] Socialized loss mechanism is fair
- [ ] Liquidator incentive doesn't exceed protocol benefit

### Order Processing
- [ ] All order types reject invalid parameters
- [ ] ABI version is checked on matcher returns
- [ ] Identity binding for CPI matchers (all 6 checks)
- [ ] Nonce transitions are correct (unchanged on failure, +1 on success)
- [ ] `exec_size` (not `req_size`) is used for actual fills

### Economic Security
- [ ] Funding rate cannot be manipulated by single actor
- [ ] Protocol fees are non-bypassable
- [ ] Flash loan attacks cannot distort protocol state
- [ ] Maximum position size is bounded

## Integration with Other Skills

| Skill | Relationship |
|-------|-------------|
| [Solana Oracle Audit](../solana-scanner/resources/solana-oracle-audit.md) | Perps are the heaviest oracle consumers |
| [Oracle Patterns (EVM)](patterns/oracle-patterns.md) | EVM-side oracle validation |
| [Formal Verification Assessment](methodology/formal-verification-assessment.md) | Percolator proofs demonstrate FV in perps |
| [Sharp Edges Detection](methodology/sharp-edges-detection.md) | Precision footguns are the #1 sharp edge in perps |
| [Fix Patterns](../fix-patterns/) | Precision-fix patterns for arithmetic issues |
