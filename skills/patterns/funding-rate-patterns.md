---
id: PAT-FUNDING-RATE
title: Funding Rate Security Patterns
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
  - funding-rate
  - perpetuals
  - derivatives
  - margin
  - mark-price
related_patterns:
  - oracle-patterns
  - liquidation-patterns
  - precision-loss-patterns
  - flash-loan-patterns
finding_count: 18
last_updated: 2026-02-24
---
# Funding Rate Security Patterns

## Overview

**Frequency**: 18 occurrences (0.03% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 2 | 8 | 6 | 2 | 0 |

**Common Sources**: Sherlock, Code4rena, Immunefi

---

## Detection Checklist

- [ ] Verify funding rate calculation uses reliable mark/index price oracle, not spot price
- [ ] Check for manipulation via large position opening right before funding settlement
- [ ] Review funding rate bounds — are extreme rates capped to prevent liquidity extraction?
- [ ] Analyze funding settlement timing for front-running or timing exploitation
- [ ] Test funding rate precision with extreme position sizes and very small/large rates

---

## Key Vulnerability Classes

### 1. Funding Rate Oracle Manipulation

Funding rate = f(mark_price - index_price). If either price is manipulable, the funding rate itself is manipulable.

```solidity
// VULNERABLE: Mark price from spot AMM
function calculateFundingRate() public view returns (int256) {
    uint256 markPrice = pool.slot0().sqrtPriceX96; // ⚠ Spot price, manipulable
    uint256 indexPrice = oracle.getPrice();
    int256 premium = int256(markPrice) - int256(indexPrice);
    return premium * FUNDING_RATE_FACTOR / int256(indexPrice);
}

// SECURE: Mark price from TWAP
function calculateFundingRate() public view returns (int256) {
    uint256 markPrice = getTWAP(FUNDING_TWAP_INTERVAL); // 8-hour TWAP
    uint256 indexPrice = oracle.getPrice();
    int256 premium = int256(markPrice) - int256(indexPrice);
    return clamp(premium * FUNDING_RATE_FACTOR / int256(indexPrice), MIN_RATE, MAX_RATE);
}
```

### 2. Funding Rate Position Gaming

Open a large position right before funding settlement, receive/pay one funding period, then close immediately after. If the cost of opening/closing (fees + slippage) is less than the funding payment received, this is profitable.

```solidity
// Attack flow (collecting positive funding):
// 1. Observe that longs will pay shorts (negative funding rate)
// 2. Open maximum short position 1 block before funding settlement
// 3. Funding settles — attacker receives funding payment proportional to position
// 4. Close short position immediately after settlement
// 5. Profit = funding_received - (open_fee + close_fee + slippage)

// The attack is profitable when:
//   |funding_rate| * position_size > 2 * trading_fee * position_size + slippage
```

**Fix**: Time-weighted average position for funding calculation, or delay funding accrual for new positions.

### 3. Funding Rate Overflow / Extreme Values

When the premium between mark and index price is extreme (depegged assets, illiquid markets), funding rates can overflow or become so large they drain margin.

```solidity
// VULNERABLE: Unbounded funding rate
function applyFunding(Position storage pos) internal {
    int256 fundingPerUnit = cumulativeFunding - pos.entryFunding;
    int256 fundingPayment = fundingPerUnit * int256(pos.size) / 1e18;
    // ⚠ If fundingPerUnit is extreme (market dislocated for days),
    //    fundingPayment > pos.margin → position goes negative
    pos.margin = uint256(int256(pos.margin) - fundingPayment);
    // ⚠ Underflow if fundingPayment > margin
}

// SECURE: Cap funding and handle boundary
int256 fundingPayment = clamp(
    fundingPerUnit * int256(pos.size) / 1e18,
    -int256(pos.margin), // Can't lose more than margin
    int256(type(int128).max) // Bounded above
);
```

### 4. Funding Settlement Timing Attacks

If funding settles at predictable intervals (every 8 hours), MEV bots can:
- Delay settlement transactions for favorable rates
- Bundle settlement with position changes
- Exploit stale accumulated funding

```solidity
// VULNERABLE: Anyone can trigger settlement, timing exploitable
function settleFunding() external {
    require(block.timestamp >= lastFundingTime + FUNDING_INTERVAL, "Too early");
    int256 rate = calculateFundingRate();
    cumulativeFunding += rate;
    lastFundingTime = block.timestamp;
    // ⚠ Keeper can delay calling this to let funding accumulate
    //    or call it at the most favorable moment
}
```

### 5. Cross-Margin Funding Drain

In cross-margin systems, funding payments from one position can drain margin shared with other positions, triggering cascading liquidations.

```solidity
// Cross-margin scenario:
// Position A: Long BTC, +$10,000 unrealized PnL
// Position B: Short ETH, -$2,000 unrealized PnL
// Total margin: $15,000, used across both positions
//
// If BTC funding rate turns highly negative:
// Position A pays $12,000 in accumulated funding
// Total margin: $3,000 — now Position B is liquidatable
// ⚠ Funding on one position cascades to liquidate another
```

---

## Real-World Examples

### Example 1: [H-01] Funding rate manipulation via oracle attack on Perpetual Protocol

**Source**: Immunefi
**Protocol**: Perpetual Protocol
**Impact**: CRITICAL

**Details**:

The mark price used for funding rate calculation was derived from the virtual AMM price, which could be manipulated by opening large positions. An attacker could:
1. Open a large long to push vAMM price above index
2. This creates a positive funding rate (longs pay shorts)
3. Open a larger short on a different account
4. Collect funding payments on the short position
5. Close both positions

The attack was profitable because funding payments accrued to the entire short position, while manipulation cost was limited to the vAMM impact.

---

### Example 2: [H-02] Keeper front-running funding settlement in GMX

**Source**: Sherlock
**Protocol**: GMX
**Impact**: HIGH

**Details**:

GMX uses keepers to execute position changes and funding settlements. The PositionRouter design allows keepers to observe pending position orders and front-run them with funding settlement. By selectively delaying or expediting settlement, keepers could:
- Settle funding right before a large position opens (favorable for existing positions)
- Delay settlement to accumulate larger funding payments

GMX's fast price feed mechanism was designed to mitigate this but introduced its own oracle manipulation surface.

---

### Example 3: [M-01] Precision loss in per-second funding accrual

**Source**: Code4rena
**Protocol**: Perp DEX
**Impact**: MEDIUM

**Details**:

Funding accrued per-second with a rate expressed as a fraction of 1e18. For small funding rates (near-balanced markets), `rate * elapsed / 1e18` would truncate to 0 for short intervals. Over time, this precision loss accumulated asymmetrically — large positions still accrued while small positions lost funding to truncation, creating a systemic imbalance.

---

## Interaction with Other Patterns

| Combined With | Creates Risk |
|---------------|-------------|
| Oracle manipulation | Fake premium → fake funding rate |
| Flash loans | Temporary large position for funding capture |
| MEV / Keepers | Front-running or delaying funding settlement |
| Liquidation | Funding drain triggers cascading liquidations |
| Precision loss | Small per-second rates truncate to zero |

---

## Recommended Secure Patterns

1. **TWAP mark price**: Use 1-8 hour TWAP for mark price, never spot
2. **Capped funding rate**: Bound rate to ±0.1% per interval (or similar)
3. **Time-weighted positions**: Only count position time-in-market for funding
4. **Automated settlement**: Trigger funding in every trade/liquidation, not on fixed schedule
5. **Position delay**: New positions don't accrue funding for first N seconds
6. **Per-position margin**: Isolated margin prevents cross-position funding cascade
7. **High precision**: Use 1e36 precision for per-second rate accumulation
