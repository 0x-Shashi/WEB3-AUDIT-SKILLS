---
id: SOL-ORACLE-AUDIT
title: Solana Oracle Audit Patterns
category: solana-scanner/resources
severity: critical
chains: [solana]
languages: [rust, typescript]
tags:
  - oracle
  - pyth
  - switchboard
  - price-feed
  - staleness
  - confidence-interval
  - manipulation
  - pull-oracle
  - vrf
last_updated: 2026-02-27
description: >-
  Use when auditing Solana protocols that consume price data from Pyth,
  Switchboard, or other oracle providers — covers pull oracle architecture,
  confidence interval validation, staleness thresholds, cross-oracle
  comparison, and Solana-specific manipulation vectors. Different from EVM
  oracle-patterns.md which covers Chainlink/TWAP — this addresses
  Pyth's i64/u64/i32 price structure, Switchboard's TEE/Surge/VRF
  model, and Solana-specific account ownership verification.
---

# Solana Oracle Audit Patterns

## Overview

Solana oracle integrations differ fundamentally from EVM patterns. Pull-based
oracles (Pyth, Switchboard) require the consumer to actively fetch and post
prices on-chain, creating trust boundaries that don't exist in push-based
models. Solana's account model means oracle data lives in program-owned
accounts that must be verified for ownership, program ID, and data freshness.

### Oracle Architecture Comparison

| Property | Pyth (Solana) | Switchboard | Chainlink (EVM) |
|----------|--------------|-------------|-----------------|
| Model | Pull (Hermes) | Pull (Oracle Quotes / Surge) | Push (heartbeat) |
| Update latency | ~400ms | 2-5ms (Surge) / ~1s (Quotes) | ~60s heartbeat |
| Price structure | i64 price + u64 conf + i32 expo | i128 result + u8 decimals | int256 answer + uint8 decimals |
| Staleness detection | `publish_time` field | `result_timestamp` field | `updatedAt` from `latestRoundData` |
| Confidence measure | Confidence interval (σ estimate) | Standard deviation (feed-dependent) | Deviation threshold (1-2%) |
| On-chain cost | ~0.002 SOL per update | 90% lower (stateless Quotes) | Gas per callback |
| Security model | Publisher network (60+) | TEE-secured oracle nodes | Decentralized node operators |

## Pyth Oracle Audit Patterns

### Price Structure Deep Dive

Pyth prices use a fixed-point representation with separate exponent:

```rust
// Pyth PriceUpdateV2 structure (critical fields)
pub struct PriceUpdateV2 {
    pub price_message: PriceFeedMessage,
    // ... verification data
}

pub struct PriceFeedMessage {
    pub feed_id: [u8; 32],          // unique identifier
    pub price: i64,                  // price (can be negative for spreads)
    pub conf: u64,                   // confidence interval (always positive)
    pub exponent: i32,               // power of 10 (typically -8 to -5)
    pub publish_time: i64,           // unix timestamp
    pub prev_publish_time: i64,      // previous update timestamp
    pub ema_price: i64,              // exponential moving average
    pub ema_conf: u64,               // EMA confidence
}

// Actual price = price × 10^exponent
// Example: price=12345678, exponent=-5 → $123.45678
```

### Pattern 1: Confidence Interval Validation

**Vulnerability**: Using price without checking confidence. High confidence
intervals indicate uncertain/volatile pricing.

```rust
// ❌ DANGEROUS: No confidence check
let oracle_price = price_update.price_message.price;
let value = position_size * oracle_price; // could be wildly off

// ✅ SAFE: Enforce confidence ratio
let price = price_update.price_message.price;
let conf = price_update.price_message.conf;
let price_abs = price.unsigned_abs();

// Confidence should be < 2% of price for most DeFi operations
require!(
    conf * 50 <= price_abs,  // conf/price <= 0.02
    ErrorCode::OracleConfidenceTooWide
);
```

**Audit checklist for confidence**:
- [ ] Is confidence checked at all?
- [ ] Is the ratio threshold appropriate? (2% for lending, tighter for perps)
- [ ] Is `price_abs` used correctly? (price can be negative for spreads)
- [ ] Does the protocol handle zero price? (`price_abs == 0` → division by zero)

### Pattern 2: Staleness Detection

**Vulnerability**: Using outdated prices during volatile markets.

```rust
// ❌ DANGEROUS: No staleness check
let price = get_pyth_price(&price_account)?;
calculate_collateral(price); // price could be hours old

// ✅ SAFE: Enforce freshness
let clock = Clock::get()?;
let price_age = clock.unix_timestamp - price_update.price_message.publish_time;

// Staleness threshold depends on use case:
// - Perps/liquidations: 10-30 seconds
// - Lending collateral: 60-120 seconds
// - Informational display: 300+ seconds acceptable
require!(
    price_age <= MAX_PRICE_AGE_SECONDS,
    ErrorCode::OraclePriceStale
);
```

**Audit checklist for staleness**:
- [ ] Is `publish_time` compared against `Clock::get()`?
- [ ] Is the threshold appropriate for the use case?
- [ ] Can an attacker deliberately submit stale prices?
- [ ] Is `prev_publish_time` checked for gap detection?
- [ ] What happens during Solana network outages (prices stop updating)?

### Pattern 3: EMA vs Spot Price Divergence

**Vulnerability**: Using spot price when EMA is more appropriate, or vice versa.

```rust
// EMA is smoother — harder to manipulate but slower to react
let ema_price = price_update.price_message.ema_price;
let spot_price = price_update.price_message.price;

// ❌ DANGEROUS: Liquidation on spot only (flashable)
if collateral_value(spot_price) < maintenance_margin {
    liquidate(position);
}

// ✅ SAFER: Cross-check spot against EMA
let divergence = (spot_price - ema_price).abs();
let max_divergence = ema_price.abs() / 10; // 10% max
require!(
    divergence <= max_divergence,
    ErrorCode::OraclePriceDivergence
);
// Use the MORE CONSERVATIVE price for liquidations
let safe_price = if is_long { spot_price.min(ema_price) } else { spot_price.max(ema_price) };
```

**When to use EMA vs spot**:

| Use Case | Recommended | Reason |
|----------|------------|--------|
| Liquidation trigger | EMA or conservative of both | Resist flash manipulation |
| Position opening | Spot (with confidence check) | Fair current price |
| Funding rate | EMA | Smooth long-term signal |
| Informational display | Spot | Most current |

### Pattern 4: Exponent Normalization

**Vulnerability**: Different feeds have different exponents. Mixing them
without normalization causes precision errors of 10x to 100,000x.

```rust
// ❌ DANGEROUS: Assuming all feeds use same exponent
let sol_price = sol_feed.price_message.price;  // expo = -8
let btc_price = btc_feed.price_message.price;  // expo = -8
let eth_price = eth_feed.price_message.price;  // expo = -8
let ratio = sol_price * PRECISION / btc_price;  // might work... until feed changes

// ✅ SAFE: Normalize to common precision
fn normalize_price(price: i64, exponent: i32, target_decimals: u32) -> i128 {
    let price = price as i128;
    if exponent >= 0 {
        price * 10i128.pow(exponent as u32 + target_decimals)
    } else {
        let abs_expo = (-exponent) as u32;
        if target_decimals >= abs_expo {
            price * 10i128.pow(target_decimals - abs_expo)
        } else {
            price / 10i128.pow(abs_expo - target_decimals)
        }
    }
}
```

### Pattern 5: Feed Account Verification

**Vulnerability**: Attacker passes a fake account that looks like a price feed.

```rust
// ❌ DANGEROUS: No account ownership verification
let price_data = AccountDeserialize::deserialize(&price_account.data)?;

// ✅ SAFE: Verify the account is owned by Pyth program
// Using Pyth SDK (recommended)
let price_update = PriceUpdateV2::try_deserialize(
    &mut &price_account.data.borrow()[..]
)?;

// Verify feed ID matches expected
require!(
    price_update.price_message.feed_id == EXPECTED_SOL_USD_FEED_ID,
    ErrorCode::InvalidOracleFeed
);
```

**Critical checks for feed accounts**:
- [ ] Account owner is Pyth program ID
- [ ] Feed ID matches expected (not just any valid Pyth feed)
- [ ] For ephemeral feeds: verify the update was recently posted
- [ ] For fixed feeds: verify the account address matches on-chain config

### Pattern 6: Ephemeral vs Fixed Feed Accounts

Pyth on Solana supports two models:

| Model | Account Lifetime | Trust Assumption | Cost |
|-------|-----------------|------------------|------|
| Ephemeral (write-once) | Single transaction | Freshest possible | Higher (create account each time) |
| Fixed (persistent) | Permanent | Updated by keeper network | Lower (reuse account) |

**Vulnerability with ephemeral feeds**: The price poster controls WHEN the
update is submitted. An attacker can selectively post favorable prices.

```rust
// Audit question: Is the price poster incentive-aligned?
// If the BORROWER posts the price → they'll pick the highest price
// If the LIQUIDATOR posts the price → they'll pick the lowest price
// If a KEEPER posts the price → neutral, but verify keeper incentives
```

## Switchboard Oracle Audit Patterns

### Architecture: Oracle Quotes (Stateless)

Switchboard Oracle Quotes are stateless — no on-chain feed accounts. The
oracle signs the result inside a TEE, and the consumer verifies the
signature on-chain.

```rust
// Oracle Quotes flow:
// 1. Client requests quote from TEE oracle
// 2. Oracle fetches data, computes result inside TEE
// 3. Oracle signs result with TEE-attested key
// 4. Client submits signed result to on-chain program
// 5. Program verifies signature and uses result
```

**Audit checklist for Oracle Quotes**:
- [ ] Is the oracle quote signature verified on-chain?
- [ ] Is the TEE attestation chain validated?
- [ ] Is `numSignatures` parameter set correctly? (more = safer, slower)
- [ ] Is the result age checked? (TEE timestamp vs on-chain clock)
- [ ] Can the client selectively discard unfavorable quotes?

### Pattern 7: Surge Streaming Latency Assumptions

Switchboard Surge delivers prices in 2-5ms with WebSocket streaming.

**Vulnerability**: Protocol assumes sub-second freshness but Surge has
delivery failures and reconnection gaps.

```rust
// ❌ DANGEROUS: Assuming Surge always delivers
let price = get_surge_price(feed_id)?;
execute_trade(price); // no staleness check because "Surge is fast"

// ✅ SAFE: Staleness check even with Surge
let price_data = get_surge_price(feed_id)?;
let age_ms = clock_ms() - price_data.result_timestamp;
require!(
    age_ms <= MAX_SURGE_STALENESS_MS, // 500ms-2000ms depending on use case
    ErrorCode::SurgePriceStale
);
```

### Pattern 8: VRF Randomness Verification

Switchboard VRF provides verifiable randomness on Solana.

**Vulnerability**: Using VRF result without verifying the proof, or
re-using a VRF result across multiple operations.

```rust
// ❌ DANGEROUS: Trust VRF result without proof verification
let randomness = vrf_account.result;
assign_winner(randomness);

// ✅ SAFE: Verify VRF proof + check freshness
// Using Switchboard SDK
let vrf = VrfAccountData::new(&vrf_account)?;
require!(
    vrf.authority == expected_authority,
    ErrorCode::InvalidVrfAuthority
);
require!(
    vrf.counter == expected_counter, // prevents replay
    ErrorCode::VrfReplay
);
let randomness = vrf.get_result()?;
```

**VRF audit checklist**:
- [ ] Is the VRF proof verified on-chain (not just the result)?
- [ ] Is `counter` incremented to prevent replay?
- [ ] Is the `authority` checked to prevent substitution?
- [ ] Can the VRF requester see the result before committing? (front-running)
- [ ] Is the callback function atomic with the VRF reveal?

### Pattern 9: Permissionless Feed Deployment Risk

Switchboard allows anyone to create custom feeds.

**Vulnerability**: Protocol references a feed by address without verifying
the feed's data source configuration.

```rust
// ❌ DANGEROUS: Trust any Switchboard feed
let feed = AggregatorAccountData::new(&feed_account)?;
let price = feed.latest_confirmed_round.result;

// ✅ SAFE: Verify feed configuration matches expectations
let feed = AggregatorAccountData::new(&feed_account)?;

// Check minimum oracle responses (should be >= 3 for production)
require!(
    feed.min_oracle_results >= MIN_ORACLE_RESPONSES,
    ErrorCode::InsufficientOracleResponses
);

// Check feed is active (not abandoned)
let last_update_age = clock.unix_timestamp - feed.latest_confirmed_round.round_open_timestamp;
require!(
    last_update_age <= MAX_FEED_AGE,
    ErrorCode::FeedInactive
);

// Verify feed address matches on-chain config (not user-supplied)
require!(
    feed_account.key() == stored_feed_address,
    ErrorCode::WrongFeedAccount
);
```

## Cross-Oracle Patterns

### Multi-Oracle Price Comparison

```rust
// When using two oracles for the same asset, define acceptable divergence
fn validate_cross_oracle(
    pyth_price: i64,
    pyth_conf: u64,
    sb_price: i128,
    sb_decimals: u8,
    max_divergence_bps: u64,
) -> Result<i64> {
    // Normalize to same precision
    let pyth_normalized = pyth_price as i128;
    let sb_normalized = normalize_to_pyth_precision(sb_price, sb_decimals);

    // Check divergence
    let diff = (pyth_normalized - sb_normalized).unsigned_abs();
    let avg = (pyth_normalized.unsigned_abs() + sb_normalized.unsigned_abs()) / 2;

    require!(
        diff * 10_000 <= avg * max_divergence_bps as u128,
        ErrorCode::OracleDivergence
    );

    // Use the more conservative price (depends on direction)
    Ok(pyth_price) // or choose based on use case
}
```

### Fallback Oracle Strategy

```
Primary Oracle → Check freshness → Use if fresh
       ↓ (stale)
Secondary Oracle → Check freshness → Use if fresh
       ↓ (stale)
TWAP from on-chain DEX → Use with wider spread
       ↓ (unavailable)
HALT PROTOCOL (pause all new positions)
```

**Audit checklist for multi-oracle**:
- [ ] Is there a fallback if primary oracle is stale?
- [ ] Are divergence thresholds configured per-asset?
- [ ] Can an attacker force fallback to a weaker oracle?
- [ ] Is the fallback oracle's security model adequate?
- [ ] Are oracle addresses stored on-chain (not hardcoded in binary)?

## Solana-Specific Manipulation Vectors

### Vector 1: Transaction Ordering Attacks

On Solana, validators choose transaction order. An attacker can:
1. Observe a pending oracle price update
2. Submit their transaction with the update in the same block
3. Ensure their trade executes BEFORE the price update

**Mitigation**: Use oracle prices from the PREVIOUS slot, not the current one.

### Vector 2: Oracle Update Sandwiching

```
Attacker flow:
1. Post favorable price update (old price) → gets included
2. Execute trade at favorable price → profits
3. Post correct price update → market returns to normal

Detection: Check that price_update.publish_time is recent (not replayed)
```

### Vector 3: Account Substitution

```
Attacker creates an account with:
- Correct data format (matches Pyth/Switchboard schema)
- Incorrect owner (attacker's program)
- Favorable price data

If the protocol only checks data format but not account owner,
the attacker controls the "oracle" price.
```

**Defense**: ALWAYS verify:
1. Account owner == expected oracle program ID
2. Feed ID/address == stored on-chain configuration
3. Account data length matches expected schema

## Quick Reference: Minimum Checks

### Pyth Integration Minimum

```rust
// Every Pyth price read must include ALL of these:
fn safe_pyth_price(
    price_update: &PriceUpdateV2,
    expected_feed_id: &[u8; 32],
    max_age_seconds: i64,
    max_conf_ratio_bps: u64,  // 200 = 2%
) -> Result<(i64, i32)> {
    // 1. Feed ID verification
    require!(price_update.price_message.feed_id == *expected_feed_id);

    // 2. Staleness check
    let clock = Clock::get()?;
    require!(clock.unix_timestamp - price_update.price_message.publish_time <= max_age_seconds);

    // 3. Confidence check
    let price_abs = price_update.price_message.price.unsigned_abs();
    require!(price_abs > 0); // zero price guard
    require!(price_update.price_message.conf * 10_000 / price_abs <= max_conf_ratio_bps);

    Ok((price_update.price_message.price, price_update.price_message.exponent))
}
```

### Switchboard Integration Minimum

```rust
// Every Switchboard price read must include ALL of these:
fn safe_switchboard_price(
    feed_account: &AccountInfo,
    expected_feed_key: &Pubkey,
    max_age_seconds: i64,
    min_oracle_responses: u32,
) -> Result<(i128, u8)> {
    // 1. Account address verification
    require!(feed_account.key() == *expected_feed_key);

    // 2. Account owner verification (Switchboard program)
    require!(feed_account.owner == &SWITCHBOARD_PROGRAM_ID);

    // 3. Deserialize and check freshness
    let feed = AggregatorAccountData::new(feed_account)?;
    let clock = Clock::get()?;
    require!(
        clock.unix_timestamp - feed.latest_confirmed_round.round_open_timestamp <= max_age_seconds
    );

    // 4. Minimum oracle responses
    require!(feed.latest_confirmed_round.num_success >= min_oracle_responses);

    Ok((feed.latest_confirmed_round.result, feed.latest_confirmed_round.result_decimals))
}
```

## Integration with Other Skills

| Skill | Relationship |
|-------|-------------|
| [Oracle Patterns (EVM)](../../patterns/oracle-patterns.md) | EVM counterpart — Chainlink/TWAP focus |
| [Sharp Edges Detection](../../methodology/sharp-edges-detection.md) | Oracle data trust is a key S-T-S template |
| [DeFi Perpetuals Audit](../../patterns/defi-perpetuals-audit.md) | Perps are the heaviest oracle consumers |
| [CPI Adversarial Security](../../patterns/cpi-adversarial-security.md) | Oracle CPI calls need account verification |
