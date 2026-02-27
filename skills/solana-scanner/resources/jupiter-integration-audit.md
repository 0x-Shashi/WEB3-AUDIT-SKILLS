---
id: SOL-JUPITER-INT-001
title: Jupiter API Integration Audit Guide
category: integration-security
subcategory: dex-aggregator
severity: high
chains:
  - solana
protocols:
  - dex
  - lending
  - perpetuals
  - prediction-markets
tags:
  - jupiter
  - aggregator
  - ultra-swap
  - dca
  - limit-orders
  - price-oracle
  - rate-limiting
  - idempotency
  - token-2022
  - rfq
difficulty: advanced
prerequisites:
  - solana-basics
  - cpi-security
  - anchor-security
related_patterns:
  - solana-oracle-audit
  - defi-perpetuals-audit
  - solana-testing-for-auditors
related_exploits:
  - dex-price-manipulation
  - slippage-extraction
  - stale-oracle-attacks
source_material: "New-info/agent-skills/skills/integrating-jupiter/SKILL.md (Jupiter official, 369 lines, MIT)"
last_updated: 2026-01-31
---

# Jupiter API Integration Audit Guide

> Security-focused audit patterns for protocols integrating Jupiter's DeFi API suite — Ultra Swap, Lending, Perps, Trigger Orders, DCA, Price, Tokens, Routing, and more.

---

## Why This Matters

Jupiter is Solana's dominant aggregator. Nearly every Solana DeFi frontend and protocol integrates at least one Jupiter API. Audit failures in Jupiter integrations surface as:

- **Silent price manipulation** — missing confidence checks on Price API
- **Order griefing** — Trigger program doesn't validate favorable rates
- **Fund loss on stale execution** — signed payloads executed after market moves
- **Token-2022 incompatibility** — DCA and Trigger silently reject Token-2022 mints
- **Rate-limit DoS** — burst patterns triggering 429 cascades with no graceful fallback
- **Dual-sign bypass** — Send API invite codes leaking derived keypairs

This guide distills every security-relevant pattern from Jupiter's official integration docs into audit-ready checklists.

---

## Table of Contents

- [Per-API Security Gotchas](#per-api-security-gotchas)
- [Production Hardening Audit Checklist](#production-hardening-audit-checklist)
- [Error Handling Classification](#error-handling-classification)
- [Rate Limit Architecture](#rate-limit-architecture)
- [Price Confidence & Oracle Safety](#price-confidence--oracle-safety)
- [Idempotency & Replay Protection](#idempotency--replay-protection)
- [Aggregator Routing Security](#aggregator-routing-security)
- [Token-2022 Compatibility Matrix](#token-2022-compatibility-matrix)
- [Lending Health Factor Patterns](#lending-health-factor-patterns)
- [Limit Order & DCA Validation](#limit-order--dca-validation)
- [Cross-Cutting Audit Checklist](#cross-cutting-audit-checklist)

---

## Per-API Security Gotchas

### Ultra Swap — Transaction Lifecycle Risks

| Gotcha | Audit Impact | What to Check |
|--------|-------------|---------------|
| Signed payloads have ~2 min TTL | Stale execution risk if sign→execute gap exceeds TTL | Measure time between `/order` and `/execute`; reject if > 90s |
| Transactions are immutable after receipt | Cannot modify amount/slippage post-signature | Verify re-quote logic exists before signing |
| Order/execute must be split in code | Mixing phases hides failures | Separate try/catch per phase; log `requestId` at each |
| Fee is 5–10 bps (standard), 20% of integrator fee if custom | Fee stacking if integrator adds fees on top | Audit total effective fee path; warn users |

**Audit question:** Does the integration re-quote before signing when market conditions may have changed (e.g., user idle > 30s)?

### Lend — State Consistency Risks

| Gotcha | Audit Impact | What to Check |
|--------|-------------|---------------|
| Must recompute account state before each state-changing action | Stale state → wrong deposit/withdraw amounts | Verify fresh `GET /earn/positions` precedes every deposit/withdraw |
| Health factors and liquidation boundaries must be preconditions | Under-collateralized borrows if skipped | Check health factor validation before borrow actions |
| All endpoints return unsigned `VersionedTransaction` (base64) | Client must sign — unsigned tx exposure | Verify tx is signed immediately, never stored unsigned |

**Audit question:** Does the integration enforce a minimum health factor buffer (e.g., 1.2x) before allowing borrows?

### Perps — Position Model Risks

| Gotcha | Audit Impact | What to Check |
|--------|-------------|---------------|
| Max 9 simultaneous positions (3 long + 6 short) | Position overflow causes silent rejection | Validate position count before opening new |
| 3 long assets: SOL, wETH, wBTC; shorts use USDC/USDT collateral | Wrong collateral → tx failure | Enforce collateral mint validation |
| No REST API — on-chain Anchor IDL only | Can't audit via API calls; need CPI analysis | Review Anchor instruction handlers directly |
| Margin/leverage must validate against account model | Over-leverage → liquidation on entry | Check leverage bounds enforcement |

**Audit question:** Does the integration check existing position count and collateral types before CPI calls?

### Trigger (Limit Orders) — Rate Validation Gap

| Gotcha | Audit Impact | What to Check |
|--------|-------------|---------------|
| **Program does NOT validate if rates are favorable** | Users can set self-harmful limit prices | Integration MUST validate target price vs market |
| Frontend enforces $5 min; on-chain has no minimum | Dust order spam possible | Check minimum order enforcement |
| Token-2022 disabled | Orders with Token-2022 mints silently fail | Validate mint standards before order creation |
| Default zero slippage ("Exact" mode) | Orders may never fill | Check if `slippageBps` is configured for "Ultra" mode |
| Max 5 cancels per transaction | Batch cancel overflow | Validate cancel batch size ≤ 5 |

**Critical finding pattern:** If the integration accepts user-supplied limit prices without validating against current market price, users can create orders that execute at a loss. The on-chain program will happily fill them.

### Recurring (DCA) — Constraint Violations

| Gotcha | Audit Impact | What to Check |
|--------|-------------|---------------|
| Token-2022 NOT supported | DCA with Token-2022 mints fails silently | Mint standard validation before DCA creation |
| Price-based recurring orders are **deprecated** | Using `params.price` may break without notice | Ensure only `params.time` is used |
| Min 100 USD total, min 2 orders, min 50 USD/order | Under-minimum orders rejected | Validate constraints client-side |
| 0.1% fee on all recurring orders | Fee-on-fee if integrator adds extra | Disclose total fee to users |

### Price API — Confidence & Null Handling

| Gotcha | Audit Impact | What to Check |
|--------|-------------|---------------|
| Unreliable tokens return `null` or are omitted | `null` ≠ $0; treating as zero causes fund loss | Verify null-safe parsing; null = "unknown", not zero |
| `confidenceLevel` field indicates reliability | Low-confidence prices in safety-critical paths | Check confidence gating before trade execution |
| Max 50 mints per request | Silent truncation if exceeded | Validate request size ≤ 50 |

**Critical pattern:** `if (price === null) price = 0` is a **critical vulnerability** in any valuation, collateral, or liquidation calculation. Null must trigger a fail-closed path.

### Tokens API — Trust Signals

| Gotcha | Audit Impact | What to Check |
|--------|-------------|---------------|
| Use mint address as primary identity | Symbol/name collisions enable phishing | Never match tokens by symbol alone |
| `audit.isSus` flag indicates suspicious tokens | Displaying suspicious tokens as legitimate | Surface `isSus` prominently in UI |
| `organicScore` measures organic trading activity | Low organic = likely wash-traded | Gate high-risk actions on minimum organicScore |

### Send — Invite Code Security

| Gotcha | Audit Impact | What to Check |
|--------|-------------|---------------|
| **Dual-sign requirement**: sender + recipient keypair (from invite code) | Invite code = keypair material; leaking = fund theft | Verify invite codes are never logged, stored plaintext, or transmitted insecurely |
| Claims only via Jupiter Mobile (no API claiming) | Integration can't programmatically claim | Verify no custom claim implementation exists |

### Routing — DEX & RFQ Integration Risks

| Gotcha | Audit Impact | What to Check |
|--------|-------------|---------------|
| DEX: No network calls allowed in AMM implementation | Network calls = routing timeout/DoS | Verify `jupiter-amm-interface` impl is pure computation |
| RFQ: 95% fill rate, 250ms response, 55s expiry required | Sub-threshold = blacklist | Monitor fill rates and response times |
| RFQ: Market makers host webhook endpoints | Webhook compromise = price manipulation | Verify webhook auth, TLS, IP restrictions |
| Market listing: < 30% loss on $500 round-trip OR < 20% impact $1k vs $500 | Illiquid token routing can cause losses | Test round-trip loss for new token integrations |
| Instant routing for tokens < 30 days old | New tokens bypass liquidity checks | Flag new-token swaps in audit |

---

## Production Hardening Audit Checklist

Jupiter documents 10 production hardening rules. Each maps to an audit check:

| # | Rule | Audit Check | Severity |
|---|------|-------------|----------|
| 1 | Fail fast on missing/invalid `x-api-key` | Is API key validated before any request? | High |
| 2 | 5s quote timeout, 30s execute timeout | Are timeout values enforced? Are they configurable? | Medium |
| 3 | Retry only transient failures with backoff+jitter | Does retry logic distinguish transient from permanent errors? | High |
| 4 | Ultra `/execute` idempotent for 2 min (same tx+requestId) | Is `requestId` included in execute calls? | High |
| 5 | Validate mints, amounts, wallet ownership pre-call | Is input validation present before API calls? | Critical |
| 6 | Slippage and max-amount guardrails from app config | Are slippage bounds enforced? What are the defaults? | Critical |
| 7 | Log requestId, API family, endpoint, latency, status, error code | Is structured logging in place? | Low |
| 8 | Return actionable UX states (retry, adjust, insufficient) | Are error states classified for UX? | Low |
| 9 | Reconcile async states before final user success | Is submitted vs confirmed vs failed tracked? | High |
| 10 | Re-fetch docs when behavior differs | N/A for audit (developer practice) | Info |

### Key Audit Findings to Surface

```
[CRITICAL] No slippage guardrails → user can be sandwich-attacked
[CRITICAL] Price null treated as zero → incorrect valuations
[HIGH] No idempotency key → duplicate execution risk
[HIGH] Trigger orders accept unfavorable rates → self-harm trades
[HIGH] No state recompute before lend actions → stale position data
[MEDIUM] Token-2022 mints not filtered → silent failures
[MEDIUM] No timeout enforcement → hung transactions
```

---

## Error Handling Classification

Jupiter errors follow a three-tier pattern that integrations must classify correctly:

### Tier 1: Rate Limits (HTTP 429) — Always Retryable

```
Strategy: Exponential backoff with jitter
Formula:  delay = min(baseDelay × 2^attempt + random(0, jitter), maxDelay)
Window:   10-second sliding window refresh
```

**Audit check:** Does the integration use exponential backoff, or does it burst-retry (which will extend the rate-limit window)?

### Tier 2: Ultra Execute Errors (Negative Codes) — Mixed Retryability

| Code | Meaning | Retryable? |
|------|---------|------------|
| -1 | Generic error | Yes |
| -1000 | Transaction expired | Yes (re-quote) |
| -1001 | Transaction failed | Yes |
| -1005 | Execution timeout | Yes |
| -1006 | Network error | Yes |
| -2000 | Service unavailable | Yes |
| -2003 | Rate limit (internal) | Yes |
| -2005 | Dependency failure | Yes |
| Other negative | Various | **No** — investigate |

**Audit check:** Does the integration retry only the safe negative codes? Retrying non-retryable errors (e.g., insufficient funds) wastes time and may cause double-spend.

### Tier 3: Program Errors (Positive Codes) — Never Retry

| Code | Meaning | Action |
|------|---------|--------|
| 6001 | Slippage exceeded | Re-quote with higher tolerance |
| Other | Program-specific | Investigate; do not retry |

**Audit check:** Does the integration ever retry positive error codes? This is always wrong — program errors indicate logical failures.

---

## Rate Limit Architecture

Jupiter uses dynamic volume-based rate limiting for Ultra Swap:

| 24h Execute Volume | Requests / 10s |
|--------------------|----------------|
| $0 | 50 |
| $10,000 | 51 |
| $100,000 | 61 |
| $1,000,000 | 165 |

**Key properties:**
- Quotas recalculate every 10 minutes based on 24-hour rolling volume
- Pro plan does NOT increase Ultra limits (common misconception)
- Other APIs managed at portal level with separate limits

### Audit Implications

1. **Low-volume integrations** have only 50 req/10s — easy to exceed under load
2. **Volume-based scaling** means new integrations start rate-limited
3. **10-minute recalculation** creates a lag between volume increase and limit increase
4. **No burst allowance** — 50 reqs in 1s triggers same 429 as 50 in 10s

**Audit check:** Does the integration implement request queuing or throttling to stay within limits, or does it rely on 429 handling alone?

---

## Price Confidence & Oracle Safety

### The Null Price Problem

Jupiter Price API returns `null` for tokens with unreliable pricing. This is NOT an error — it's a safety signal.

```
WRONG:  price = response.price ?? 0        // $0 valuation → false liquidation
WRONG:  price = response.price ?? lastKnown // Stale price → wrong decisions
RIGHT:  if (response.price === null) return FAIL_CLOSED  // Halt action
```

### Confidence Level Framework

| Confidence | Meaning | Audit Action |
|------------|---------|-------------|
| `high` | Multiple sources agree | Safe for all operations |
| `medium` | Some source disagreement | Safe for display; gate execution |
| `low` | Significant uncertainty | Display only with warning |
| `null` / missing | Unreliable | Block all value-dependent operations |

### Audit Checklist — Price Safety

- [ ] Null prices trigger fail-closed behavior (not zero-substitution)
- [ ] `confidenceLevel` is checked before price-dependent actions
- [ ] Low-confidence prices are never used for collateral/liquidation calculations
- [ ] Max 50 mints per request is enforced (no silent truncation)
- [ ] Price staleness is bounded (re-fetch if data > N seconds old)
- [ ] Price display clearly distinguishes confidence levels to users

---

## Idempotency & Replay Protection

### Ultra Swap Idempotency

The `/execute` endpoint provides built-in idempotency:
- Same `signedTransaction` + `requestId` → returns same result for 2 minutes
- After 2 minutes → treated as new execution

### Audit Patterns

| Risk | Check |
|------|-------|
| Missing `requestId` | Every `/execute` call must include `requestId` from `/order` response |
| Client-generated requestId | requestId must come from Jupiter `/order`, not client-generated |
| Replay after 2 min TTL | Signed transactions must be invalidated after TTL expiry |
| Network retry without idempotency | Non-idempotent retry → possible double execution |

### State Reconciliation

Before reporting success to users, integrations must reconcile:

```
[submitted] → [confirmed] → [finalized]   ← success
[submitted] → [failed]                     ← retry or abort
[submitted] → [unknown after timeout]      ← check signature status
```

**Audit check:** Does the integration verify transaction confirmation status before displaying success, or does it trust the `/execute` response alone?

---

## Aggregator Routing Security

### Three Routing Engines

| Engine | Role | Security Concern |
|--------|------|-----------------|
| **Juno** | Meta-aggregator (selects best engine) | Route selection integrity |
| **Iris** | Multi-hop DEX routing (powers Ultra) | Intermediate hop manipulation |
| **JupiterZ** | RFQ market maker quotes | MM price manipulation |

### DEX Integration Audit (Iris)

When auditing a DEX that integrates into Jupiter's Iris router:

1. **No network calls** — The `jupiter-amm-interface` implementation must be pure computation over pre-batched accounts. Network calls cause routing timeouts.
2. **Account model integrity** — Verify all required accounts are declared and pre-fetched.
3. **Quote accuracy** — Compare on-chain execution vs quoted output for deviation.
4. **Code health + security audit** — Jupiter requires these as prerequisites.

### RFQ Integration Audit (JupiterZ)

When auditing a market maker's RFQ webhook:

1. **Fill rate ≥ 95%** — Sub-threshold leads to blacklisting
2. **Response time ≤ 250ms** — Timeout = missed quotes
3. **Swap expiry = 55s** — Shorter = failed trades; longer = stale-price risk
4. **Webhook security** — TLS required; verify authentication, IP whitelisting
5. **No selective quoting** — MM must not discriminate by counterparty

### Market Listing Liquidity Rules

| Token Age | Routing Type | Liquidity Requirement |
|-----------|-------------|----------------------|
| < 30 days | Instant | None (auto-routed) |
| ≥ 30 days | Normal (30 min refresh) | < 30% loss on $500 round-trip OR < 20% impact $1k vs $500 |

**Audit concern:** Tokens under 30 days bypass liquidity checks. Integrations displaying new tokens should implement their own liquidity validation.

---

## Token-2022 Compatibility Matrix

Several Jupiter APIs do NOT support Token-2022 (SPL Token Extensions). This is a common integration failure point:

| API | Token-2022 Support | Consequence of Attempt |
|-----|-------------------|----------------------|
| Ultra Swap | ✅ Supported | N/A |
| Lend | ✅ Supported | N/A |
| Perps | ⚠️ Collateral tokens only (USDC/USDT) | Limited asset support |
| **Trigger (Limits)** | ❌ **Disabled** | Order creation silently fails |
| **Recurring (DCA)** | ❌ **Not supported** | Order creation silently fails |
| Tokens API | ✅ Returns metadata | N/A |
| Price API | ✅ Returns prices | N/A |

**Audit check:** Does the integration validate token mint standards before calling Trigger or Recurring APIs? Silent failures lead to user confusion and stuck funds in approval transactions.

---

## Lending Health Factor Patterns

Jupiter Lend requires state recomputation before every action. The integration must:

### Pre-Action Validation Flow

```
1. GET /earn/positions     → current positions + health factor
2. Validate health factor  → abort if below threshold
3. Compute action impact   → new health factor after deposit/withdraw/borrow
4. Execute if safe         → POST action endpoint
5. Verify post-action      → re-fetch positions and confirm state
```

### Health Factor Thresholds (Recommended)

| Health Factor | State | Allowed Actions |
|---------------|-------|----------------|
| > 1.5 | Healthy | All operations |
| 1.2 – 1.5 | Caution | Deposits, repayments; warn on new borrows |
| 1.0 – 1.2 | Danger | Repayments only; block new borrows |
| < 1.0 | Liquidatable | Emergency repay only |

**Audit check:** Does the integration enforce health factor floors, or does it blindly pass through any borrow request?

### Unsigned Transaction Risk

All Lend endpoints return unsigned `VersionedTransaction` (base64). Audit points:

- [ ] Transactions are signed immediately upon receipt
- [ ] Unsigned transactions are never persisted to storage
- [ ] Transaction content is validated before signing (expected instructions match)
- [ ] Signing happens client-side only (never server-side with user keys)

---

## Limit Order & DCA Validation

### Limit Order Price Validation

Since the Trigger program does **not** validate rate favorability:

```
Pre-order validation:
1. Fetch current market price (Price API)
2. Compare user's target price to market
3. For buy limits: target must be BELOW market (or within tolerance)
4. For sell limits: target must be ABOVE market (or within tolerance)
5. Reject orders where user would lose > X% vs market
6. Surface clear price comparison in confirmation UI
```

### DCA Order Validation

```
Pre-DCA validation:
1. Verify token is NOT Token-2022 (standard SPL only)
2. Verify only time-based parameters (no deprecated price-based)
3. Validate: total ≥ $100, orders ≥ 2, per-order ≥ $50
4. Check input token has sufficient liquidity for recurring execution
5. Estimate total fees (0.1% × number of orders)
6. Calculate effective execution price range under volatile scenarios
```

---

## Cross-Cutting Audit Checklist

### Authentication & Authorization

- [ ] `x-api-key` validated before every Jupiter REST call
- [ ] API key never exposed in client-side code or logs
- [ ] Wallet ownership verified before transaction signing
- [ ] Invite codes (Send API) never logged or stored plaintext

### Input Validation

- [ ] Mint addresses validated against Tokens API before use
- [ ] Amounts validated for correct decimal precision per token
- [ ] Slippage bounded (both floor and ceiling)
- [ ] Batch sizes respect per-API limits (50 mints/price, 5 cancels/trigger, 10 orders/page)

### Transaction Safety

- [ ] Re-quote before signing if conditions may have changed
- [ ] Signed transactions invalidated after 2-min TTL
- [ ] `requestId` from `/order` always included in `/execute`
- [ ] Transaction confirmation status verified before success display
- [ ] Async state reconciliation (submitted → confirmed → finalized)

### Error Handling

- [ ] HTTP 429 → exponential backoff with jitter (never burst-retry)
- [ ] Negative error codes → retry only safe subset (-1, -1000, -1001, -1005, -1006, -2000, -2003, -2005)
- [ ] Positive error codes → never retry (program errors)
- [ ] Null/missing prices → fail-closed (never zero-substitute)

### Token Compatibility

- [ ] Token-2022 mints filtered before Trigger and Recurring API calls
- [ ] Token identity by mint address (never by symbol/name alone)
- [ ] `audit.isSus` flag surfaced in UI
- [ ] `organicScore` gating for high-risk operations

### Rate Limiting

- [ ] Request throttling implemented (not just 429 handling)
- [ ] Awareness that Ultra starts at 50 req/10s for new integrations
- [ ] No assumption that Pro plan increases Ultra limits
- [ ] 10-second sliding window understood in backoff logic

---

## Relationship to Other Skill Files

| Topic | See Also |
|-------|---------|
| Solana oracle patterns (Pyth, Switchboard) | [solana-oracle-audit.md](solana-oracle-audit.md) |
| DeFi perpetuals audit patterns | [patterns/defi-perpetuals-audit.md](../../patterns/defi-perpetuals-audit.md) |
| Solana testing strategies | [solana-testing-for-auditors.md](solana-testing-for-auditors.md) |
| Multisig/session key patterns | [multisig-smart-account-audit.md](multisig-smart-account-audit.md) |
| Codebase recon methodology | [methodology/codebase-recon-methodology.md](../../methodology/codebase-recon-methodology.md) |

---

## References

- [Jupiter Developer Docs](https://dev.jup.ag/)
- [Jupiter Portal (API Keys)](https://portal.jup.ag/)
- [Jupiter Status Page](https://status.jup.ag/)
- [Ultra OpenAPI Spec](https://dev.jup.ag/openapi-spec/ultra/ultra.yaml)
- [Lend OpenAPI Spec](https://dev.jup.ag/openapi-spec/lend/lend.yaml)
- [Trigger OpenAPI Spec](https://dev.jup.ag/openapi-spec/trigger/trigger.yaml)
- [Recurring OpenAPI Spec](https://dev.jup.ag/openapi-spec/recurring/recurring.yaml)
- [RFQ Webhook Toolkit](https://github.com/jup-ag/rfq-webhook-toolkit)
- [Jupiter Lock Program](https://github.com/jup-ag/jup-lock)
- [Jupiter AMM Interface (Rust)](https://github.com/jup-ag/rust-amm-implementation)
- [Perps Anchor IDL Parser](https://github.com/julianfssen/jupiter-perps-anchor-idl-parsing)
