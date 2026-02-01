---
id: PLAYBOOK-HYPERLIQUID
title: Hyperliquid Integration Playbook
category: protocol-playbooks
protocol: hyperliquid
version: mainnet
difficulty: advanced
tags: [hyperliquid, perpetuals, orderbook, dex, l1]
last_updated: 2026-01-31
---

# Hyperliquid Integration Playbook

## Protocol Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    HYPERLIQUID L1                               │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │   Perp DEX  │  │  Spot DEX   │  │   Vaults    │             │
│  │  (Orderbook)│  │ (Orderbook) │  │ (Strategies)│             │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘             │
│         │                │                │                     │
│         └────────────────┼────────────────┘                     │
│                          ▼                                      │
│              ┌───────────────────────┐                          │
│              │    Clearing Layer     │                          │
│              │ (Margin & Liquidation)│                          │
│              └───────────────────────┘                          │
│                          │                                      │
│              ┌───────────▼───────────┐                          │
│              │   Bridge (Arbitrum)   │                          │
│              │    USDC Deposits      │                          │
│              └───────────────────────┘                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Concepts

### 1. Order Book Architecture

Unlike AMM-based perp DEXs, Hyperliquid uses a fully on-chain order book:

```python
# Order structure
Order = {
    "asset": int,           # Asset index (0 = BTC, 1 = ETH, etc.)
    "isBuy": bool,          # True = long, False = short
    "limitPx": float,       # Limit price
    "sz": float,            # Size in contracts
    "reduceOnly": bool,     # Only reduce position
    "orderType": {
        "limit": {"tif": "Gtc"},  # Good til cancel
        # or "Ioc" (immediate or cancel)
        # or "Alo" (add liquidity only)
    },
    "cloid": str            # Client order ID (optional)
}
```

### 2. Margin System

```python
# Cross-margin by default
# Isolated margin available per position

Margin Types:
├── Cross Margin (default)
│   └── All positions share account margin
├── Isolated Margin
│   └── Per-position margin allocation
└── Portfolio Margin (for advanced users)
    └── Risk-based margining across positions
```

### 3. Vault System

```python
# Vaults = Strategy containers managed by leaders
Vault = {
    "name": str,
    "leader": Address,
    "lockupPeriod": int,      # Days before withdrawal
    "profitShare": float,     # Leader's cut (e.g., 10%)
    "maxCapacity": float,     # USDC limit
    "followers": List[Address]
}

# Risk: Leader can take risky positions
# Risk: Lockup prevents exit during drawdown
```

---

## Integration Patterns

### Placing Orders via API

```python
import json
import time
from eth_account import Account
from hyperliquid.utils import sign_l1_action

# Initialize
wallet = Account.from_key(PRIVATE_KEY)
info = Info(base_url="https://api.hyperliquid.xyz")
exchange = Exchange(wallet, base_url="https://api.hyperliquid.xyz")

# Place limit order
order_result = exchange.order(
    coin="BTC",
    is_buy=True,
    sz=0.1,
    limit_px=42000.0,
    order_type={"limit": {"tif": "Gtc"}},
    reduce_only=False
)

# Place market order (use aggressive limit)
market_order = exchange.order(
    coin="ETH", 
    is_buy=True,
    sz=1.0,
    limit_px=None,  # Market order
    order_type={"limit": {"tif": "Ioc"}}
)
```

### Vault Interactions

```python
# Deposit to vault
exchange.vault_transfer(
    vault_address="0x...",
    is_deposit=True,
    usd=10000.0
)

# Withdraw from vault (subject to lockup)
exchange.vault_transfer(
    vault_address="0x...",
    is_deposit=False,
    usd=5000.0
)
```

### Reading Market Data

```python
# Get order book
orderbook = info.l2_snapshot("BTC")
# Returns: {"levels": [[price, size], ...], "time": timestamp}

# Get user positions
positions = info.user_state(wallet.address)
# Returns margin info, positions, open orders

# Get funding rate
meta = info.meta()
funding = meta["universe"][0]["funding"]  # Current funding rate
```

---

## Security Considerations

### 1. API Key Security

```python
# CRITICAL: Never expose API keys
# Hyperliquid uses wallet signatures, not API keys

# Safe pattern: Sign locally, send signature
action = {
    "type": "order",
    "orders": [order],
    "grouping": "na"
}
signature = sign_l1_action(wallet, action, timestamp, is_mainnet=True)

# Unsafe: Exposing private key to third parties
```

### 2. Liquidation Risks

```python
# Liquidation happens when:
# Account Value < Maintenance Margin

# Maintenance margin = sum of position margins
# Position margin = |size| * mark_price * maintenance_margin_rate

# Example liquidation check
def check_liquidation_risk(account_value, positions):
    maintenance_margin = 0
    for pos in positions:
        mm_rate = get_mm_rate(pos["coin"])  # Usually 0.5-3%
        maintenance_margin += abs(pos["szi"]) * pos["markPx"] * mm_rate
    
    return account_value < maintenance_margin
```

### 3. Funding Rate Manipulation

```solidity
// Funding = (Mark Price - Index Price) / Index Price * rate
// Funding paid every hour

// Risk: Large positions can temporarily skew mark price
// Mitigation: Use TWAP for mark price calculation

// Auditor check:
// - Can large traders manipulate funding to drain opponents?
// - Is mark price TWAP window sufficient?
```

### 4. Vault Leader Risks

```python
# Vault followers trust the leader completely
# Leader can:
# - Take excessive leverage
# - Trade illiquid assets
# - Time entries/exits against followers

# Audit checks:
# [ ] Max leverage limits enforced?
# [ ] Position size limits per asset?
# [ ] Leader skin-in-the-game requirements?
# [ ] Transparent fee structure?
```

---

## Common Vulnerabilities

### 1. Oracle/Index Price Manipulation

```python
# Hyperliquid uses external index prices
# Index = median of CEX prices (Binance, OKX, etc.)

# Attack vector:
# 1. Manipulate CEX prices (wash trading)
# 2. Skew index price
# 3. Profit from funding or liquidations

# Defense: Multiple sources, outlier filtering
```

### 2. Order Griefing

```python
# Spamming orders to congest the orderbook
# Or placing/canceling to mislead traders

# Mitigation:
# - Rate limits on orders per second
# - Minimum order size
# - Cancel fees for excessive cancellations
```

### 3. Liquidation Cascades

```python
# Large liquidation → price impact → more liquidations

# Check:
# - Liquidation engine uses fair price?
# - Backstop/insurance fund sufficient?
# - Maximum liquidation per block limited?
```

### 4. Bridge Risks (Arbitrum ↔ Hyperliquid)

```python
# Deposits/withdrawals go through Arbitrum bridge

# Risks:
# - Bridge contract vulnerabilities
# - Finality assumptions
# - USDC blacklisting

# Always verify:
# - Bridge contract audited?
# - Withdrawal delay appropriate?
# - Emergency pause mechanism?
```

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/info` | POST | Account state, positions |
| `/exchange` | POST | Place/cancel orders |
| `/info/l2Book` | POST | Order book snapshot |
| `/info/candleSnapshot` | POST | Historical candles |
| `/info/fundingHistory` | POST | Funding rate history |

---

## Audit Checklist

### Order Execution
```
[ ] Order matching is deterministic and fair (FIFO)?
[ ] No front-running by validators/sequencer?
[ ] Price-time priority enforced correctly?
[ ] Reduce-only orders can't increase position?
[ ] Order size/price bounds validated?
```

### Margin & Liquidation
```
[ ] Margin calculations use correct prices?
[ ] Liquidation threshold appropriate for volatility?
[ ] Liquidation proceeds distributed fairly?
[ ] Insurance fund properly funded?
[ ] No self-liquidation exploits?
```

### Vaults
```
[ ] Vault leader can't steal funds directly?
[ ] Withdrawal lockup enforced correctly?
[ ] Profit share calculated accurately?
[ ] Max capacity prevents oversized vaults?
[ ] Follower can always withdraw (after lockup)?
```

### Bridge Security
```
[ ] Bridge uses proper finality confirmations?
[ ] Withdrawal limits/delays in place?
[ ] Emergency pause functionality?
[ ] Multi-sig or decentralized validation?
```

---

## Quick Reference

| Parameter | Value |
|-----------|-------|
| Max Leverage | 50x (varies by asset) |
| Min Order Size | $10 |
| Funding Interval | 1 hour |
| Liquidation Fee | 0.5% |
| Taker Fee | 0.025% |
| Maker Rebate | 0.002% |
| Withdrawal Time | ~15 minutes |

---

## Related Resources

- [Hyperliquid Docs](https://hyperliquid.gitbook.io/)
- [API Reference](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api)
- [Risk Parameters](https://hyperliquid.gitbook.io/hyperliquid-docs/trading/risk)
