# Perpetuals & Derivatives Protocol Audit Checklist

## 1. Position Management
- [ ] **CRITICAL** Position size cannot exceed available liquidity or open interest caps
- [ ] **CRITICAL** Leverage calculation correct — initial margin and maintenance margin enforced
- [ ] **CRITICAL** Position value tracks oracle price accurately (no stale mark price)
- [ ] **HIGH** Long and short open interest balanced or bounded by protocol caps
- [ ] **HIGH** Position cannot be opened and liquidated in the same transaction
- [ ] **HIGH** Maximum leverage per asset enforced (e.g., 50x BTC, 20x altcoins)
- [ ] **MEDIUM** Minimum position size enforced to prevent dust positions
- [ ] **MEDIUM** Partial close calculates remaining margin and PnL correctly

## 2. Margin and Collateral
- [ ] **CRITICAL** Cross-margin: total account value tracks all positions, not just one
- [ ] **CRITICAL** Isolated margin: one position's loss cannot drain another's collateral
- [ ] **CRITICAL** Collateral value uses manipulation-resistant oracle pricing
- [ ] **HIGH** Multi-collateral: each asset weighted by risk factor (haircut applied)
- [ ] **HIGH** Collateral withdrawal blocked while positions are below maintenance margin
- [ ] **HIGH** Fee-on-transfer and rebasing tokens handled correctly as collateral
- [ ] **MEDIUM** Margin ratio calculation uses correct unrealized PnL direction
- [ ] **MEDIUM** Cross-margin ↔ isolated margin mode switch cannot leave position undercollateralized

## 3. Liquidation Engine
- [ ] **CRITICAL** Liquidation triggers at correct maintenance margin threshold
- [ ] **CRITICAL** Liquidation cannot be front-run by MEV bots extracting value before liquidator
- [ ] **CRITICAL** Insurance fund covers bad debt when liquidation doesn't fully close position
- [ ] **HIGH** Partial liquidation reduces position to safe margin, not full close
- [ ] **HIGH** Liquidation penalty/fee doesn't exceed remaining collateral
- [ ] **HIGH** ADL (Auto-Deleveraging) only triggers when insurance fund is depleted
- [ ] **HIGH** ADL selects counterparties fairly (by profit and leverage ranking)
- [ ] **MEDIUM** Liquidation incentive covers gas costs on all supported chains
- [ ] **MEDIUM** Cascading liquidations analyzed — one large liquidation triggering others
- [ ] **LOW** Liquidation events emitted with full position details for monitoring

## 4. Funding Rate
- [ ] **CRITICAL** Funding rate calculation: (mark price - index price) / index price, bounded
- [ ] **CRITICAL** Funding rate applied to correct position direction (longs pay shorts or vice versa)
- [ ] **HIGH** Funding rate magnitude capped to prevent extreme payments
- [ ] **HIGH** Funding rate settlement: periodic (8h) or continuous, applied consistently
- [ ] **HIGH** Funding rate cannot be manipulated via flash loan position opening
- [ ] **MEDIUM** Funding rate at zero when mark price equals index price
- [ ] **MEDIUM** Accrued funding tracked correctly across position modifications
- [ ] **LOW** Historical funding rate accessible for UI display and verification

## 5. Oracle and Price Feeds
- [ ] **CRITICAL** Mark price uses time-weighted or median oracle, not spot price
- [ ] **CRITICAL** Index price aggregates multiple sources — no single-source dependency
- [ ] **CRITICAL** Stale oracle price detection with fallback or position freeze
- [ ] **HIGH** Price deviation between mark and index bounded (circuit breaker)
- [ ] **HIGH** Oracle update on L2 checks sequencer uptime (Chainlink L2 sequencer feed)
- [ ] **HIGH** Price bands prevent execution at prices far from fair value
- [ ] **MEDIUM** Price impact calculation accurate for large orders moving the mark price
- [ ] **MEDIUM** Oracle failure mode: positions cannot be liquidated on stale prices

## 6. Order Book / Matching Engine
- [ ] **CRITICAL** Market orders execute at correct mark price with slippage protection
- [ ] **CRITICAL** Limit orders cannot be filled at worse price than specified
- [ ] **HIGH** Stop-loss and take-profit trigger at correct price with bounded slippage
- [ ] **HIGH** Order expiry enforced — expired orders cannot be executed
- [ ] **HIGH** Reduce-only orders cannot increase position size
- [ ] **MEDIUM** Order priority: time-priority or pro-rata, consistently applied
- [ ] **MEDIUM** Post-only orders rejected if they would immediately match
- [ ] **LOW** Maximum open orders per account bounded to prevent DoS

## 7. PnL Settlement
- [ ] **CRITICAL** Realized PnL calculation: (exit price - entry price) × size × direction
- [ ] **CRITICAL** Settlement pool/vault has sufficient funds to pay profitable traders
- [ ] **HIGH** Unrealized PnL correctly marks to current oracle price
- [ ] **HIGH** Fee deduction happens before PnL credit (not double-counted)
- [ ] **HIGH** Global PnL tracking: net protocol exposure stays within risk bounds
- [ ] **MEDIUM** Profit withdrawal checks vault liquidity — cannot drain settlement pool
- [ ] **MEDIUM** Rolling PnL: position modification recalculates average entry price correctly

## 8. Liquidity Provider (LP) Vault
- [ ] **CRITICAL** LP vault share price cannot be manipulated via donation attack
- [ ] **CRITICAL** LP exposure: vault is counterparty to traders — risk is two-sided
- [ ] **HIGH** LP deposit/withdraw uses time-weighted share pricing
- [ ] **HIGH** Maximum utilization: LP vault cannot be fully utilized by open positions
- [ ] **HIGH** LP withdrawal cooldown prevents JIT liquidity that avoids counterparty risk
- [ ] **MEDIUM** LP fee distribution proportional to time-weighted share ownership
- [ ] **MEDIUM** LP vault rebalancing between long and short exposure managed safely

## 9. Fee Structure
- [ ] **HIGH** Trading fee (open/close) correctly applied as percentage of notional
- [ ] **HIGH** Borrowing fee (hourly rate) accrues correctly on position value
- [ ] **HIGH** Fee tier discounts based on volume or staking cannot be gamed
- [ ] **MEDIUM** Fee distribution: protocol treasury, LP vault, referrals split correctly
- [ ] **MEDIUM** Fee-free positions not possible through contract direct interaction
- [ ] **LOW** Fee parameter changes bounded and timelocked

## 10. Protocol Safety
- [ ] **CRITICAL** Global open interest cap prevents protocol from exceeding risk capacity
- [ ] **HIGH** Emergency pause: can freeze new positions while allowing close/liquidation
- [ ] **HIGH** Maximum single-position size bounded relative to total liquidity
- [ ] **HIGH** Price impact fee increases with position size to discourage manipulation
- [ ] **MEDIUM** Position netting: long and short in same asset by same user handled correctly
- [ ] **MEDIUM** Keeper/executor role: order execution permissioned or incentivized correctly
- [ ] **LOW** Historical trade data and open interest queryable for transparency
