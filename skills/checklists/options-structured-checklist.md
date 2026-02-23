# Options & Structured Products Audit Checklist

## 1. Option Pricing and Greeks
- [ ] **CRITICAL** Option premium calculation uses correct model (Black-Scholes, binomial)
- [ ] **CRITICAL** Implied volatility (IV) sourced from manipulation-resistant oracle or TWAP
- [ ] **CRITICAL** Strike price and expiry immutable after option creation
- [ ] **HIGH** Greeks (delta, gamma, vega, theta) calculated correctly for risk engine
- [ ] **HIGH** Time decay (theta) computed accurately — no jump at epoch boundaries
- [ ] **HIGH** Volatility surface: IV per strike/expiry pair stored or computed consistently
- [ ] **MEDIUM** Premium cannot be manipulated via flash loan before purchase
- [ ] **MEDIUM** Pricing model handles extreme edge cases (deep ITM, deep OTM, near-expiry)

## 2. Option Lifecycle
- [ ] **CRITICAL** Exercise only allowed when option is in-the-money (ITM) at expiry
- [ ] **CRITICAL** Settlement price from oracle matches exact expiry timestamp
- [ ] **CRITICAL** Expired options cannot be exercised after settlement window
- [ ] **HIGH** European vs American exercise: early exercise correctly allowed or blocked
- [ ] **HIGH** Auto-exercise at expiry for ITM options if protocol supports it
- [ ] **HIGH** Settlement: cash-settled pays difference, physically-settled delivers underlying
- [ ] **MEDIUM** Grace period for exercise after expiry is bounded and documented
- [ ] **MEDIUM** Option token (ERC-20/1155) correctly minted on write and burned on exercise

## 3. Collateral and Margin
- [ ] **CRITICAL** Option writer locks sufficient collateral to cover maximum payout
- [ ] **CRITICAL** Naked call: unlimited loss — collateral must cover price spike scenarios
- [ ] **CRITICAL** Spread positions: net collateral correctly reduced for defined-risk strategies
- [ ] **HIGH** Collateral release only after expiry + settlement, not before
- [ ] **HIGH** Multi-collateral: each type weighted by risk factor
- [ ] **HIGH** Collateral value uses manipulation-resistant oracle (not spot)
- [ ] **MEDIUM** Partial collateral withdrawal allowed only if remaining covers worst case
- [ ] **MEDIUM** Cross-margining between option positions reduces capital requirement correctly

## 4. Vault Strategies (Structured Products)
- [ ] **CRITICAL** Vault share price cannot be manipulated via donation or first-depositor attack
- [ ] **CRITICAL** Strategy execution (selling covered calls, puts) matches vault description
- [ ] **CRITICAL** Vault cannot sell options exceeding deposited collateral
- [ ] **HIGH** Epoch rollover: old options settled before new round starts
- [ ] **HIGH** Vault deposit/withdraw windows enforced — no JIT deposits before premium
- [ ] **HIGH** Strike selection algorithm bounded — cannot choose strikes guaranteeing loss
- [ ] **MEDIUM** Performance fee calculated on actual gains, not unrealized
- [ ] **MEDIUM** Vault capacity cap enforced to prevent liquidity concentration
- [ ] **LOW** Historical vault performance data accurate and verifiable on-chain

## 5. Liquidation and Risk Management
- [ ] **CRITICAL** Undercollateralized option writers liquidated before insolvency
- [ ] **CRITICAL** Liquidation uses fair mark price, not manipulable spot
- [ ] **HIGH** Liquidation incentive covers gas costs across all supported chains
- [ ] **HIGH** Portfolio margin: net exposure calculated across all positions
- [ ] **HIGH** Maximum loss per position bounded and enforced by contract
- [ ] **MEDIUM** Cascading liquidation risk: large writer liquidation doesn't cause price spiral
- [ ] **MEDIUM** Insurance fund or backstop for bad debt from gap risk
- [ ] **LOW** Liquidation events emitted with full position and price details

## 6. Oracle Integration
- [ ] **CRITICAL** Settlement oracle returns price at exact expiry timestamp (not latest)
- [ ] **CRITICAL** Oracle manipulation cannot shift settlement price (TWAP or multi-source)
- [ ] **HIGH** Stale price detection: options cannot be exercised against stale oracle
- [ ] **HIGH** IV oracle (if external): validated against on-chain realized volatility
- [ ] **HIGH** L2 sequencer uptime checked before settlement
- [ ] **MEDIUM** Oracle failure mode: settlement delayed, not defaulted to zero
- [ ] **MEDIUM** Price feed decimal precision sufficient for strike price granularity

## 7. Token Compatibility
- [ ] **HIGH** Underlying asset: rebasing tokens excluded or share-based accounting used
- [ ] **HIGH** Fee-on-transfer tokens: actual received amount used for collateral
- [ ] **HIGH** Option NFTs/tokens: correct ERC standard compliance (721/1155/20)
- [ ] **MEDIUM** Token with blacklists: option exercise not blocked for blacklisted addresses
- [ ] **MEDIUM** Low-decimal tokens: precision loss in premium/payout calculation
- [ ] **LOW** Exotic underlyings (LP tokens, yield-bearing): valuation methodology documented

## 8. MEV and Front-Running
- [ ] **HIGH** Option purchase cannot be front-run to move IV and increase premium
- [ ] **HIGH** Settlement transaction cannot be sandwiched to manipulate oracle
- [ ] **HIGH** Vault strategy execution (strike selection) not predictable by MEV searchers
- [ ] **MEDIUM** Commit-reveal for large option orders to prevent information leakage
- [ ] **MEDIUM** Batch auction for option sales prevents price sniping
- [ ] **LOW** Keeper/executor for settlements is permissioned or uses private mempool

## 9. Exotic Option Types
- [ ] **HIGH** Binary/digital options: payout is fixed amount or zero — no partial payout bugs
- [ ] **HIGH** Barrier options (knock-in/knock-out): barrier condition checked at correct frequency
- [ ] **HIGH** Perpetual options (Everlasting): funding mechanism analogous to perp funding rate
- [ ] **MEDIUM** Power perpetuals (Squeeth): squared payoff calculated correctly
- [ ] **MEDIUM** Range tokens: bounded payoff between floor and cap enforced
- [ ] **LOW** Quanto options: cross-currency risk accounted for in pricing
