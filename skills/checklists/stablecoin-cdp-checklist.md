# Stablecoin & CDP Protocol Audit Checklist

## 1. Collateralized Debt Position (CDP) Mechanics
- [ ] **CRITICAL** Debt minting: stablecoin issued only against sufficient collateral at correct ratio
- [ ] **CRITICAL** Collateral ratio enforced at all times — no path to mint below minimum
- [ ] **CRITICAL** Stablecoin total supply equals sum of all active CDP debt plus protocol surplus
- [ ] **HIGH** Debt ceiling per collateral type bounded and enforced
- [ ] **HIGH** CDP owner cannot withdraw collateral below liquidation threshold
- [ ] **HIGH** Dust position prevention: minimum debt per CDP enforced
- [ ] **MEDIUM** Opening fee (origination fee) applied correctly and cannot be bypassed
- [ ] **MEDIUM** Multi-collateral CDPs: each collateral type has independent risk parameters

## 2. Peg Stability
- [ ] **CRITICAL** Peg mechanism: arbitrage loop (mint at $1, buy below $1, or vice versa) works
- [ ] **CRITICAL** Stability fee (interest) accrual calculation correct and continuous
- [ ] **HIGH** Peg stability module (PSM): 1:1 swap with correct fee and cap
- [ ] **HIGH** Reserve ratio: protocol-owned reserves sufficient to absorb depeg scenarios
- [ ] **HIGH** Savings rate (DSR equivalent): funded by stability fees, not inflationary
- [ ] **MEDIUM** Depeg circuit breaker: pause minting/redemption below threshold
- [ ] **MEDIUM** External stablecoin collateral (USDC backing): centralization risk documented
- [ ] **LOW** Peg deviation monitored — oracle reports stablecoin price alongside collateral

## 3. Liquidation
- [ ] **CRITICAL** Liquidation triggers when collateral value / debt falls below ratio
- [ ] **CRITICAL** Liquidation auction: collateral sold at fair market price (Dutch or English)
- [ ] **CRITICAL** Bad debt: deficit socialized correctly (protocol surplus or governance backstop)
- [ ] **HIGH** Liquidation penalty incentivizes keepers without excessive user loss
- [ ] **HIGH** Partial liquidation: allows closing portion of debt to restore ratio
- [ ] **HIGH** Flash loan liquidation: no advantage over normal liquidation
- [ ] **MEDIUM** Auction duration bounded — not so fast that keepers can't compete
- [ ] **MEDIUM** Cascading liquidation analysis: ETH price drop triggers multiple CDPs
- [ ] **LOW** Liquidation events emitted with collateral type, amount, and auction ID

## 4. Algorithmic Stability (if applicable)
- [ ] **CRITICAL** Mint/burn mechanism: rebase or seigniorage does not create infinite supply
- [ ] **CRITICAL** Death spiral protection: contraction mechanism bounded to prevent bank run
- [ ] **HIGH** Secondary token (governance/seigniorage): dilution capped per epoch
- [ ] **HIGH** Redemption during contraction: not first-come-first-served (queue or pro rata)
- [ ] **HIGH** Fractional reserve: backing ratio transparent and verifiable on-chain
- [ ] **MEDIUM** Expansion: new supply distributed to stakers/LPs proportionally
- [ ] **MEDIUM** Oracle for stablecoin price uses TWAP, not spot (manipulation resistance)
- [ ] **LOW** Historical peg deviation logged for governance monitoring

## 5. Oracle Integration
- [ ] **CRITICAL** Collateral price oracle manipulation-resistant (Chainlink, TWAP, or multi-source)
- [ ] **CRITICAL** Stale price detection: CDPs not liquidated on stale data
- [ ] **HIGH** Oracle failure mode: minting paused, not default to zero price
- [ ] **HIGH** L2 sequencer uptime feed checked before liquidation
- [ ] **HIGH** Price feed for exotic collateral (LSTs, LP tokens) uses fair value calculation
- [ ] **MEDIUM** Oracle update frequency sufficient for collateral volatility
- [ ] **MEDIUM** Price deviation between oracle sources triggers alert or pause

## 6. Governance and Risk Parameters
- [ ] **CRITICAL** Debt ceiling changes timelocked — cannot raise instantly to drain protocol
- [ ] **CRITICAL** Collateral ratio changes timelocked and bounded
- [ ] **HIGH** Emergency shutdown: can freeze protocol and allow proportional collateral redemption
- [ ] **HIGH** Stability fee changes prospective only — no retroactive debt increase
- [ ] **HIGH** New collateral onboarding requires governance vote with timelock
- [ ] **MEDIUM** Protocol surplus distribution (buyback, burn, treasury) governed transparently
- [ ] **MEDIUM** Governance can add but not remove collateral types without migration path
- [ ] **LOW** Risk parameter history logged for auditability

## 7. Redemption
- [ ] **CRITICAL** Redemption: stablecoin holder can always redeem for $1 of collateral
- [ ] **CRITICAL** Redemption selects lowest-ratio CDPs (riskiest first) to improve system health
- [ ] **HIGH** Redemption fee: dynamic fee prevents griefing of CDP owners
- [ ] **HIGH** Redemption: cannot drain specific CDP below minimum debt (dust)
- [ ] **MEDIUM** Redemption cool-down or rate limit prevents mass redemption cascade
- [ ] **MEDIUM** Redeemed collateral: correct asset type returned (not a different collateral)
- [ ] **LOW** Redemption events emitted with CDP owner, collateral type, and amount

## 8. Token Compatibility
- [ ] **HIGH** Collateral: fee-on-transfer tokens handled — actual received amount credited
- [ ] **HIGH** Collateral: rebasing tokens use share-based accounting
- [ ] **HIGH** Collateral: low-decimal tokens — precision loss in ratio calculations
- [ ] **HIGH** Stablecoin: ERC-20 compliance — transfer, approve, transferFrom correct
- [ ] **MEDIUM** Collateral: tokens with blacklists — CDP owner can still repay/close
- [ ] **MEDIUM** Collateral: upgradeable tokens — behavior change risk documented
- [ ] **LOW** Stablecoin: permit (EIP-2612) supported correctly

## 9. Protocol Accounting
- [ ] **CRITICAL** Global invariant: total collateral value ≥ total debt × minimum ratio
- [ ] **CRITICAL** Surplus and deficit tracking accurate across all vaults
- [ ] **HIGH** Interest accrual: compounding per second matches intended APR
- [ ] **HIGH** Protocol-owned liquidity (if any) accounted separately from user collateral
- [ ] **MEDIUM** Flash mint of stablecoin: invariant holds within same transaction
- [ ] **MEDIUM** Accounting remains correct during partial liquidation + repayment in same block
- [ ] **LOW** Surplus auction and deficit auction mutually exclusive
