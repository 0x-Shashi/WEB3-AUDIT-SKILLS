# DeFi Lending Protocol Audit Checklist

## 1. Collateral Management
- [ ] **CRITICAL** Collateralization ratio enforced correctly at all times
- [ ] **CRITICAL** Oracle price feeds accurate and manipulation-resistant
- [ ] **CRITICAL** Collateral cannot be withdrawn below liquidation threshold
- [ ] **HIGH** Multiple collateral types handled with correct risk parameters
- [ ] **HIGH** Collateral factor / LTV ratio per asset is appropriate
- [ ] **HIGH** Isolated collateral pools don't cross-contaminate risk
- [ ] **MEDIUM** Collateral value calculated in correct denomination (USD/ETH)
- [ ] **MEDIUM** Collateral tokens can't be used simultaneously in multiple positions

## 2. Borrowing Logic
- [ ] **CRITICAL** Cannot borrow more than collateral allows
- [ ] **CRITICAL** Borrow rate calculation is correct (jump rate model)
- [ ] **CRITICAL** Interest accrual: block-by-block or time-based, consistent
- [ ] **HIGH** Borrow cap per asset enforced
- [ ] **HIGH** Utilization rate calculation: borrows / (cash + borrows - reserves)
- [ ] **HIGH** Interest rate model parameters reasonable (base rate, multiplier, kink)
- [ ] **MEDIUM** Borrow balance correctly tracks accrued interest
- [ ] **MEDIUM** Cannot borrow dust amounts that are impossible to liquidate

## 3. Liquidation
- [ ] **CRITICAL** Liquidation triggers correctly when health factor < 1 (or threshold)
- [ ] **CRITICAL** Liquidation incentive/bonus doesn't drain excess collateral
- [ ] **CRITICAL** Liquidation doesn't leave bad debt (underwater positions)
- [ ] **HIGH** Partial liquidation: close factor limits how much can be liquidated at once
- [ ] **HIGH** Liquidation price calculation uses correct oracle
- [ ] **HIGH** Self-liquidation prevented or intentionally allowed
- [ ] **HIGH** Flash loan liquidation attacks considered
- [ ] **MEDIUM** Liquidation gas costs don't exceed incentive (small positions)
- [ ] **MEDIUM** Cascading liquidations analyzed (one liquidation triggers others)
- [ ] **LOW** Liquidation events emitted for monitoring

## 4. Supply/Deposit
- [ ] **CRITICAL** First depositor attack: initial shares inflation
- [ ] **CRITICAL** Share/token exchange rate cannot be manipulated (donation attack)
- [ ] **HIGH** Deposit cap per asset enforced
- [ ] **HIGH** Interest distribution proportional to share ownership
- [ ] **HIGH** Fee-on-transfer tokens: actual received amount used
- [ ] **MEDIUM** Withdrawal: sufficient liquidity check (utilization < 100%)
- [ ] **MEDIUM** Withdrawal queue fair (no preferential treatment)
- [ ] **LOW** Minimum deposit amount enforced

## 5. Interest Rate Model
- [ ] **HIGH** Interest rate model: rate increases with utilization
- [ ] **HIGH** Kink model: sharp rate increase above optimal utilization
- [ ] **HIGH** Reserve factor: protocol takes appropriate cut
- [ ] **MEDIUM** Rate model parameters can be updated (governance risk)
- [ ] **MEDIUM** Extreme utilization: rates don't overflow or underflow
- [ ] **LOW** Interest compounds correctly over time gaps

## 6. Flash Loan Specifics
- [ ] **CRITICAL** Flash loan fee correctly applied
- [ ] **CRITICAL** Protocol state consistent after flash loan (invariants hold)
- [ ] **HIGH** Flash loan can't be used to manipulate internal accounting
- [ ] **HIGH** Borrowing + flash loan in same block considered
- [ ] **MEDIUM** Flash loan reentrancy in callback function

## 7. Oracle Integration
- [ ] **CRITICAL** Price feed: not using DEX spot price
- [ ] **CRITICAL** Stale price protection (heartbeat timeout)
- [ ] **HIGH** Oracle failure mode: what happens when oracle is down?
- [ ] **HIGH** Multi-oracle with median or fallback
- [ ] **HIGH** Price deviation check between updates
- [ ] **MEDIUM** L2 sequencer uptime feed checked
- [ ] **MEDIUM** Asset prices >= 0 (negative price edge case)

## 8. Governance and Risk Parameters
- [ ] **HIGH** Timelock on risk parameter changes
- [ ] **HIGH** Maximum collateral factor bounded
- [ ] **HIGH** Reserve factor cannot be set to 100% (protocol takes all interest)
- [ ] **MEDIUM** Asset listing process secure (malicious token can't drain)
- [ ] **MEDIUM** Borrowing/supplying can be paused per asset
- [ ] **LOW** Guardian role for emergency actions

## 9. Token Compatibility
- [ ] **HIGH** Non-standard ERC-20 tokens handled (USDT, BNB)
- [ ] **HIGH** Rebasing tokens: share-based accounting or explicit exclusion
- [ ] **HIGH** Low-decimal tokens: precision loss in interest calculation
- [ ] **HIGH** Tokens with transfer hooks (ERC-777): reentrancy
- [ ] **MEDIUM** Tokens with blacklists: position can't be liquidated if blacklisted
- [ ] **MEDIUM** Token upgrade: what if underlying token changes behavior?
