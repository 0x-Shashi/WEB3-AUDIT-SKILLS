# Lending Protocol Audit Template

## Protocol Overview
Lending protocols allow users to supply assets to earn interest and borrow assets against collateral, with liquidation mechanisms to maintain solvency.

## Architecture Checklist
- [ ] Interest rate model implementation correct
- [ ] Collateral factor / LTV configuration safe
- [ ] Liquidation mechanism functions correctly
- [ ] Oracle integration validated
- [ ] Reserve management and accounting
- [ ] Flash loan integration (if applicable)
- [ ] Multi-asset isolation or shared pool design

## Critical Invariants
```
1. Solvency: totalBorrows <= totalDeposits (globally)
2. Collateralization: each position's collateral * CF >= borrows
3. Interest Accrual: rates compound correctly over time
4. Share Pricing: exchangeRate monotonically non-decreasing (absent bad debt)
5. Conservation: no tokens created or destroyed in accounting
```

## Attack Vectors

### Oracle Manipulation
- [ ] Price source manipulable (AMM spot price)?
- [ ] Chainlink staleness check present?
- [ ] Fallback oracle configured?
- [ ] Price used for both deposit AND withdrawal valuation?
- [ ] LP token pricing uses fair pricing formula?

### Liquidation
- [ ] Liquidation threshold allows timely liquidation
- [ ] Liquidation bonus doesn't exceed remaining collateral
- [ ] Self-liquidation prevented (or harmless)
- [ ] Close factor reasonable (not 100% — prevents bad debt spiral)
- [ ] Dust positions handled (too small to liquidate profitably)
- [ ] Multiple assets as collateral — partial liquidation correct?

### Interest Rate
- [ ] Utilization calculation overflow-safe
- [ ] Interest compounds correctly (per-block or per-second)
- [ ] Rate model has reasonable bounds (no astronomical rates)
- [ ] Reserve factor deducted correctly
- [ ] First depositor exploit (share inflation)?

### Flash Loan
- [ ] Fee collected correctly
- [ ] Reentrancy during flash loan callback
- [ ] Flash loan can circumvent interest accrual?
- [ ] Flash loan used to manipulate interest rates?

### Collateral/Borrow Management
- [ ] Deposit and withdrawal update exchange rate correctly
- [ ] Borrow and repay update borrow index correctly
- [ ] Health factor checked AFTER every state change
- [ ] Cannot withdraw collateral below minimum health factor
- [ ] Cannot borrow if already undercollateralized

### Token Risks
- [ ] Fee-on-transfer tokens handled (Compound V2 famous bug)
- [ ] Rebasing tokens (stETH) handled or excluded
- [ ] Token blacklist doesn't brick protocol
- [ ] ERC777 reentrancy via token hooks

## Critical Functions to Review Deep
| Function | Risk | Check |
|----------|------|-------|
| `borrow()` | Under-collateralization | Health check, oracle call |
| `liquidate()` | Incorrect seizure | Math, bonus calc, access |
| `accrueInterest()` | Accounting error | Rate math, overflow |
| `getPrice()` / oracle | Manipulation | Staleness, source |
| `withdraw()` | Drain reserves | Health check, reentrancy |

## Integration Risks
- Oracle dependency (single point of failure)
- Token compatibility (see token-analyzer)
- Governance parameter changes (collateral factors, liquidation incentives)
- Composability risk (receipt tokens used as collateral elsewhere)

## Economic Considerations
- Bad debt socialization mechanism
- Liquidation incentive adequacy (gas costs vs bonus)
- Interest rate model efficiency (optimal utilization)
- Capital efficiency vs safety margin tradeoff
