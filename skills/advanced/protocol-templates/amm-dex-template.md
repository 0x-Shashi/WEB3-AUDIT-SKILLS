# AMM / DEX Audit Template

## Protocol Overview
Automated Market Makers and Decentralized Exchanges provide token swapping and liquidity provision without order books, using mathematical pricing curves.

## Architecture Checklist
- [ ] Pricing curve implementation correct (x*y=k, StableSwap, concentrated)
- [ ] Factory-pool pattern secure (pool creation, initialization)
- [ ] Router/periphery properly validates pool interactions
- [ ] Fee collection and distribution correct
- [ ] Multi-hop routing secure

## Critical Invariants
```
1. Pool Solvency: reserve0 * reserve1 >= k (after fees)
2. LP Value: totalLPTokens * pricePerLP = totalPoolValue
3. Swap Output: output <= reserve (can't drain pool in one swap)
4. Fee Accuracy: feeCollected = swapAmount * feeRate
5. No Tokens Lost: sum(deposits) - sum(withdrawals) = pool balance
```

## Attack Vectors

### Price Manipulation
- [ ] Read-only reentrancy on price calculation
- [ ] Flash loan price manipulation via reserves
- [ ] Sandwich attack profitability (front-run user swaps)
- [ ] TWAP manipulation window (if TWAP oracle exposed)

### Liquidity Provider Attacks
- [ ] First depositor inflation attack (donation + rounding)
- [ ] JIT (Just-In-Time) liquidity sandwich
- [ ] Imbalanced liquidity withdrawal exploit
- [ ] LP token price manipulation for external protocols

### Swap Security
- [ ] Slippage protection enforced (minAmountOut)
- [ ] Deadline parameter checked
- [ ] Token pair ordering assumptions
- [ ] Reentrancy during swap callbacks

### Fee Exploits
- [ ] Fee-on-transfer tokens handled correctly
- [ ] Protocol fee extraction doesn't break invariant
- [ ] Fee change admin functions protected
- [ ] Dynamic fee manipulation

## Critical Functions to Review Deep
| Function | Risk | Check |
|----------|------|-------|
| `swap()` | Price manipulation, reentrancy | CEI, slippage, callback safety |
| `addLiquidity()` | Inflation attack, rounding | First deposit protection |
| `removeLiquidity()` | Imbalanced withdrawal | Proportional check |
| `getAmountOut()` | Math errors | Precision, overflow |
| `flash()` | Reentrancy, fee bypass | Callback validation, fee enforce |

## Integration Risks
- External tokens: fee-on-transfer, rebasing, hooks
- Oracle consumers: Who reads this pool's price?
- Flash loan providers: Can flash swaps be abused?
- Router: Multi-hop path validation

## Economic Considerations
- Impermanent loss exposure for LPs
- MEV extraction (sandwich, arbitrage)
- Liquidity fragmentation (concentrated liquidity)
- Fee competitiveness vs manipulation resistance
