# DEX / AMM Audit Checklist

## 1. Liquidity Pool Security
- [ ] **CRITICAL** Pool reserves cannot be manipulated to drain liquidity
- [ ] **CRITICAL** Constant product formula (x*y=k) or equivalent maintained
- [ ] **CRITICAL** LP token minting proportional to added liquidity
- [ ] **HIGH** First LP provider attack: initial liquidity can inflate share price
- [ ] **HIGH** Minimum liquidity burned on first deposit (Uniswap V2 pattern)
- [ ] **HIGH** LP token burning returns correct proportional share
- [ ] **MEDIUM** Imbalanced liquidity addition handled correctly
- [ ] **MEDIUM** Single-sided liquidity: proper price impact applied
- [ ] **LOW** Pool creation: initial price determined by first depositor

## 2. Swap Security
- [ ] **CRITICAL** Swap output correctly calculated per pricing formula
- [ ] **CRITICAL** Rounding direction favors the protocol (not the user)
- [ ] **HIGH** Slippage protection: amountOutMin enforced
- [ ] **HIGH** Deadline parameter prevents stale transactions
- [ ] **HIGH** Fee calculation: correct percentage taken
- [ ] **HIGH** Fee-on-transfer tokens: actual received amount used
- [ ] **MEDIUM** Multi-hop swaps: intermediate amounts correct
- [ ] **MEDIUM** ETH/WETH: wrapping/unwrapping handled correctly
- [ ] **LOW** Swap events emitted with correct amounts

## 3. Price Oracle (TWAP)
- [ ] **CRITICAL** TWAP not manipulable within single block
- [ ] **CRITICAL** TWAP observation window sufficient (30min+)
- [ ] **HIGH** Cumulative price overflow handled correctly
- [ ] **HIGH** Oracle observations stored with sufficient granularity
- [ ] **MEDIUM** First observation period: TWAP not reliable until sufficient data
- [ ] **MEDIUM** Low-liquidity pool TWAP still manipulable (need liquidity threshold)

## 4. Concentrated Liquidity (V3-style)
- [ ] **CRITICAL** Tick math: price calculation at tick boundaries correct
- [ ] **HIGH** Position NFT: ownership correctly tracked
- [ ] **HIGH** Fee accumulation per tick range: correct accounting
- [ ] **HIGH** Crossing ticks: liquidity added/removed correctly at boundaries
- [ ] **MEDIUM** Tick spacing: correct for fee tier
- [ ] **MEDIUM** Position merging/splitting: no value creation/destruction
- [ ] **LOW** Out-of-range positions: fees not accumulating (expected)

## 5. MEV and Front-Running
- [ ] **HIGH** Sandwich attack: user slippage can protect against front-running
- [ ] **HIGH** JIT (Just-In-Time) liquidity: brief liquidity provision and removal
- [ ] **HIGH** Multi-block MEV: sequential manipulation considered
- [ ] **MEDIUM** Router contract: doesn't hold user funds between operations
- [ ] **MEDIUM** Large swaps: private mempool recommendation documented
- [ ] **LOW** Price impact limits per transaction

## 6. Flash Swaps / Flash Loans
- [ ] **CRITICAL** Flash swap: full repayment enforced within same transaction
- [ ] **CRITICAL** Flash swap callback: reentrancy protection
- [ ] **HIGH** Flash swap fee correctly applied
- [ ] **HIGH** Pool state consistent after flash swap completes
- [ ] **MEDIUM** Flash swap can't be used to manipulate pool reserves permanently

## 7. Routing
- [ ] **HIGH** Multi-hop routing: intermediate pools valid
- [ ] **HIGH** Path validation: no circular routes that extract value
- [ ] **MEDIUM** Optimal route calculation: protocol doesn't guarantee best price
- [ ] **MEDIUM** Router approval: doesn't retain excess approvals
- [ ] **LOW** Failed intermediate swap: entire route reverts correctly

## 8. Fee Structure
- [ ] **HIGH** Protocol fee: correctly split between LPs and protocol treasury
- [ ] **HIGH** Fee tiers: correct fee applied per pool
- [ ] **MEDIUM** Dynamic fees: calculation is manipulation-resistant
- [ ] **MEDIUM** Fee withdrawal: only authorized parties can claim protocol fees
- [ ] **LOW** Fee accumulation: no value loss over time from rounding

## 9. Token Compatibility
- [ ] **CRITICAL** Non-standard ERC-20 tokens: USDT (no return value), BNB
- [ ] **HIGH** Rebasing tokens: pool reserves desync from actual balance
- [ ] **HIGH** Fee-on-transfer tokens: received amount != sent amount
- [ ] **HIGH** Low-decimal tokens (USDC/6): precision loss in calculations
- [ ] **MEDIUM** ERC-777 tokens: reentrancy via transfer hooks
- [ ] **MEDIUM** Tokens with blacklists: can't swap or remove liquidity
- [ ] **LOW** Pausable tokens: pool frozen if token is paused
