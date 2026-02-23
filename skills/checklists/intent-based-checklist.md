# Intent-Based & Solver Protocol Audit Checklist

## 1. Intent Specification
- [ ] **CRITICAL** Intent struct fully specifies trade parameters — no ambiguous or missing fields
- [ ] **CRITICAL** Intent cannot be modified after user signature (immutable once signed)
- [ ] **CRITICAL** Intent expiry enforced — cannot be filled after deadline
- [ ] **HIGH** Intent nonce prevents replay of previously filled or cancelled intents
- [ ] **HIGH** Partial fill: fill amount bounded by minimum output and user specification
- [ ] **HIGH** Intent type clearly distinguishes swap, bridge, limit order, auction
- [ ] **MEDIUM** Token approval: intent specifies exact token and amount (no over-approval drain)
- [ ] **MEDIUM** Intent metadata (chain ID, verifying contract) prevents cross-chain replay

## 2. Solver/Filler Security
- [ ] **CRITICAL** Solver cannot provide output worse than user's minimum (slippage protection)
- [ ] **CRITICAL** Solver cannot extract more input tokens than intent specifies
- [ ] **CRITICAL** Solver collateral/bond at risk if fill is invalid or reverts
- [ ] **HIGH** Solver competition: multiple solvers can compete — no monopoly by design
- [ ] **HIGH** Solver cannot front-run their own fill with a sandwich attack
- [ ] **HIGH** Solver registration requires bond/stake — spam solver prevention
- [ ] **MEDIUM** Solver timeout: unaccepted intents released back to open competition
- [ ] **MEDIUM** Solver reputation: repeated failed fills lead to bond slashing or ban
- [ ] **LOW** Solver fee transparent in execution — user sees net output correctly

## 3. Settlement and Verification
- [ ] **CRITICAL** Settlement contract verifies solver provided correct output token and amount
- [ ] **CRITICAL** Settlement atomic — solver deposits output before receiving input (no trust)
- [ ] **CRITICAL** Settlement cannot be reentered to drain funds
- [ ] **HIGH** Cross-chain settlement: proof of fill on destination chain verified on source
- [ ] **HIGH** Settlement reverts if oracle price deviates beyond acceptable range at fill time
- [ ] **HIGH** Post-fill hook (if any) cannot be manipulated by solver
- [ ] **MEDIUM** Settlement gas limit bounded — solver cannot cause out-of-gas failure
- [ ] **MEDIUM** Fill proof submitted within challenge window

## 4. Auction Mechanisms
- [ ] **CRITICAL** Dutch auction: price decay function correct and bounded (floor price)
- [ ] **CRITICAL** Batch auction: uniform clearing price computed fairly
- [ ] **HIGH** Auction start price not manipulable by observing mempool
- [ ] **HIGH** Auction timing: decay rate reasonable — not too fast (MEV) or too slow (stale)
- [ ] **HIGH** Priority auction: ordering criteria transparent (fee, time, or combination)
- [ ] **MEDIUM** Auction extension if no fill — fall back to AMM or RFQ
- [ ] **MEDIUM** MEV protection: auction uses private mempool, commit-reveal, or threshold encryption

## 5. Signature and Authorization
- [ ] **CRITICAL** EIP-712 typed data includes domain separator with chain ID and contract address
- [ ] **CRITICAL** Signature recovery: ecrecover result validated (not zero address, not malleable)
- [ ] **CRITICAL** Permit2 or allowance: approved amount cannot exceed intent specification
- [ ] **HIGH** Smart contract wallets (ERC-1271): isValidSignature checked correctly
- [ ] **HIGH** Signature cannot be reused after intent cancellation
- [ ] **HIGH** Off-chain intent relay: transport layer cannot modify intent before on-chain submission
- [ ] **MEDIUM** Gasless intents: relayer cannot substitute different intent for user's signature
- [ ] **MEDIUM** Multi-sig intents: threshold signatures handled correctly

## 6. Cross-Chain Intents
- [ ] **CRITICAL** Source chain locks user funds only after destination fill is proven
- [ ] **CRITICAL** Destination fill proof cannot be forged — uses bridge or oracle attestation
- [ ] **HIGH** Timeout: if destination fill doesn't happen, user can reclaim source funds
- [ ] **HIGH** Chain ID mismatch: intent for chain A cannot be filled on chain B
- [ ] **HIGH** Finality risk: destination fill must wait for source chain finality
- [ ] **MEDIUM** Solver fronts capital on destination — reimbursement on source is guaranteed
- [ ] **MEDIUM** Multi-hop intents (A → B → C): intermediate fills validated end-to-end
- [ ] **LOW** Cross-chain message relay fee covered by solver or user transparently

## 7. Order Flow and MEV
- [ ] **CRITICAL** User's worst-case execution at least as good as on-chain AMM benchmark
- [ ] **CRITICAL** Exclusive order flow: monopoly solver windows bounded and transparent
- [ ] **HIGH** Solver surplus sharing: improvement over minimum goes to user, not solver
- [ ] **HIGH** Private order flow: intent not broadcast to public mempool before fill
- [ ] **HIGH** Backrunning allowed but sandwiching blocked by design
- [ ] **MEDIUM** Solver routing: can access off-chain liquidity (CEX, RFQ) but verified on-chain
- [ ] **MEDIUM** Order flow auction revenue distributed transparently
- [ ] **LOW** User can opt out of exclusive solver and use open competition

## 8. Cancellation and Expiry
- [ ] **CRITICAL** User can cancel unfilled intent on-chain (nonce invalidation)
- [ ] **CRITICAL** Cancelled intent cannot be filled by solver after cancellation tx confirms
- [ ] **HIGH** Off-chain cancellation propagates to all relayers reliably
- [ ] **HIGH** Expired intents automatically become unfillable — no manual action required
- [ ] **MEDIUM** Batch cancellation supported — cancel all intents below a nonce
- [ ] **MEDIUM** Cancellation race: if cancel and fill in same block, cancel takes priority
- [ ] **LOW** Cancellation gas cost reasonable — not prohibitive for retail users

## 9. Protocol Safety
- [ ] **CRITICAL** Settlement contract holds no user funds between transactions (stateless)
- [ ] **HIGH** Emergency pause: halt new intents while allowing pending settlements to complete
- [ ] **HIGH** Contract upgrade path with timelock — cannot change settlement logic instantly
- [ ] **HIGH** Solver bond pool: cannot be drained by malicious solver registration/exit
- [ ] **MEDIUM** Rate limiting: maximum intents per block per user to prevent spam
- [ ] **MEDIUM** Monitoring: fill rate, solver performance, and surplus tracked on-chain
- [ ] **LOW** Protocol fee on fills bounded, transparent, and governable
