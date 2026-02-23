# Vault & Yield Aggregator Audit Checklist

## 1. Share Accounting (ERC-4626)
- [ ] **CRITICAL** Share price: totalAssets / totalSupply calculated using correct underlying balance
- [ ] **CRITICAL** First depositor attack mitigated (virtual shares, minimum deposit, or dead shares)
- [ ] **CRITICAL** Donation attack: direct asset transfer does not inflate share price unfairly
- [ ] **HIGH** Deposit: shares minted = deposit amount × totalSupply / totalAssets (rounding down)
- [ ] **HIGH** Withdraw: assets returned = shares burned × totalAssets / totalSupply (rounding down)
- [ ] **HIGH** Rounding direction: always favors vault (round down on mint, round up on burn)
- [ ] **MEDIUM** convertToShares and convertToAssets functions match actual deposit/withdraw logic
- [ ] **MEDIUM** maxDeposit, maxMint, maxWithdraw, maxRedeem return accurate caps
- [ ] **LOW** Preview functions (previewDeposit, previewMint, etc.) exact or conservative

## 2. Strategy Execution
- [ ] **CRITICAL** Strategy cannot withdraw more than vault authorized — bounded by allocated amount
- [ ] **CRITICAL** Strategy loss reported correctly — share price adjusts, no hidden bad debt
- [ ] **CRITICAL** Strategy cannot be reentered during deposit/withdraw flow
- [ ] **HIGH** Strategy harvest: yield compounded into vault assets atomically
- [ ] **HIGH** Strategy migration: old strategy fully recalled before new strategy funded
- [ ] **HIGH** Emergency strategy revocation: vault can pull all funds from strategy immediately
- [ ] **MEDIUM** Strategy allocation percentages sum to 100% or less (not overcommitted)
- [ ] **MEDIUM** Strategy queue priority: deposits flow to strategies in defined order
- [ ] **LOW** Strategy performance fee calculated on real gains since last harvest

## 3. Deposit and Withdrawal
- [ ] **CRITICAL** Deposit: user receives correct shares for deposited assets
- [ ] **CRITICAL** Withdrawal: vault has sufficient liquid assets or can recall from strategy
- [ ] **HIGH** Withdrawal queue: FIFO or proportional, not front-runnable
- [ ] **HIGH** Withdrawal lock/cooldown enforced — no immediate deposit + withdraw to harvest yield
- [ ] **HIGH** Deposit cap enforced — vault does not accept beyond strategy capacity
- [ ] **MEDIUM** Fee-on-transfer tokens: vault credits actual received, not requested amount
- [ ] **MEDIUM** Rebasing tokens: share-based accounting used, not balance-based
- [ ] **MEDIUM** Withdrawal rounding: user cannot extract 1 wei extra per transaction (rounding griefing)
- [ ] **LOW** Minimum deposit and minimum withdrawal enforced

## 4. Yield and Reward Handling
- [ ] **CRITICAL** Harvested yield correctly added to totalAssets before share price recalculation
- [ ] **CRITICAL** Reward tokens (CRV, COMP) swapped via manipulation-resistant path
- [ ] **HIGH** Harvest timing: MEV searchers cannot front-run harvest to extract value
- [ ] **HIGH** Reward swap slippage protection: minimum output enforced
- [ ] **HIGH** Multi-reward tokens: each handled independently, no cross-contamination
- [ ] **MEDIUM** Harvest frequency: yield dripped over time, not credited instantly (prevents JIT deposit)
- [ ] **MEDIUM** Negative yield (strategy loss): correctly reduces totalAssets and share price
- [ ] **LOW** Yield source diversification: not 100% dependent on single farm

## 5. Fee Structure
- [ ] **CRITICAL** Management fee: calculated on AUM, not inflating share price
- [ ] **CRITICAL** Performance fee: calculated on actual gains since high-water mark
- [ ] **HIGH** Fee minting: shares minted to fee recipient, diluting existing holders correctly
- [ ] **HIGH** Fee parameters bounded — cannot be set to 100% drainage
- [ ] **HIGH** Fee-on-withdraw: correctly deducted from redeem amount
- [ ] **MEDIUM** Fee changes timelocked — users can exit before new fees apply
- [ ] **MEDIUM** No double-fee: deposit fee + performance fee don't stack unfairly
- [ ] **LOW** Fee recipient address non-zero and changeable via governance

## 6. Access Control and Governance
- [ ] **CRITICAL** Strategy addition/removal restricted to governance with timelock
- [ ] **CRITICAL** Vault admin cannot rugpull by sending funds to arbitrary address
- [ ] **HIGH** Guardian/manager role: can pause, adjust allocation, but not withdraw to self
- [ ] **HIGH** Keeper/harvester role: can trigger harvest but not steal funds
- [ ] **HIGH** Upgradability: vault proxy upgrade timelocked with opt-out window
- [ ] **MEDIUM** Role separation: strategist ≠ guardian ≠ governance ≠ keeper
- [ ] **MEDIUM** Emergency shutdown: halts deposits, allows withdrawals at current share price
- [ ] **LOW** Governance multisig quorum documented and enforced

## 7. Integration Risks
- [ ] **CRITICAL** Strategy integrates with audited protocols only — no unverified contracts
- [ ] **CRITICAL** Protocol dependency: underlying protocol pause doesn't freeze vault funds
- [ ] **HIGH** Composability: vault token (ERC-4626) used as collateral elsewhere — circular risk
- [ ] **HIGH** Approval management: strategy approves only required amount to target protocol
- [ ] **HIGH** Liquidity pool: vault LP position impermanent loss managed or documented
- [ ] **MEDIUM** Oracle dependency: strategy relies on oracle — stale price handled
- [ ] **MEDIUM** External protocol upgrade: behavior change risk documented per strategy
- [ ] **LOW** Insurance coverage against underlying protocol exploits

## 8. MEV and Front-Running
- [ ] **HIGH** Vault deposit/withdraw: share price cannot be sandwiched
- [ ] **HIGH** Harvest: reward swap cannot be front-run for worse execution
- [ ] **HIGH** Strategy rebalance: large trades not predictable by MEV searchers
- [ ] **MEDIUM** Private harvest: keeper uses Flashbots or private mempool
- [ ] **MEDIUM** JIT liquidity: deposit before harvest + withdraw after prevented by cooldown
- [ ] **LOW** Vault share price update frequency: if lagging, creates arbitrage window

## 9. Token Compatibility
- [ ] **HIGH** Underlying asset: supports standard ERC-20 (approve/transfer/balanceOf)
- [ ] **HIGH** Underlying with hooks (ERC-777): reentrancy mitigated in deposit/withdraw
- [ ] **HIGH** Low-decimal tokens (USDC/USDT with 6 decimals): precision loss in share accounting
- [ ] **MEDIUM** Token with blacklists: depositor/withdrawer not blocked from accessing funds
- [ ] **MEDIUM** Upgradeable underlying: vault handles token behavior change gracefully
- [ ] **LOW** Non-standard return values (USDT approve): SafeERC20 used consistently
