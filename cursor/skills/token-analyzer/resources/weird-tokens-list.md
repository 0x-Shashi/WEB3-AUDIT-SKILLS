# Weird ERC20 Tokens Reference

Comprehensive list of non-standard ERC20 behaviors that break protocol assumptions.

## Category 1: Missing Return Values
Tokens that don't return `bool` from `transfer`/`transferFrom`/`approve`.
- **USDT** (Tether) — Most impactful. Doesn't return bool.
- **BNB** (on Ethereum) — No return value
- **OMG** — No return value

**Impact**: `IERC20(token).transfer()` reverts because ABI decoder expects bool.
**Fix**: Use OpenZeppelin `SafeERC20.safeTransfer()`

## Category 2: Fee-on-Transfer
Tokens that deduct a fee during transfer, so recipient receives less than sent.
- **STA** (Statera) — 1% burn on transfer
- **PAXG** — 0.02% fee
- **USDT** — Has fee mechanism (currently 0, but can be activated)
- **SHIB variants** — Many have transfer taxes

**Impact**: Protocol accounting desync. Pool tracks 100 tokens but only has 99.
**Fix**: Measure `balanceOf` before/after transfer

## Category 3: Rebasing Tokens
Tokens where balances change without transfers.
- **stETH** (Lido) — Daily rebase based on staking rewards
- **AMPL** (Ampleforth) — Supply adjusts to target price
- **OHM** (Olympus) — Rebase rewards to stakers
- **AAVE aTokens** — Balance increases with lending interest

**Impact**: Stored balances become incorrect. Invariants break.
**Fix**: Use shares-based accounting, or wrap to non-rebasing (wstETH)

## Category 4: Tokens with Blacklists
Tokens that can freeze/blacklist addresses from transferring.
- **USDC** — Centre consortium blacklist
- **USDT** — Tether blacklist
- **BUSD** — Paxos blacklist
- **TUSD** — TrustToken blacklist

**Impact**: Blacklisted addresses can't withdraw. Funds permanently stuck if protocol address blacklisted.
**Fix**: Consider rescue mechanisms, don't hold user funds in single pool

## Category 5: Pausable Tokens
Tokens where all transfers can be paused by admin.
- **USDC** — Pausable
- **USDT** — Pausable
- **BNB** (ERC20) — Pausable

**Impact**: Protocol operations halt if underlying token is paused.
**Fix**: Handle transfer failures gracefully, don't assume transfers always succeed

## Category 6: Upgradeable Tokens
Token implementation can change.
- **USDC** — Proxy upgradeable
- **USDT** — Proxy upgradeable
- **TUSD** — Proxy upgradeable

**Impact**: Token behavior can change post-deployment. Current audit may become invalid.
**Fix**: Document upgrade risk, monitor token proxy changes

## Category 7: Multiple Entry Points
Tokens with more than one address pointing to same balances.
- **TUSD** (legacy) — Had dual entry points

**Impact**: Double-counting deposits via different addresses.
**Fix**: Token whitelist, deduplicate by checking underlying

## Category 8: Tokens with Transfer Hooks
Tokens that call hooks on sender/receiver during transfers.
- **ERC777 tokens** — `tokensToSend` and `tokensReceived` hooks
- **ERC1155** — `onERC1155Received` callback
- **Some NFTs** — `onERC721Received`

**Impact**: Reentrancy via callback. Recipient can execute arbitrary code mid-transfer.
**Fix**: CEI pattern, `nonReentrant` modifier, be aware of callback existence

## Category 9: Low/High Decimal Tokens
Tokens with non-18 decimals.
- **USDC** — 6 decimals
- **USDT** — 6 decimals
- **WBTC** — 8 decimals
- **GUSD** — 2 decimals
- **YAMv2** — 24 decimals

**Impact**: Precision loss in calculations, overflow in multiplications.
**Fix**: Normalize to common precision, use appropriate scaling factors

## Category 10: Tokens Reverting on Zero Transfer
- **LEND** — Reverts on 0 amount transfer
- **Some custom tokens** — Revert on 0

**Impact**: Batch operations fail if any amount is 0.
**Fix**: Check amount > 0 before transfer

## Category 11: Tokens with Max Balance/Transfer Limits
- **SafeMoon forks** — Max transaction amount, max wallet size
- **Reflection tokens** — Redistribute percentage of transfers

**Impact**: Large protocol operations may fail or trigger unexpected redistribution.
**Fix**: Test with actual token, verify limits don't affect protocol operations

## Quick Reference: What to Check

```
For EVERY external token integration, verify:
1. Does it return bool from transfer/approve?
2. Does it charge fees on transfer?
3. Does it rebase?
4. Can it blacklist addresses?
5. Can it pause?
6. Is it upgradeable?
7. What are the decimals?
8. Does it have transfer callbacks?
9. Does it allow zero transfers?
10. Does it have transfer limits?
```

## Reference
- [d-xo/weird-erc20](https://github.com/d-xo/weird-erc20) — Comprehensive weird token repo
- [Trail of Bits Token Integration Checklist](https://github.com/crytic/building-secure-contracts/blob/master/development-guidelines/token_integration.md)
