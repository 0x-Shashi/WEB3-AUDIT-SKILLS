# Comprehensive Smart Contract Audit Checklist

## 1. Access Control
- [ ] **CRITICAL** All admin/privileged functions have proper access control
- [ ] **CRITICAL** Owner/admin cannot rug pull (drain all funds)
- [ ] **HIGH** Role-based access implemented correctly (OpenZeppelin AccessControl)
- [ ] **HIGH** Two-step ownership transfer (not single-step)
- [ ] **MEDIUM** Default admin role properly assigned and protected
- [ ] **MEDIUM** Renounce ownership implications analyzed
- [ ] **LOW** Functions use correct visibility (public/external/internal/private)
- [ ] **LOW** Modifiers applied consistently

## 2. Reentrancy
- [ ] **CRITICAL** External calls follow Checks-Effects-Interactions (CEI)
- [ ] **CRITICAL** ReentrancyGuard on all state-changing external functions
- [ ] **HIGH** Cross-contract reentrancy considered (shared state)
- [ ] **HIGH** Read-only reentrancy: view functions return consistent state
- [ ] **HIGH** ERC777/ERC721/ERC1155 callback reentrancy handled
- [ ] **MEDIUM** Cross-function reentrancy (same contract, different functions)

## 3. Integer Math
- [ ] **HIGH** Solidity >= 0.8.0 used (built-in overflow checks)
- [ ] **HIGH** Unchecked blocks justified and safe
- [ ] **HIGH** Division before multiplication avoided (precision loss)
- [ ] **HIGH** Casting between types is safe (uint256 to uint128, etc.)
- [ ] **MEDIUM** Rounding direction is correct and intentional
- [ ] **MEDIUM** Zero denominators handled (division by zero)
- [ ] **LOW** Magic numbers documented

## 4. External Calls
- [ ] **CRITICAL** Return values of external calls checked
- [ ] **CRITICAL** Untrusted contracts not called with delegatecall
- [ ] **HIGH** Low-level calls (.call, .delegatecall) have proper error handling
- [ ] **HIGH** External contract address validated before interaction
- [ ] **MEDIUM** Gas stipend sufficient for target operations
- [ ] **MEDIUM** Fallback/receive functions handle unexpected ETH
- [ ] **LOW** Static calls used where mutations not needed

## 5. Token Handling
- [ ] **CRITICAL** ERC-20 approve race condition handled (use increaseAllowance)
- [ ] **CRITICAL** Fee-on-transfer tokens handled (compare before/after balance)
- [ ] **CRITICAL** Rebasing tokens handled (share-based accounting)
- [ ] **HIGH** Non-standard ERC-20 return values handled (USDT, BNB)
- [ ] **HIGH** Token decimals not assumed (not always 18)
- [ ] **HIGH** Low-decimal tokens (USDC/6, WBTC/8) precision handled
- [ ] **HIGH** Max approval (type(uint256).max) implications understood
- [ ] **MEDIUM** Token blacklist/pausable functionality considered
- [ ] **MEDIUM** Multiple token paths tested (ETH vs WETH vs ERC-20)
- [ ] **LOW** SafeERC20 used for token transfers

## 6. Oracle and Price Feeds
- [ ] **CRITICAL** Oracle manipulation: spot price not used as oracle
- [ ] **CRITICAL** Stale price check (Chainlink heartbeat/threshold)
- [ ] **HIGH** Oracle decimals handled correctly
- [ ] **HIGH** Multi-oracle setup with fallback
- [ ] **HIGH** TWAP period sufficient (minimum 30 minutes)
- [ ] **MEDIUM** Sequencer uptime feed checked (L2 deployments)
- [ ] **MEDIUM** Oracle return data fully validated (roundId, answeredInRound)
- [ ] **LOW** Oracle update frequency matches protocol needs

## 7. Flash Loan Resistance
- [ ] **HIGH** Key operations atomic-resistant (can't manipulate in one tx)
- [ ] **HIGH** TWAP used instead of spot prices
- [ ] **HIGH** Governance voting snapshots used (not live balances)
- [ ] **MEDIUM** Token balance checks at start and end of critical operations
- [ ] **MEDIUM** Minimum lock/delay periods for large operations

## 8. Upgradability
- [ ] **CRITICAL** Storage layout compatible between versions
- [ ] **CRITICAL** Initializer can only be called once
- [ ] **HIGH** Implementation contract has no selfdestruct
- [ ] **HIGH** Proxy admin is separate from protocol admin
- [ ] **HIGH** No storage collisions between proxy and implementation
- [ ] **MEDIUM** Upgrade timelock/multisig required
- [ ] **MEDIUM** Upgrade path tested end-to-end
- [ ] **LOW** UUPS vs Transparent proxy choice appropriate

## 9. Denial of Service
- [ ] **HIGH** No unbounded loops over user-controlled arrays
- [ ] **HIGH** Pull over push pattern for payments
- [ ] **HIGH** External call failures don't block protocol
- [ ] **MEDIUM** Block gas limit considered for batch operations
- [ ] **MEDIUM** Storage growth bounded
- [ ] **LOW** Griefing attacks via dust amounts considered

## 10. MEV and Front-Running
- [ ] **HIGH** Commit-reveal for sensitive operations
- [ ] **HIGH** Slippage protection user-configurable
- [ ] **HIGH** Deadline parameters on swaps
- [ ] **MEDIUM** Private mempool usage documented
- [ ] **MEDIUM** Auction/batch mechanisms for large operations

## 11. Signature and Cryptography
- [ ] **CRITICAL** EIP-712 domain separator includes chainId
- [ ] **CRITICAL** Replay protection (nonce or unique identifier)
- [ ] **HIGH** Signature malleability prevented (use OpenZeppelin ECDSA)
- [ ] **HIGH** ecrecover return value checked (address(0))
- [ ] **MEDIUM** Permit (EIP-2612) deadline not set to max
- [ ] **MEDIUM** Signature used/invalidated after use

## 12. Gas and Optimization
- [ ] **MEDIUM** Storage reads minimized (cache in memory)
- [ ] **MEDIUM** Events emitted for all important state changes
- [ ] **LOW** Immutable and constant used where appropriate
- [ ] **LOW** Struct packing optimized for storage slots
- [ ] **INFO** Custom errors used instead of require strings

## 13. Protocol-Specific
- [ ] **CRITICAL** Invariants documented and maintained
- [ ] **HIGH** Edge cases: zero amounts, max amounts, single wei
- [ ] **HIGH** First depositor attack mitigated (vault tokens)
- [ ] **HIGH** Donation attack resistance
- [ ] **MEDIUM** Emergency shutdown/pause mechanism exists
- [ ] **MEDIUM** Time-dependent logic handles edge cases
- [ ] **LOW** NatSpec documentation complete and accurate
