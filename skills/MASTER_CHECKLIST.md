# Smart Contract Security Master Checklist

_Based on 50,530 real audit findings from Code4rena, Sherlock, Cyfrin, and 20+ audit platforms_

---

## How to Use This Checklist

1. **Start with CRITICAL PRIORITY** — These 20 types represent the most frequent real-world vulnerabilities
2. **Check every box** — Mark each item as you audit
3. **Follow pattern links** — Each section links to the detailed pattern file with code examples
4. **Cross-reference attack trees** — Use [XREF.md](XREF.md) to find related exploits and fixes

---

## CRITICAL PRIORITY (Top 20 Most Common)

### 1. Business Logic (234 occurrences - 0.46%)

- [ ] Trace every state transition — can any sequence of valid calls reach an invalid state?
- [ ] Check if economic incentives can be gamed (deposit/withdraw cycles, fee avoidance, reward manipulation)
- [ ] Verify all assumptions about external protocol behavior (token balances, oracle prices, pool states)
- [ ] Test boundary conditions: zero amounts, max uint256, empty arrays, self-referencing addresses
- [ ] Confirm that user-facing functions cannot be called in unexpected order to bypass intended flows

**Pattern Reference**: [patterns/business-logic-patterns.md](patterns/business-logic-patterns.md)

---

### 2. Validation (127 occurrences - 0.25%)

- [ ] Check all function parameters for missing zero-address validation (`address(0)`)
- [ ] Verify all array length inputs match when multiple arrays are passed together
- [ ] Confirm numeric inputs are bounded (min/max/cap checks) — especially amounts, percentages, rates
- [ ] Check that `msg.value` is validated in payable functions (not excess, not zero when required)
- [ ] Verify enum and mapping key inputs don't accept out-of-range or non-existent values

**Pattern Reference**: [patterns/validation-patterns.md](patterns/validation-patterns.md)

---

### 3. Wrong Math (107 occurrences - 0.21%)

- [ ] Check for division before multiplication — reorder to `(a * b) / c` not `(a / c) * b`
- [ ] Verify consistent use of scaling factors (WAD `1e18`, RAY `1e27`) — no mixing
- [ ] Check all percentage calculations — `amount * percentage / 100` vs `amount * percentage / 10000`
- [ ] Look for implicit zero results: `smallNumber / largeNumber == 0` losing precision
- [ ] Verify `unchecked {}` blocks have provably safe arithmetic (no user-controlled values)

**Pattern Reference**: [patterns/wrong-math-patterns.md](patterns/wrong-math-patterns.md)

---

### 4. Front-Running (106 occurrences - 0.21%)

- [ ] Check all swap/trade functions for `deadline` parameter — reject expired transactions
- [ ] Verify `minAmountOut` / `maxAmountIn` slippage protection is present and not hardcoded to 0
- [ ] Look for commit-reveal patterns on sensitive operations (auctions, votes, name registrations)
- [ ] Check if `permit()` calls can be front-run to cause the main transaction to revert
- [ ] Verify oracle updates cannot be sandwiched to manipulate pricing within a block

**Pattern Reference**: [patterns/front-running-patterns.md](patterns/front-running-patterns.md)

---

### 5. Fee On Transfer (66 occurrences - 0.13%)

- [ ] Check if token transfers use `balanceBefore` / `balanceAfter` to measure actual received amount
- [ ] Verify the protocol doesn't assume `transferFrom(from, to, amount)` delivers exactly `amount`
- [ ] Look for hardcoded token lists — does the protocol handle arbitrary ERC20s including deflationary tokens?
- [ ] Check withdraw/redeem functions — does accounting assume `transfer(to, amount)` sends exactly `amount`?
- [ ] Verify fees aren't double-counted in deposit/withdraw round trips

**Pattern Reference**: [patterns/fee-on-transfer-patterns.md](patterns/fee-on-transfer-patterns.md)

---

### 6. DOS (66 occurrences - 0.13%)

- [ ] Find all loops iterating over user-controlled or unbounded arrays — can gas exceed block limit?
- [ ] Check if any external call failure (revert) can block the entire function (batch operations, payouts)
- [ ] Verify `push`-based payment patterns — can a failing recipient block all other recipients?
- [ ] Look for self-destruct or force-sent ETH breaking `address(this).balance` assumptions
- [ ] Check if delisting/removing/pausing can permanently lock user funds

**Pattern Reference**: [patterns/dos-patterns.md](patterns/dos-patterns.md)

---

### 7. Oracle (59 occurrences - 0.12%)

- [ ] Verify Chainlink `latestRoundData()` checks: `price > 0`, `updatedAt` not stale, `answeredInRound >= roundId`
- [ ] Confirm the oracle price is NOT a spot/reserve-based price manipulable in a single transaction
- [ ] Check for L2 sequencer uptime feed — prices may be stale during sequencer downtime
- [ ] Verify fallback oracle exists if the primary oracle reverts or returns zero
- [ ] Check decimal handling — Chainlink returns 8 decimals for USD feeds, 18 for ETH feeds

**Pattern Reference**: [patterns/oracle-patterns.md](patterns/oracle-patterns.md) | Anti-Pattern: [anti-patterns/oracle-anti-patterns.md](anti-patterns/oracle-anti-patterns.md)

---

### 8. Reentrancy (59 occurrences - 0.12%)

- [ ] Check all external calls (`.call`, `.transfer`, `.send`, `safeTransfer`, `safeTransferFrom`) — is state updated BEFORE the call? (CEI pattern)
- [ ] Verify `nonReentrant` modifier is present on all functions that transfer value or modify shared state
- [ ] Look for cross-function reentrancy — can function A's external call re-enter function B that shares state?
- [ ] Check for read-only reentrancy — do view functions used by other protocols read stale state during callbacks?
- [ ] Verify ERC721 `safeTransferFrom`, ERC1155 callbacks, and ERC777 hooks can't reenter

**Pattern Reference**: [patterns/reentrancy-patterns.md](patterns/reentrancy-patterns.md) | Anti-Pattern: [anti-patterns/reentrancy-anti-patterns.md](anti-patterns/reentrancy-anti-patterns.md)

---

### 9. Access Control (48 occurrences - 0.09%)

- [ ] Verify every admin/privileged function has an access modifier (`onlyOwner`, `onlyRole`, etc.)
- [ ] Check `initialize()` functions — are they protected from being called by anyone? Is `_disableInitializers()` in the constructor?
- [ ] Confirm no function uses `tx.origin` for authentication (phishable via contract calls)
- [ ] Verify ownership transfer uses a two-step pattern (propose + accept) not single-step
- [ ] Check that `selfdestruct` / critical functions are not callable by unauthorized addresses

**Pattern Reference**: [patterns/access-control-patterns.md](patterns/access-control-patterns.md) | Anti-Pattern: [anti-patterns/access-control-anti-patterns.md](anti-patterns/access-control-anti-patterns.md)

---

### 10. State Update Issues (47 occurrences - 0.09%)

- [ ] Verify all state variables are updated BEFORE external calls (Checks-Effects-Interactions)
- [ ] Check that reward/interest accumulators are updated before any deposit/withdraw/transfer
- [ ] Look for missing state updates on error paths — does a `revert` leave partial state changes?
- [ ] Verify `delete` operations actually clear all relevant mappings and arrays (not just the primary key)
- [ ] Check that state transitions in multi-step processes can't be skipped or replayed

**Pattern Reference**: [patterns/don-t-update-state-patterns.md](patterns/don-t-update-state-patterns.md)

---

### 11. Decimals (45 occurrences - 0.09%)

- [ ] Check all cross-token math normalizes decimals (USDC=6, WBTC=8, DAI=18 treated identically?)
- [ ] Verify `decimals()` is not assumed to return 18 — query it dynamically
- [ ] Look for hardcoded `1e18` or `10**18` used with tokens that have different decimals
- [ ] Check share/asset conversion math handles tokens with decimals < 8 without fatal precision loss
- [ ] Verify price feed decimal normalization matches the token's actual decimals

**Pattern Reference**: [patterns/decimals-patterns.md](patterns/decimals-patterns.md)

---

### 12. Overflow/Underflow (43 occurrences - 0.09%)

- [ ] If Solidity < 0.8.0: verify SafeMath is used on ALL arithmetic operations
- [ ] Audit every `unchecked {}` block — prove that overflow/underflow is mathematically impossible
- [ ] Check all type-casting narrowing conversions: `uint256` → `uint128/96/64/32` can silently truncate
- [ ] Verify `type(uint256).max` inputs don't cause unexpected behavior in calculations
- [ ] Look for underflow in subtraction: `a - b` where `b` could exceed `a` (balances, timestamps, counters)

**Pattern Reference**: [patterns/overflow-underflow-patterns.md](patterns/overflow-underflow-patterns.md)

---

### 13. Liquidation (42 occurrences - 0.08%)

- [ ] Check if users can self-liquidate to earn the liquidation bonus on their own position
- [ ] Verify interest is accrued BEFORE checking health factor for liquidation
- [ ] Look for liquidation DoS — can a user's position become un-liquidatable (reverting collateral tokens, dust amounts)?
- [ ] Check if flash loans can be used to manipulate price → liquidate → profit in one transaction
- [ ] Verify partial liquidation doesn't allow looping to extract more bonus than intended

**Pattern Reference**: [patterns/liquidation-patterns.md](patterns/liquidation-patterns.md) | Attack Tree: [attack-trees/lending-attack-tree.md#B](attack-trees/lending-attack-tree.md)

---

### 14. Slippage (36 occurrences - 0.07%)

- [ ] Verify every swap/trade call has a non-zero `amountOutMin` (not hardcoded to `0`)
- [ ] Check that `amountOutMin` is set by the USER, not computed on-chain from a manipulable source
- [ ] Look for multi-hop swaps — is slippage checked on the final output, not intermediate steps?
- [ ] Verify AMM `addLiquidity()` calls include `amountAMin` / `amountBMin` parameters
- [ ] Check if the protocol exposes any path to swap with `0` slippage protection via a wrapper

**Pattern Reference**: [patterns/slippage-patterns.md](patterns/slippage-patterns.md)

---

### 15. Denial-Of-Service (36 occurrences - 0.07%)

- [ ] Check withdrawal patterns — can one user's revert (blacklisted USDC, contract with no receive) block all withdrawals?
- [ ] Verify batch processing has a max batch size or gas-safe loop bounds
- [ ] Look for `require(address(this).balance >= X)` — force-sent ETH via `selfdestruct` can break this
- [ ] Check if governance/admin actions (pause, blacklist, parameter change) can permanently trap user funds
- [ ] Verify that emergency functions exist for recovery if a dependency (oracle, bridge, DEX) is down

**Pattern Reference**: [patterns/denial-of-service-patterns.md](patterns/denial-of-service-patterns.md)

---

### 16. Admin / Centralization (36 occurrences - 0.07%)

- [ ] List ALL admin-only functions — can the owner rug pull users (drain funds, change fees to 100%, pause forever)?
- [ ] Check if privileged parameter changes have upper/lower bounds (fee caps, rate limits, cooldowns)
- [ ] Verify admin actions emit events for transparency and off-chain monitoring
- [ ] Look for timelock on critical admin operations (parameter changes, upgrades, fund movements)
- [ ] Check if the admin can upgrade the implementation to a malicious contract without delay

**Pattern Reference**: [patterns/admin-patterns.md](patterns/admin-patterns.md)

---

### 17. Missing Logic (33 occurrences - 0.07%)

- [ ] Check that withdraw/claim functions handle the case where `amount == 0` (should revert or no-op)
- [ ] Verify that protocol fee collection cannot be skipped by calling in a specific order
- [ ] Look for missing `whenNotPaused` modifiers on functions that should be pausable
- [ ] Check if important state transitions have missing event emissions
- [ ] Verify that cleanup/removal functions delete ALL associated state (not leaving orphan entries)

**Pattern Reference**: [patterns/missing-logic-patterns.md](patterns/missing-logic-patterns.md)

---

### 18. Rounding (32 occurrences - 0.06%)

- [ ] Verify rounding direction favors the PROTOCOL, not the user (round down on mint/deposit, round up on redeem/withdraw)
- [ ] Check share-to-asset and asset-to-share conversions — ERC4626 `convertToShares()` / `convertToAssets()`
- [ ] Look for repeated small operations that accumulate rounding loss over time (1 wei per tx adds up)
- [ ] Verify that division results used in comparisons account for truncation (e.g., `a / b * b != a`)
- [ ] Check if rounding errors enable a profitable deposit/withdraw loop

**Pattern Reference**: [patterns/rounding-patterns.md](patterns/rounding-patterns.md)

---

### 19. Stale Price (31 occurrences - 0.06%)

- [ ] Verify `latestRoundData()` return value `updatedAt` is checked against a maximum staleness threshold
- [ ] Check that `answeredInRound >= roundId` to avoid consuming stale round data
- [ ] Look for L2-specific feeds — is the L2 sequencer uptime feed checked before using the price?
- [ ] Verify the staleness threshold is appropriate for the feed (e.g., 1 hour for ETH/USD, 24 hours for less liquid pairs)
- [ ] Check what happens if the oracle returns `price == 0` — does the protocol revert or proceed with bad math?

**Pattern Reference**: [patterns/stale-price-patterns.md](patterns/stale-price-patterns.md)

---

### 20. ERC4626 (28 occurrences - 0.06%)

- [ ] Check for first depositor / share inflation attack — is there a dead shares mechanism or minimum deposit?
- [ ] Verify `previewDeposit()` / `previewMint()` / `previewRedeem()` / `previewWithdraw()` match actual behavior
- [ ] Check rounding: `deposit` and `mint` should round IN FAVOR of the vault; `redeem` and `withdraw` should round IN FAVOR of the vault
- [ ] Verify `totalAssets()` cannot be manipulated by directly sending tokens to the vault (donation attack)
- [ ] Check that `maxDeposit()` / `maxMint()` / `maxRedeem()` / `maxWithdraw()` return correct limits

**Pattern Reference**: [patterns/erc4626-patterns.md](patterns/erc4626-patterns.md) | Attack Tree: [attack-trees/vault-attack-tree.md](attack-trees/vault-attack-tree.md)

---

## HIGH PRIORITY (Ranks 21-50)

| Rank | Vulnerability Type               | Count | Pattern Reference                                                                                     |
| ---- | -------------------------------- | ----- | ----------------------------------------------------------------------------------------------------- |
| 21   | ERC20                            | 27    | [erc20-patterns.md](patterns/erc20-patterns.md)                                                       |
| 22   | First Depositor Issue            | 26    | [first-depositor-issue-patterns.md](patterns/first-depositor-issue-patterns.md)                       |
| 23   | Weird ERC20                      | 26    | [weird-erc20-patterns.md](patterns/weird-erc20-patterns.md)                                           |
| 24   | Flash Loan                       | 25    | [flash-loan-patterns.md](patterns/flash-loan-patterns.md)                                             |
| 25   | Chainlink                        | 25    | [chainlink-patterns.md](patterns/chainlink-patterns.md)                                               |
| 26   | Configuration                    | 24    | [configuration-patterns.md](patterns/configuration-patterns.md)                                       |
| 27   | Missing Check                    | 23    | [missing-check-patterns.md](patterns/missing-check-patterns.md)                                       |
| 28   | Vote                             | 22    | [vote-patterns.md](patterns/vote-patterns.md)                                                         |
| 29   | Uniswap                          | 22    | [uniswap-patterns.md](patterns/uniswap-patterns.md)                                                   |
| 30   | Fund Lock                        | 22    | [fund-lock-patterns.md](patterns/fund-lock-patterns.md)                                               |
| 31   | ERC721                           | 21    | [erc721-patterns.md](patterns/erc721-patterns.md)                                                     |
| 32   | Coding Bug                       | 20    | [coding-bug-patterns.md](patterns/coding-bug-patterns.md)                                             |
| 33   | Sandwich Attack                  | 19    | [sandwich-attack-patterns.md](patterns/sandwich-attack-patterns.md)                                   |
| 34   | NFT                              | 19    | [nft-patterns.md](patterns/nft-patterns.md)                                                           |
| 35   | Deposit/Reward Tokens            | 18    | [deposit-reward-tokens-patterns.md](patterns/deposit-reward-tokens-patterns.md)                       |
| 36   | Gas Limit                        | 18    | [gas-limit-patterns.md](patterns/gas-limit-patterns.md)                                               |
| 37   | Chain Reorg Attack               | 18    | [chain-reorganization-attack-patterns.md](patterns/chain-reorganization-attack-patterns.md)           |
| 38   | Approve                          | 18    | [approve-patterns.md](patterns/approve-patterns.md)                                                   |
| 39   | Swap                             | 18    | [swap-patterns.md](patterns/swap-patterns.md)                                                         |
| 40   | Lending Pool                     | 17    | [lending-pool-patterns.md](patterns/lending-pool-patterns.md)                                         |
| 41   | ERC1155                          | 17    | [erc1155-patterns.md](patterns/erc1155-patterns.md)                                                   |
| 42   | Blacklisted                      | 16    | [blacklisted-patterns.md](patterns/blacklisted-patterns.md)                                           |
| 43   | Auction                          | 15    | [auction-patterns.md](patterns/auction-patterns.md)                                                   |
| 44   | Initialization                   | 15    | [initialization-patterns.md](patterns/initialization-patterns.md)                                     |
| 45   | Allowance                        | 15    | [allowance-patterns.md](patterns/allowance-patterns.md)                                               |
| 46   | call vs transfer                 | 15    | [call-vs-transfer-patterns.md](patterns/call-vs-transfer-patterns.md)                                 |
| 47   | Bypass Limit                     | 15    | [bypass-limit-patterns.md](patterns/bypass-limit-patterns.md)                                         |
| 48   | Precision Loss                   | 14    | [precision-loss-patterns.md](patterns/precision-loss-patterns.md)                                     |
| 49   | Replay Attack                    | 14    | [replay-attack-patterns.md](patterns/replay-attack-patterns.md)                                       |
| 50   | transferFrom vs safeTransferFrom | 14    | [transferfrom-vs-safetransferfrom-patterns.md](patterns/transferfrom-vs-safetransferfrom-patterns.md) |

---

## MEDIUM PRIORITY (Ranks 51-100)

| Rank | Vulnerability Type        | Count | Pattern Reference                                                                       |
| ---- | ------------------------- | ----- | --------------------------------------------------------------------------------------- |
| 51   | Type Casting              | 14    | [type-casting-patterns.md](patterns/type-casting-patterns.md)                           |
| 52   | SafeTransfer              | 14    | [safetransfer-patterns.md](patterns/safetransfer-patterns.md)                           |
| 53   | Ownership                 | 13    | [ownership-patterns.md](patterns/ownership-patterns.md)                                 |
| 54   | Grief Attack              | 12    | [grief-attack-patterns.md](patterns/grief-attack-patterns.md)                           |
| 55   | Share Inflation           | 12    | [share-inflation-patterns.md](patterns/share-inflation-patterns.md)                     |
| 56   | Refund Ether              | 12    | [refund-ether-patterns.md](patterns/refund-ether-patterns.md)                           |
| 57   | ERC777                    | 11    | [erc777-patterns.md](patterns/erc777-patterns.md)                                       |
| 58   | Upgradable                | 10    | [upgradable-patterns.md](patterns/upgradable-patterns.md)                               |
| 59   | Code Quality              | 10    | [code-quality-patterns.md](patterns/code-quality-patterns.md)                           |
| 60   | Pause                     | 10    | [pause-patterns.md](patterns/pause-patterns.md)                                         |
| 61   | TWAP                      | 10    | [twap-patterns.md](patterns/twap-patterns.md)                                           |
| 62   | Initial Deposit           | 9     | [initial-deposit-patterns.md](patterns/initial-deposit-patterns.md)                     |
| 63   | Timing                    | 9     | [timing-patterns.md](patterns/timing-patterns.md)                                       |
| 64   | Vault                     | 9     | [vault-patterns.md](patterns/vault-patterns.md)                                         |
| 65   | Payable                   | 9     | [payable-patterns.md](patterns/payable-patterns.md)                                     |
| 66   | EIP-4626                  | 9     | [eip-4626-patterns.md](patterns/eip-4626-patterns.md)                                   |
| 67   | Min/Max Cap Validation    | 9     | [min-max-cap-validation-patterns.md](patterns/min-max-cap-validation-patterns.md)       |
| 68   | External Call             | 8     | [external-call-patterns.md](patterns/external-call-patterns.md)                         |
| 69   | Cross Chain               | 8     | [cross-chain-patterns.md](patterns/cross-chain-patterns.md)                             |
| 70   | Delegate                  | 8     | [delegate-patterns.md](patterns/delegate-patterns.md)                                   |
| 71   | Pre/Post Balance          | 7     | [pre-post-balance-patterns.md](patterns/pre-post-balance-patterns.md)                   |
| 72   | 0x                        | 7     | [0x-patterns.md](patterns/0x-patterns.md)                                               |
| 73   | Check Return Value        | 7     | [check-return-value-patterns.md](patterns/check-return-value-patterns.md)               |
| 74   | Whitelist/Blacklist Match | 7     | [whitelist-blacklist-match-patterns.md](patterns/whitelist-blacklist-match-patterns.md) |
| 75   | LayerZero                 | 7     | [layerzero-patterns.md](patterns/layerzero-patterns.md)                                 |
| 76   | Data Validation           | 7     | [data-validation-patterns.md](patterns/data-validation-patterns.md)                     |
| 77   | External Contract         | 7     | [external-contract-patterns.md](patterns/external-contract-patterns.md)                 |
| 78   | Broken Loop               | 7     | [broken-loop-patterns.md](patterns/broken-loop-patterns.md)                             |
| 79   | Revert By Sending Dust    | 7     | [revert-by-sending-dust-patterns.md](patterns/revert-by-sending-dust-patterns.md)       |
| 80   | Bridge                    | 7     | [bridge-patterns.md](patterns/bridge-patterns.md)                                       |
| 81   | 1/64 Rule                 | 6     | [1-64-rule-patterns.md](patterns/1-64-rule-patterns.md)                                 |
| 82   | Account Abstraction       | 6     | [account-abstraction-patterns.md](patterns/account-abstraction-patterns.md)             |
| 83   | L2 Sequencer              | 6     | [l2-sequencer-patterns.md](patterns/l2-sequencer-patterns.md)                           |
| 84   | from=to                   | 6     | [from-to-patterns.md](patterns/from-to-patterns.md)                                     |
| 85   | Typo / CopyPaste          | 6     | [typo-copypaste-patterns.md](patterns/typo-copypaste-patterns.md)                       |
| 86   | Change Validation         | 6     | [change-validation-patterns.md](patterns/change-validation-patterns.md)                 |
| 87   | EIP-712                   | 6     | [eip-712-patterns.md](patterns/eip-712-patterns.md)                                     |
| 88   | Deadline                  | 6     | [deadline-patterns.md](patterns/deadline-patterns.md)                                   |
| 89   | USDC                      | 6     | [usdc-patterns.md](patterns/usdc-patterns.md)                                           |
| 90   | USDT                      | 6     | [usdt-patterns.md](patterns/usdt-patterns.md)                                           |
| 91   | Event                     | 6     | [event-patterns.md](patterns/event-patterns.md)                                         |
| 92   | Withdraw Pattern          | 6     | [withdraw-pattern-patterns.md](patterns/withdraw-pattern-patterns.md)                   |
| 93   | Array                     | 6     | [array-patterns.md](patterns/array-patterns.md)                                         |
| 94   | Read-only Reentrancy      | 6     | [read-only-reentrancy-patterns.md](patterns/read-only-reentrancy-patterns.md)           |
| 95   | Royalty                   | 6     | [royalty-patterns.md](patterns/royalty-patterns.md)                                     |
| 96   | ERC2981                   | 6     | [erc2981-patterns.md](patterns/erc2981-patterns.md)                                     |
| 97   | Hardcoded Address         | 6     | [hardcoded-address-patterns.md](patterns/hardcoded-address-patterns.md)                 |
| 98   | Arbitrum                  | 5     | [arbitrum-patterns.md](patterns/arbitrum-patterns.md)                                   |
| 99   | EIP-165                   | 5     | [eip-165-patterns.md](patterns/eip-165-patterns.md)                                     |
| 100  | supportsInterface         | 5     | [supportsinterface-patterns.md](patterns/supportsinterface-patterns.md)                 |

---

## Statistics

- **Total Vulnerabilities Analyzed**: 50,530
- **Unique Vulnerability Types**: 207
- **Checklist Coverage**: Top 100 vulnerability types
- **Last Updated**: 2026-02-24

## Quick Links

- [All Pattern Files](patterns/)
- [Severity Analysis](severity/)
- [Audit Source Analysis](sources/)
- [Full Statistics](STATISTICS.md)
- [Searchable Index](INDEX.md)
- [Cross-Reference Index](XREF.md)
- [AI Trigger Phrases](TRIGGERS.md)
