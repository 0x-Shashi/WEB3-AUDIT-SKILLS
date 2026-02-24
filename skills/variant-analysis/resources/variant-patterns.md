---
id: variant-patterns-catalog
title: Variant Pattern Catalog
category: resource
parent_skill: variant-analysis/SKILL.md
description: >
  Catalog of 12 major vulnerability pattern classes with their variant dimensions,
  search strategies, real-world examples, and detection code. Use this as a lookup
  reference when performing variant analysis during an audit.
tags:
  - variant-analysis
  - patterns
  - search
  - catalog
last_updated: 2026-02-24
---

# Variant Pattern Catalog

This catalog documents the most common root cause families encountered in smart contract audits. For each pattern class, it provides:

- **Root Cause** — Why the vulnerability exists
- **Variant Dimensions** — How it manifests in different contexts
- **Search Queries** — Grep / Slither / Semgrep patterns to find all instances
- **Validation Criteria** — How to distinguish true positives from false positives
- **Real-World Cases** — Historical exploits with the same root cause

---

## Pattern 1: Reentrancy (CEI Violations)

### Root Cause
State is modified after an external call, allowing the callee to re-enter the contract and operate on stale state.

### Variant Dimensions

| Variant | Description | Example |
|---|---|---|
| **Single-function** | Re-enter the same function | `withdraw()` → re-enter `withdraw()` |
| **Cross-function** | Re-enter a different function on the same contract | `withdraw()` → re-enter `getBalance()` to read stale state |
| **Cross-contract** | Re-enter via a different contract in the protocol | `VaultA.withdraw()` → callback → `VaultB.borrow()` using VaultA's stale state |
| **Read-only** | View function returns stale state during reentrancy | `getPrice()` reads `totalAssets` before it's updated during `withdraw()` |
| **ERC777 callback** | `tokensReceived()` hook triggers reentrancy | Any `safeTransfer` with ERC777-compatible token |
| **ERC721 callback** | `onERC721Received()` hook triggers reentrancy | NFT minting or transfer with callback |
| **Transient storage bypass** | Reentrancy guard uses transient storage but cross-contract call bypasses it | Different contract addresses have independent transient storage |

### Search Queries

```bash
# Find all external calls
grep -rn "\.call{value\|\.call(\|\.safeTransfer\|\.safeTransferFrom\|\.transfer(\|\.send(" \
  --include="*.sol"

# Find state changes after external calls (heuristic)
grep -rn -A10 "\.safeTransfer\|\.call{" --include="*.sol" | grep "\[.*\] =\|\[.*\] -="

# Find functions WITHOUT nonReentrant that have external calls
grep -rn "function.*external\|function.*public" --include="*.sol" | grep -v "nonReentrant"
# Then cross-reference with external call list

# Slither built-in
slither . --detect reentrancy-eth,reentrancy-no-eth,reentrancy-benign,reentrancy-events
```

### Validation Criteria

- [ ] External call is present AND reachable by untrusted caller
- [ ] State variable is written AFTER the external call
- [ ] No `nonReentrant` modifier on the function
- [ ] Callback is attacker-controlled (ERC777/ERC721/raw call)
- [ ] Re-entered state is meaningfully exploitable (not just event emission)

### Real-World Cases

| Protocol | Date | Loss | Variant Type |
|---|---|---|---|
| The DAO | June 2016 | $60M | Single-function reentrancy |
| Cream Finance | Oct 2021 | $130M | ERC777 cross-contract reentrancy |
| Fei Protocol / Rari | Apr 2022 | $80M | Cross-contract reentrancy |
| Euler Finance | Mar 2023 | $197M | Single-function (donateToReserves) |
| Curve Finance | Jul 2023 | $70M | Vyper reentrancy lock failure |

---

## Pattern 2: Access Control Gaps

### Root Cause
Functions that modify sensitive state lack proper authorization checks, allowing unauthorized callers to execute privileged operations.

### Variant Dimensions

| Variant | Description | Example |
|---|---|---|
| **Missing modifier** | No `onlyOwner`/`onlyRole` on admin function | `setFee()` callable by anyone |
| **Unprotected initializer** | `initialize()` can be called after deployment | Proxy impl left uninitialized, attacker calls `initialize()` |
| **Wrong role check** | Function checks wrong role | `onlyMinter` instead of `onlyAdmin` for parameter change |
| **Bypassed via delegatecall** | Access control on proxy, not implementation | Direct call to implementation bypasses proxy's auth |
| **Missing validation on parameter** | Function is protected but parameters aren't validated | Admin can set `fee = 100%` |
| **Privilege escalation** | Lower-privileged role can grant higher privileges | `MINTER_ROLE` can call `grantRole(ADMIN_ROLE, attacker)` |

### Search Queries

```bash
# Find all external/public functions
grep -rn "function.*) external\|function.*) public" --include="*.sol"

# Filter OUT protected functions
grep -rn "function.*) external\|function.*) public" --include="*.sol" \
  | grep -v "onlyOwner\|onlyRole\|require(msg.sender\|_checkRole\|onlyAdmin\|modifier"

# Find all initializer functions
grep -rn "function initialize\|function init\b\|initializer" --include="*.sol"

# Find selfdestruct (must be protected)
grep -rn "selfdestruct\|SELFDESTRUCT" --include="*.sol"

# Find functions that change owner/admin
grep -rn "owner =\|admin =\|_transferOwnership\|transferOwnership\|grantRole\|revokeRole" --include="*.sol"
```

### Validation Criteria

- [ ] Function modifies state (not just a view)
- [ ] No access control modifier present
- [ ] No `require(msg.sender == ...)` check
- [ ] Function is not internal/private
- [ ] State change has security impact (not just cosmetic)

### Real-World Cases

| Protocol | Date | Loss | Variant Type |
|---|---|---|---|
| Parity Wallet | Nov 2017 | $150M frozen | Unprotected `initWallet()` |
| Wormhole | Feb 2022 | $326M | Missing validation on guardian set |
| Ronin Bridge | Mar 2022 | $624M | Compromised validator keys (partial) |
| Nomad Bridge | Aug 2022 | $190M | Broken access control on message validation |

---

## Pattern 3: Oracle Manipulation

### Root Cause
Protocol relies on a price feed or data source that can be manipulated by an attacker, typically via flash loans or large trades.

### Variant Dimensions

| Variant | Description | Example |
|---|---|---|
| **Spot price** | Using AMM spot price instead of TWAP | `UniswapV3Pool.slot0()` instead of `observe()` |
| **Stale price** | Oracle price is outdated | Chainlink `latestRoundData()` without checking `updatedAt` |
| **Reserve-based** | Price derived from pool reserves | `getReserves()` manipulable via flash loan |
| **Circular dependency** | Protocol's own token price used in calculations | `balanceOf(address(this))` used as price input |
| **Cross-pool** | Different pools used for same asset with different prices | Pool A uses Chainlink, Pool B uses Uniswap TWAP |
| **Decimal mismatch** | Oracle returns different decimal precision than expected | Chainlink ETH/USD = 8 decimals, token = 18 decimals |

### Search Queries

```bash
# Spot price usage (Uniswap V3)
grep -rn "slot0\|sqrtPriceX96" --include="*.sol"

# Spot price usage (Uniswap V2 / forks)
grep -rn "getReserves\|reserve0\|reserve1" --include="*.sol"

# Chainlink oracle usage
grep -rn "latestRoundData\|latestAnswer\|getRoundData" --include="*.sol"

# Balance-based pricing (manipulable)
grep -rn "balanceOf(address(this))\|address(this).balance" --include="*.sol"

# Check for missing staleness checks
grep -rn "latestRoundData" --include="*.sol" | grep -v "updatedAt\|roundId\|answeredInRound"
```

### Validation Criteria

- [ ] Price source can be manipulated in a single transaction (flash loan)
- [ ] No TWAP or time-weighted mechanism applied
- [ ] Price is used for a critical decision (liquidation, collateral, exchange rate)
- [ ] Manipulation profit exceeds attack cost
- [ ] No circuit breaker or deviation check

### Real-World Cases

| Protocol | Date | Loss | Variant Type |
|---|---|---|---|
| bZx | Feb 2020 | $8M | Uniswap spot price manipulation via flash loan |
| Harvest Finance | Oct 2020 | $34M | Curve pool price manipulation |
| Mango Markets | Oct 2022 | $114M | Oracle price manipulation via large trades |
| Bonq DAO | Feb 2023 | $120M | Tellor oracle manipulation with low liquidity |

---

## Pattern 4: Arithmetic / Rounding Errors

### Root Cause
Integer division truncation, precision loss in multiplication/division order, or overflow/underflow leads to incorrect asset calculations.

### Variant Dimensions

| Variant | Description | Example |
|---|---|---|
| **Round-down on deposit** | User receives fewer shares than entitled | `shares = amount * totalShares / totalAssets` truncates |
| **Round-down on withdrawal** | User receives fewer assets than entitled | `assets = shares * totalAssets / totalShares` truncates |
| **First depositor attack** | Attacker front-runs first deposit for inflation | Donate 1 wei, then deposit inflates share price |
| **Precision loss ordering** | Multiply then divide vs divide then multiply | `(a * b) / c` vs `(a / c) * b` yield different results |
| **Fee calculation** | Fees round to zero for small amounts | `fee = amount * feeRate / 10000` = 0 for small amount |
| **Accumulator drift** | Small rounding errors compound over many operations | Per-second reward rate × time accumulated |
| **Phantom overflow** | Intermediate multiplication exceeds uint256 even though result fits | `(a * b) / c` — `a * b` overflows |

### Search Queries

```bash
# Find all division operations
grep -rn " / \|\.div(" --include="*.sol"

# Find multiplication before division (check order)
grep -rn "\* .* / \|\.mul(.*\.div(" --include="*.sol"

# Find share/asset calculations
grep -rn "totalSupply\|totalAssets\|totalShares\|exchangeRate\|convertToShares\|convertToAssets" \
  --include="*.sol"

# Find ERC4626 implementations (first depositor vulnerable pattern)
grep -rn "ERC4626\|convertToShares\|convertToAssets\|previewDeposit\|previewMint" --include="*.sol"

# Find fee calculations
grep -rn "fee\|FEE\|bps\|BPS\|BASIS_POINTS" --include="*.sol"
```

### Validation Criteria

- [ ] Division present with remainder > 0 for realistic inputs
- [ ] Rounding direction favors attacker (or harms protocol)
- [ ] No explicit rounding guard (`mulDivUp` / `mulDivDown`)
- [ ] Impact exceeds dust amount (not just 1 wei)
- [ ] Repeatable — attacker can exploit multiple times to amplify

### Real-World Cases

| Protocol | Date | Loss | Variant Type |
|---|---|---|---|
| Multiple ERC4626 vaults | 2022–2023 | Various | First depositor / inflation attack |
| HundredFinance | Apr 2023 | $7M | Empty market share manipulation |
| Sushi Kashi | 2021 | Theoretical | First depositor on lending pair |

---

## Pattern 5: Unchecked External Call Returns

### Root Cause
External call return value is not checked, allowing silent failures that leave the contract in an inconsistent state.

### Variant Dimensions

| Variant | Description | Example |
|---|---|---|
| **Unchecked transfer** | `IERC20.transfer()` return ignored | Non-reverting tokens silently fail |
| **Unchecked approve** | `IERC20.approve()` return ignored | USDT reverts on non-zero to non-zero approve |
| **Unchecked low-level call** | `.call()` return value `(bool success,)` ignored | ETH transfer fails silently |
| **Unchecked send** | `.send()` return value ignored | ETH send fails if recipient reverts |
| **Double approval** | `approve(spender, newAmount)` without first setting to 0 | USDT race condition |

### Search Queries

```bash
# Unchecked transfer
grep -rn "\.transfer(" --include="*.sol" | grep -v "safeTransfer\|require\|if (\|success\|bool"

# Unchecked approve
grep -rn "\.approve(" --include="*.sol" | grep -v "safeApprove\|require\|forceApprove"

# Unchecked low-level call
grep -rn "\.call{" --include="*.sol" | grep -v "require\|if (\|success\|revert"

# Unchecked send
grep -rn "\.send(" --include="*.sol" | grep -v "require\|if (\|success"

# Check if SafeERC20 is imported (good) — if not, all transfer/approve are suspect
grep -rn "using SafeERC20\|import.*SafeERC20" --include="*.sol"

# Slither detector
slither . --detect unchecked-transfer,unchecked-send,unchecked-lowlevel
```

### Validation Criteria

- [ ] Return value is genuinely unchecked (no require/if/assert wrapping)
- [ ] Token can actually return false (some always revert instead)
- [ ] Silent failure leads to state inconsistency or fund loss
- [ ] Protocol interacts with unknown/user-supplied tokens

---

## Pattern 6: Front-Running / MEV Vulnerabilities

### Root Cause
Transaction ordering is adversarial — miners/validators can reorder, insert, or censor transactions to extract value.

### Variant Dimensions

| Variant | Description | Example |
|---|---|---|
| **Sandwich attack** | Attacker front-runs and back-runs a swap | Buy before victim, sell after, extract slippage |
| **Liquidation front-running** | Attacker front-runs liquidation to steal profit | See oracle update, liquidate before legitimate bot |
| **Missing deadline** | Swap has no deadline, can be delayed by miner | `deadline = type(uint256).max` or missing |
| **Missing slippage** | Swap has no slippage protection | `amountOutMin = 0` or parameter not used |
| **Permit front-running** | Attacker front-runs `permit()` with their own | Causes `permit()` revert, DOS on the original tx |
| **Commit-reveal bypass** | Commit-reveal scheme is too weak | Seed is predictable, or reveal window is too long |

### Search Queries

```bash
# Missing deadline checks
grep -rn "deadline\|block.timestamp" --include="*.sol" | grep -v "require\|if (\|assert"

# Missing slippage protection
grep -rn "amountOutMin\|minAmountOut\|slippage\|minReceived" --include="*.sol"
# If NOT found, check if swaps exist without protection:
grep -rn "swap\|exchange\|trade" --include="*.sol"

# Swap calls without slippage/deadline
grep -rn "\.swap(\|swapExactTokens\|swapTokensForExact" --include="*.sol"

# tx.origin usage (phishing vector)
grep -rn "tx.origin" --include="*.sol"
```

### Validation Criteria

- [ ] Transaction can be observed in mempool (not private/Flashbots)
- [ ] Reordering creates profit opportunity for attacker
- [ ] No slippage/deadline protection present
- [ ] Attack profit exceeds gas cost

---

## Pattern 7: Signature / Replay Vulnerabilities

### Root Cause
Cryptographic signatures lack sufficient context (nonce, chainId, deadline, contract address), allowing them to be replayed across contexts.

### Variant Dimensions

| Variant | Description | Example |
|---|---|---|
| **Cross-chain replay** | Signature valid on multiple chains | Missing `block.chainid` in domain separator |
| **Nonce-less replay** | Same signature can be used multiple times | No nonce increment after use |
| **Cross-contract replay** | Signature valid for multiple contracts | Missing `address(this)` in domain separator |
| **Expired signature** | No deadline, signature valid forever | Missing expiry timestamp |
| **Malleable signature** | `s` value in upper range allows duplicate | Not enforcing `s <= n/2` |
| **ecrecover returns 0** | `ecrecover` returns `address(0)` on invalid sig | Missing `require(signer != address(0))` |

### Search Queries

```bash
# Find all signature verification
grep -rn "ecrecover\|ECDSA.recover\|SignatureChecker" --include="*.sol"

# Find EIP-712 usage
grep -rn "DOMAIN_SEPARATOR\|EIP712\|_domainSeparatorV4\|_hashTypedDataV4" --include="*.sol"

# Check for missing chainId
grep -rn "DOMAIN_SEPARATOR\|domainSeparator" --include="*.sol" | grep -v "chainid\|block.chainid"

# Check for nonce management
grep -rn "nonce\|_nonces" --include="*.sol"

# Find permit implementations
grep -rn "function permit\|PERMIT_TYPEHASH" --include="*.sol"
```

### Validation Criteria

- [ ] Signature is used for authorization (not just logging)
- [ ] Missing context field (nonce, chainId, deadline, contract address)
- [ ] Replay would result in unauthorized action
- [ ] No other mechanism prevents replay (e.g., one-time state change)

---

## Pattern 8: Token Integration Issues

### Root Cause
Protocol assumes all ERC20 tokens behave identically, but non-standard tokens break these assumptions.

### Variant Dimensions

| Variant | Description | Example |
|---|---|---|
| **Fee-on-transfer** | Token takes fee during transfer, received amount < sent | USDT with fee, PAXG, deflationary tokens |
| **Rebasing tokens** | Token balance changes without transfer | stETH, aToken, AMPL |
| **Non-standard decimals** | Token has != 18 decimals | USDC (6), WBTC (8), EURS (2) |
| **Approve race** | Token requires setting approve to 0 first | USDT `approve()` reverts if current != 0 and new != 0 |
| **No boolean return** | `transfer()` returns nothing instead of `bool` | USDT, BNB (old) |
| **Blacklist** | Token can blacklist addresses | USDC, USDT — can freeze protocol funds |
| **Pausable** | Token can be paused, blocking all transfers | USDC — if paused, protocol cannot function |
| **Multiple entry points** | Token accessible via multiple addresses | Some proxy tokens have dual entry points |
| **Call hooks** | Token has pre/post transfer hooks | ERC777 (tokensReceived), ERC1363 |

### Search Queries

```bash
# Find all token interaction points
grep -rn "\.transfer(\|\.transferFrom(\|\.approve(\|\.safeTransfer\|\.safeApprove\|\.safeTransferFrom" \
  --include="*.sol"

# Find balance checks that assume exact amounts
grep -rn "balanceOf.*==\|== .*balanceOf" --include="*.sol"

# Find hardcoded decimal assumptions
grep -rn "1e18\|10\*\*18\|10 \*\* 18\|decimals()" --include="*.sol"

# Find token whitelist/blacklist handling
grep -rn "isBlacklisted\|blacklist\|whitelist\|frozenAccount" --include="*.sol"

# Check if protocol handles fee-on-transfer
grep -rn "balanceBefore\|balanceAfter\|amountReceived" --include="*.sol"
```

### Validation Criteria

- [ ] Protocol accepts arbitrary/user-supplied tokens
- [ ] No whitelist restricting which tokens can be used
- [ ] Balance accounting assumes transfer amount == received amount
- [ ] No pre/post balance check pattern for fee-on-transfer
- [ ] Decimal handling is hardcoded (not using `decimals()`)

---

## Pattern 9: Proxy / Upgrade Vulnerabilities

### Root Cause
Upgradeable contracts have special risks around storage layout, initialization, and implementation access.

### Variant Dimensions

| Variant | Description | Example |
|---|---|---|
| **Uninitialized implementation** | Implementation contract's `initialize()` never called | Attacker calls `initialize()` on impl directly |
| **Storage collision** | New implementation's storage layout conflicts with old | Adding variable before existing ones shifts slots |
| **Function selector clash** | Proxy's function selector collides with implementation | Transparent proxy pattern mitigates this |
| **Missing disableInitializers** | Implementation lacks `_disableInitializers()` in constructor | Leave impl uninitializable |
| **UUPS missing upgrade guard** | `_authorizeUpgrade()` missing or unprotected | Anyone can upgrade to malicious implementation |
| **Immutable variables in impl** | Immutables stored in bytecode, not in storage | Different values for proxy vs implementation |

### Search Queries

```bash
# Find all proxy patterns
grep -rn "delegatecall\|DELEGATECALL\|Proxy\|ERC1967\|UUPSUpgradeable\|TransparentProxy" \
  --include="*.sol"

# Find initialize functions
grep -rn "function initialize\|initializer\|reinitializer" --include="*.sol"

# Find _disableInitializers
grep -rn "_disableInitializers\|constructor" --include="*.sol"

# Find UUPS upgrade authorization
grep -rn "_authorizeUpgrade\|upgradeTo\|upgradeToAndCall" --include="*.sol"

# Find storage layout definitions
grep -rn "@custom:storage-location\|StorageSlot\|ERC7201" --include="*.sol"

# Slither detector
slither . --detect uninitialized-state,delegatecall-loop
```

---

## Pattern 10: Governance / Voting Vulnerabilities

### Root Cause
Governance mechanisms can be manipulated through flash loans, incomplete snapshot mechanisms, or quorum manipulation.

### Variant Dimensions

| Variant | Description | Example |
|---|---|---|
| **Flash loan voting** | Borrow tokens, vote, return in same tx | No snapshot, uses current balance for voting power |
| **Double voting** | Transfer tokens and vote from new address | No checkpoint mechanism |
| **Quorum manipulation** | Lower quorum by burning/locking tokens | Reduce `totalSupply` used in quorum calculation |
| **Proposal front-running** | See proposal, buy tokens to vote | Snapshot taken at proposal creation |
| **Timelock bypass** | Execute without waiting for timelock | Missing timelock on critical operations |
| **Griefing** | Block proposals by front-running with identical proposal | Proposal ID collision |

### Search Queries

```bash
# Find governance contracts
grep -rn "Governor\|propose\|castVote\|execute\|Timelock\|TimelockController" --include="*.sol"

# Find voting power calculation
grep -rn "getVotes\|getPastVotes\|balanceOf\|votingPower\|quorum" --include="*.sol"

# Find snapshot mechanism
grep -rn "snapshot\|checkpoint\|_checkpoints\|getPastTotalSupply" --include="*.sol"

# Find timelock configuration
grep -rn "delay\|minDelay\|getMinDelay\|setDelay" --include="*.sol"
```

---

## Pattern 11: Cross-Chain Bridge Vulnerabilities

### Root Cause
Bridge contracts must safely coordinate state across chains, but message verification, replay protection, and finality assumptions often have gaps.

### Variant Dimensions

| Variant | Description | Example |
|---|---|---|
| **Message replay** | Same message processed multiple times | Missing processed-message tracking |
| **Fake message** | Forged proof accepted | Insufficient merkle proof verification |
| **Incomplete finality** | Message processed before source chain finalizes | Reorg on source chain invalidates bridge message |
| **Chain ID confusion** | Same message valid on multiple chains | Missing chain ID in message hash |
| **Sequencer dependency** | L2 bridge trusts sequencer for ordering | Sequencer can censor or reorder messages |

### Search Queries

```bash
# Find bridge-related code
grep -rn "bridge\|Bridge\|crossChain\|layerZero\|ccip\|Hyperlane\|Axelar" --include="*.sol"

# Find message verification
grep -rn "verifyMessage\|processMessage\|executeMessage\|receiveMessage" --include="*.sol"

# Find replay protection
grep -rn "processedMessages\|usedNonces\|messageExecuted" --include="*.sol"

# Find chain ID validation
grep -rn "srcChainId\|sourceChain\|originChain\|chainSelector" --include="*.sol"
```

---

## Pattern 12: Denial of Service (DoS)

### Root Cause
Attacker can make a contract function unusable by forcing reverts, consuming all gas, or blocking critical operations.

### Variant Dimensions

| Variant | Description | Example |
|---|---|---|
| **Unbounded loop** | Loop over dynamic array, gas exceeds block limit | Iterating all depositors for distribution |
| **External call revert** | Single revert in batch blocks all operations | One token transfer fails, entire batch reverts |
| **Griefing** | Attacker makes a function unprofitable | Front-run every liquidation attempt |
| **Block stuffing** | Fill blocks to prevent time-sensitive tx | Prevent oracle update or auction end |
| **Contract size** | `extcodesize` check fails for contract in constructor | Access restricted to EOA but constructor bypasses |
| **Self-destruct to address** | Force ETH to contract breaking balance checks | `selfdestruct(target)` bypasses `receive()`/`fallback()` |
| **Storage DoS** | Attacker fills storage slots to increase gas costs | Create many small positions |

### Search Queries

```bash
# Find unbounded loops
grep -rn "for.*\.length\|while.*\.length" --include="*.sol"

# Find batch operations without failure handling
grep -rn "for.*{" --include="*.sol" -A5 | grep "transfer\|safeTransfer\|call{"

# Find strict equality checks on ETH balance (breakable via selfdestruct)
grep -rn "address(this).balance ==\|== address(this).balance" --include="*.sol"

# Find external calls that must succeed for function to work
grep -rn "require.*\.call\|require.*\.transfer\|require.*\.send" --include="*.sol"

# Slither detectors
slither . --detect controlled-array-length,costly-loop,calls-loop
```

---

## How to Use This Catalog

### During Initial Finding

1. Identify which pattern class your finding belongs to (1–12 above)
2. Read ALL variant dimensions for that class
3. Run EVERY search query listed for that pattern
4. Validate each match using the criteria checklist
5. Apply the expansion matrix from the variant-hunt workflow (Step 7)

### During Full Codebase Review

1. Run the search queries from ALL 12 pattern classes
2. Even if no initial finding triggers variant analysis, the queries will surface vulnerabilities
3. Prioritize patterns based on the protocol type:

| Protocol Type | High-Priority Patterns |
|---|---|
| DEX / AMM | Oracle (#3), Reentrancy (#1), Rounding (#4), MEV (#6) |
| Lending | Oracle (#3), Rounding (#4), Liquidation (#6), Token (#8) |
| Vault / Yield | Reentrancy (#1), Rounding (#4), Token (#8), Oracle (#3) |
| Bridge | Bridge (#11), Signature (#7), Access Control (#2), DoS (#12) |
| Governance | Governance (#10), Signature (#7), Access Control (#2) |
| NFT / Gaming | Reentrancy (#1), Access Control (#2), Signature (#7) |
| Upgradeable | Proxy (#9), Access Control (#2), Storage layout |

### Cross-Pattern Expansion

When you find an instance of one pattern, check adjacent patterns:

```
Reentrancy (#1)  ←→  Token Integration (#8)   → ERC777 hook creates reentrancy
Oracle (#3)      ←→  MEV / Front-Running (#6)  → Oracle update front-running
Rounding (#4)    ←→  Token Integration (#8)    → Different decimals amplify rounding
Access Control (#2) ←→ Proxy (#9)              → Unprotected upgrade function
Signature (#7)   ←→  DoS (#12)                → Permit front-running DoS
```

---

## Further Reading

- [Variant Hunt Workflow](../workflows/variant-hunt.md) — Step-by-step execution guide
- [SKILL.md](../SKILL.md) — Variant analysis overview and methodology
