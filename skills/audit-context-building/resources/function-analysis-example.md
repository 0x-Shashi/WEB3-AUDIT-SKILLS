---
id: AUDIT-CTX-FUNCEX
title: Function Analysis Template & Examples
parent: audit-context-building
type: resource
last_updated: 2025-01-31
---

# Function Analysis Template & Examples

Use this template to analyze every external/public function during deep code review. The template ensures no analysis dimension is overlooked.

---

## Template

```
### contractName.functionName(param1, param2, ...)

**Basics**
- Visibility: external / public / internal
- Access: unrestricted / onlyOwner / role(ROLE_NAME) / custom logic
- Modifiers: nonReentrant, whenNotPaused, onlyRole(X)
- Payable: YES / NO

**State Changes**
- Reads: storage variables read
- Writes: storage variables modified
- Order: [list state changes in execution order]

**External Interactions**
- Calls: [target.function(args)] → return type
- Transfers: [token/ETH sent to whom, how much]
- Callbacks: [any callback hooks to external contracts]

**Events**
- [EventName(indexed param1, param2)]

**Control Flow**
- CEI Compliance: YES / NO / PARTIAL
- Revert conditions: [when does this revert?]
- Branches: [key if/else paths]

**Security Analysis**
- Reentrancy risk: NONE / LOW / MEDIUM / HIGH
- Input validation: [what's validated, what's not]
- Edge cases: [0 amount, max uint, self-transfer, empty array, etc.]
- Arithmetic: [overflow/underflow risks, rounding]

**Risk Level**: LOW / MEDIUM / HIGH / CRITICAL
**Attack surface**: [brief description of how this could be exploited]
**Notes**: [additional observations]
```

---

## Example 1: Lending Pool Withdraw

```
### LendingPool.withdraw(address asset, uint256 amount, address to)

**Basics**
- Visibility: external
- Access: unrestricted (any depositor)
- Modifiers: nonReentrant, whenNotPaused
- Payable: NO

**State Changes**
- Reads: _reserves[asset], _usersConfig[msg.sender], _reservesCount
- Writes:
  1. _reserves[asset].updateState() → updates liquidity index, timestamps
  2. _reserves[asset].updateInterestRates() → recalculates rates
  3. aToken.burn(msg.sender, to, amountToWithdraw, index) → reduces aToken supply
- Order: state update → interest rate update → burn aToken → transfer underlying

**External Interactions**
- Calls: oracle.getAssetPrice(asset) → uint256 (for health factor check)
- Transfers: IERC20(asset).safeTransfer(to, amountToWithdraw)
- Callbacks: none

**Events**
- Withdraw(asset, msg.sender, to, amountToWithdraw)

**Control Flow**
- CEI Compliance: YES (state updated before external transfer)
- Revert conditions:
  - amount == 0 → revert VL_INVALID_AMOUNT
  - insufficient aToken balance → revert underflow
  - health factor < 1 after withdrawal → revert VL_HEALTH_FACTOR_BELOW_THRESHOLD
- Branches: if amount == type(uint256).max → withdraw full balance

**Security Analysis**
- Reentrancy risk: LOW (nonReentrant + CEI pattern)
- Input validation: asset must be valid reserve, amount > 0, to != address(0)
- Edge cases:
  - amount = type(uint256).max → withdraws entire balance (intended behavior)
  - amount = 1 wei → succeeds (dust withdrawal)
  - to = msg.sender → normal case
  - to = address(0) → should revert (check if it does)
  - asset is fee-on-transfer → pool receives less than expected (NOT HANDLED)
- Arithmetic: index multiplication could round down, losing dust

**Risk Level**: HIGH
**Attack surface**: Flash loan → deposit → manipulate oracle → withdraw at inflated value
**Notes**: Does not account for fee-on-transfer tokens. The `to` parameter allows
withdrawal to arbitrary address — verify appropriate for the design. Health factor
check uses oracle price — oracle manipulation could bypass health check.
```

---

## Example 2: Vault Deposit (ERC-4626)

```
### Vault.deposit(uint256 assets, address receiver)

**Basics**
- Visibility: external
- Access: unrestricted
- Modifiers: none
- Payable: NO

**State Changes**
- Reads: totalAssets(), totalSupply()
- Writes:
  1. _mint(receiver, shares) → increases totalSupply, balanceOf[receiver]

**External Interactions**
- Calls: asset.safeTransferFrom(msg.sender, address(this), assets)
- Transfers: ERC-20 from msg.sender to vault
- Callbacks: none (but safeTransferFrom may trigger ERC-777 hooks if asset supports it)

**Events**
- Deposit(msg.sender, receiver, assets, shares)
- Transfer(address(0), receiver, shares) (from _mint)

**Control Flow**
- CEI Compliance: NO — Transfers (external call) happen BEFORE mint (state change)
  - Pattern: check → transfer → mint (reentrancy window between transfer and mint)
- Revert conditions:
  - assets == 0 → depends on implementation (may mint 0 shares or revert)
  - previewDeposit(assets) == 0 → minting 0 shares (loss of funds!)
  - transferFrom fails → revert
- Branches: none

**Security Analysis**
- Reentrancy risk: MEDIUM (external call before state change, no guard)
  - If underlying asset has callbacks (ERC-777), reentrant deposit possible
- Input validation:
  - assets not checked for maxDeposit compliance
  - receiver not checked for address(0)
- Edge cases:
  - assets = 1 → may result in 0 shares (first depositor attack)
  - First deposit when totalSupply = 0 → attacker inflates share price
  - Fee-on-transfer token → vault receives less than `assets`, shares over-minted
  - Rebasing token → totalAssets() changes between transactions
- Arithmetic: shares = (assets * totalSupply) / totalAssets — rounds DOWN (correct per ERC-4626)

**Risk Level**: CRITICAL
**Attack surface**: First depositor inflation attack — deposit 1 wei, donate 10K tokens,
next depositor gets 0 shares. Also: ERC-777 reentrancy if no guard.
**Notes**: Missing virtual offset (decimalsOffset_) makes this vulnerable to inflation
attack. Recommend OpenZeppelin v5 ERC4626 which adds virtual shares/assets.
```

---

## Example 3: Governance Execute

```
### Governor.execute(uint256 proposalId)

**Basics**
- Visibility: external
- Access: unrestricted (anyone can execute queued proposal)
- Modifiers: none
- Payable: YES (proposals may contain ETH transfers)

**State Changes**
- Reads: proposals[proposalId] (target, value, calldata, eta)
- Writes: proposals[proposalId].executed = true

**External Interactions**
- Calls: target.call{value: value}(calldata) for each action in proposal
- Transfers: ETH from Governor to targets (if value > 0)
- Callbacks: depends entirely on proposal actions

**Events**
- ProposalExecuted(proposalId)

**Control Flow**
- CEI Compliance: PARTIAL — marks executed before calls in some impls, after in others
- Revert conditions:
  - proposal not in queued state → revert
  - timelock not elapsed (block.timestamp < eta) → revert
  - grace period exceeded → revert
  - any action call fails → revert (atomic execution)
- Branches: loops through proposal.actions[]

**Security Analysis**
- Reentrancy risk: HIGH — arbitrary external calls to unknown targets
- Input validation: proposalId must exist and be in QUEUED state
- Edge cases:
  - Proposal with 0 actions → succeeds (marks executed, does nothing)
  - Proposal targeting Governor itself → self-modifying governance
  - ETH in proposal but Governor has insufficient balance → revert mid-execution
  - Proposal action calls selfdestruct → destroys target contract
- Arithmetic: none

**Risk Level**: CRITICAL
**Attack surface**: Malicious proposal can execute arbitrary code. Governance attack
via flash-loan voting. Re-entrancy during execution to submit new proposal.
**Notes**: Execute should be guarded against re-entrancy. Verify timelock enforces
minimum delay. Check that canceled proposals can't be executed. Verify quorum
requirements are reasonable relative to circulating supply.
```

---

## Analysis Priority Order

Analyze functions in this order (highest risk first):

| Priority | Function Type | Why |
|----------|--------------|-----|
| 1 | Functions that transfer tokens/ETH | Direct value at risk |
| 2 | Functions that modify access control | Can escalate to Priority 1 |
| 3 | Functions that use oracle data | Price manipulation → fund theft |
| 4 | Functions that modify protocol parameters | Can break invariants |
| 5 | Functions with complex state changes | Logic errors hide here |
| 6 | Initialization / constructor | Deployment ordering attacks |
| 7 | View / pure functions | Lowest risk, but check used correctly |
