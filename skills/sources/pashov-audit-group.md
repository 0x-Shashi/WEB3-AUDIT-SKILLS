# Pashov Audit Group - Audit Findings

## Overview

**Total Findings**: 3,452 (6.83% of database)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 557 | 907 | 1976 | 12 |

## Common Vulnerability Types

| Vulnerability | Count |
|--------------|-------|
| Fee On Transfer | 5 |
| Business Logic | 5 |
| Sandwich Attack | 4 |
| Missing Check | 4 |
| ERC20 | 2 |
| Auction | 2 |
| Gas Limit | 2 |
| Access Control | 2 |
| DOS | 2 |
| Liquidation | 2 |

---

## Notable Findings

### 1. [H-01] Incorrect vesting interest calculation enables MEV attacks

**Protocol**: LoopVaults_2025-04-30 | **Impact**: HIGH

## Severity

**Impact:** Medium

**Likelihood:** High

## Description

Given that the value of the positions is updated only when `updateInterval` time has passed, the interest is vested to prevent MEV attacks.

However, the implementation of `_vestingInterest()` is incorrect, as it returns 0 when `block.timestamp == lastUpdate` and increases linearly until `vestingDuration` is reached. This means that calling `totalAssets()` just after an update will include all the interest accrued, which makes the update subject to MEV attacks.

```solidity
    function totalAssets() public view override re...

---

### 2. [H-01] Incorrect basket USD value will cause incorrect results

**Protocol**: Cove_2024-12-30 | **Impact**: HIGH

## Severity

**Impact:** Medium

**Likelihood:** High

## Description

Upon proposing a token swap, we have the following sequence of function calls:

```solidity
uint256[] memory totalValues = new uint256[](numBaskets);
// 2d array of asset balances for each basket
uint256[][] memory basketBalances = new uint256[][](numBaskets);
_initializeBasketData(self, baskets, basketAssets, basketBalances, totalValues);
// NOTE: for rebalance retries the internal trades must be updated as well
_processInternalTrades(self, internalTrades, baskets, basketBalances);
_validateExternalTrades(self, externalTra...

---

### 3. [C-03] Unrestricted `diamondCut` allows unauthorized facet modifications

**Protocol**: Burve_2025-01-29 | **Impact**: HIGH

## Severity

**Impact:** High

**Likelihood:** High

## Description

## Description

The `SimplexDiamond` contract includes `DiamondCutFacet.diamondCut.selector` in its selectors. This function allows adding, removing, or modifying facet cuts, which determine the contract’s functionality. However, **this function is not restricted**, meaning **anyone** can call it to remove or replace any selector or facet.

### **Proof of Concept (PoC)**

The test case below demonstrates how a random user can call `diamondCut` to remove or modify contract functionality, potentially leading to loss of control ...

---

### 4. [H-02] Stale `totalActiveDebt` used in `openTrove` causing incorrect debt update

**Protocol**: Roots_2025-02-09 | **Impact**: HIGH

## Severity

**Impact:** Medium

**Likelihood:** High

## Description

In the `TroveManager::openTrove` function, the `totalActiveDebt` is cached into a local variable `supply` before the `_accrueActiveInterests` function is called. The `_accrueActiveInterests` function itself updates the `totalActiveDebt` to reflect accrued interest. However, the `openTrove` function subsequently updates `totalActiveDebt` using the cached `supply` value instead of the potentially updated `totalActiveDebt`.

Specifically, the code caches `totalActiveDebt` in line 754:

```solidity
File: TroveManager.sol
754:  ...

---

### 5. [H-01] `_swap()` is vulnerable to sandwich attacks

**Protocol**: Gacha_2025-01-27 | **Impact**: HIGH

## Severity

**Impact:** High

**Likelihood:** High

## Description

Anyone can buy a ticket from a specified pool, a certain payment token will be used to swap for meme tokens. The swapping process is implemented as below:

```solidity
    function _swap(
        address token,
        uint256 cost
    ) private returns (uint256 actualTokens) {
        Storage storage $ = _getOwnStorage();
        IUniswapV2Router01 uni = IUniswapV2Router01($.uniswapRouter);
        IUniswapV2Factory factory = IUniswapV2Factory($.uniswapFactory);

        address pair = factory.getPair($.paymentToken, token);...

---

### 6. [H-03] `activeValidatorCount` is never set or increased

**Protocol**: Karak-June | **Impact**: HIGH

## Severity

**Impact:** Medium

**Likelihood:** High

## Description

In the `NativeVault` contract `Storage.ownerToNode[nodeOwner].activeValidatorCount` keeps track of the total validators with withdrawal credentials pointed to a specific node.

This value is decreased in `NativeVaultLib.validateSnapshotProof` when the balance of a validator in the Beacon Chain is zero.

```solidity
File: NativeVaultLib.sol

        if (newBalanceWei == 0) {
@>          self.ownerToNode[nodeOwner].activeValidatorCount--;
            validatorDetails.status = ValidatorStatus.WITHDRAWN;

            emit Valid...

---

### 7. [C-01] Decreasing position size via leverage update can be abused to steal from diamond

**Protocol**: Gainsnetwork May | **Impact**: HIGH

**Severity**

**Impact:** High

**Likelihood:** High

**Description**

The trader can decrease position size using leverage update, which will then realize the partial profit/loss based on position size delta.

However, in the case of a profit, `handleTradePnl()` will incorrectly send the closing fees to the trader instead of the vault. This allows the trader to receive more profit than expected by stealing from the diamond. Over time, this will slowly drain the diamond as the closing fees are still distributed despite not receiving it.

Suppose the trader has the following position,

- existi...

---

### 8. [H-01] Payers exploit `reentrantSettle` to bypass payments with self-transfers

**Protocol**: Itos_2025-05-24 | **Impact**: HIGH

## Severity

**Impact:** High

**Likelihood:** Medium

## Description

The `reentrantSettle` function in RFTLib contains a vulnerability that allows malicious contracts to implement the `IRFTPayer` interface to completely avoid payment obligations. The vulnerability is from how the function tracks cumulative balance changes (`transact.delta`) across nested calls.

When a contract requests tokens using `reentrantSettle`, the function:
- Records the expected balance change in `transact.delta[token]`.
- Calls the payer's `tokenRequestCB` if they implement `IRFTPayer`.
- Validates final balances a...

---

### 9. [H-01] Stakers may fail to claim all incentives

**Protocol**: Ouroboros_2025-06-30 | **Impact**: HIGH

_Resolved_

## Severity

**Impact:** High

**Likelihood:** Medium

## Description

In UniswapV3Staker, the owner can create one incentive. There is one kind of incentive that we have a fixed tick range position. LP holders can earn some incentives on condition that their position's range should match this fixed range. According to the readme, the common use is `full-range positions(-887220 - 887220)`.

In Uniswap v3, most traders will not choose the full range liquidity. Because full range liquidity will have very low liquidity efficiency.

As one LP holder, the possible profit with this v3 st...

---

### 10. [H-01] Last NFT from the supply can't be minted

**Protocol**: Museumofmahomes | **Impact**: HIGH

**Severity**

**Impact:**
Medium, as only one NFT won't be available for minting, but this is value loss to the protocol

**Likelihood:**
High, as it's impossible to mint the last NFT

**Description**

Currently both the `mint` and `mintPhysical` methods have the following check:

```solidity
if (nextId + amount >= MAX_SUPPLY) revert ExceedsMaxSupply();
```

This is incorrect, as even when the `nextId` is `MAX_SUPPLY - 1` then an `amount` of 1 should be allowed but with the current check the code will revert. This is due to the `equal` sign in the check, which shouldn't be there. Here is a Pro...

---

### 11. [H-01] Incorrect assembly packing in `getNamespace` causes collisions

**Protocol**: Biconomy_2025-11-26 | **Impact**: HIGH

_Resolved_

## Severity

**Impact:** High  

**Likelihood:** Medium

## Description

The `getNamespace` function contains incorrect assembly code that can lead to namespace collisions due to improper memory packing.

```solidity
function getNamespace(address account, address _caller) public pure returns (bytes32 result) {
    assembly {
        mstore(0x00, account)
        mstore(0x14, _caller)
        result := keccak256(0x0c, 0x28)
    }
}
```

**Memory Layout Analysis:**

`mstore(0x00, account)` writes 32 bytes:

- Positions 0x00-0x0b: 12 zero bytes (padding).
- Positions 0x0c-0x1f: 20 byt...

---

### 12. [H-02] `claim_revenue` lets admin block user withdrawals below min threshold

**Protocol**: DesciLaunchpad_2025-02-07 | **Impact**: HIGH

## Severity

**Impact:** High

**Likelihood:** Medium

## Description

The `claim_revenue` function should not be executable if the revenue falls below the `min_threshold`. In this case, users are allowed to reclaim their payment tokens after the sale duration ends. However, if the admin calls the `claim_revenue` function immediately after the sale ends, users will no longer be able to withdraw their payment tokens via `withdraw_token`.

The `withdraw_token` function requires the revenue to be less than `min_threshold` to enable withdrawals, as shown in the code snippet below:

```rust
pub fn ...

---

### 13. [H-04] Traders could lose assets when increasing counter trade position size

**Protocol**: GainsNetwork_2025-05-26 | **Impact**: HIGH

## Severity

**Impact:** High

**Likelihood:** Medium

## Description

When users request an increase in position size, it will eventually be executed, triggering `executeIncreasePositionSizeMarket`.

```solidity
    function executeIncreasePositionSizeMarket(
        ITradingStorage.PendingOrder memory _order,
        ITradingCallbacks.AggregatorAnswer memory _answer
    ) external {
        // 1. Prepare vars
        ITradingStorage.Trade memory partialTrade = _order.trade;
        ITradingStorage.Trade memory existingTrade = _getMultiCollatDiamond().getTrade(
            partialTrade.user,
...

---

### 14. [H-02] `newLeverage` wrongly calculated inside `requestIncreasePositionSize`

**Protocol**: Gainsnetwork May | **Impact**: HIGH

**Severity**

**Impact:** High

**Likelihood:** Medium

**Description**

When users call `increasePositionSize` and request an increase in position size, it will eventually trigger `IncreasePositionSizeUtils.validateRequest` to validate the request. However, when calculating `newLeverage`, it incorrectly calculates `(existingPositionSizeCollateral + positionSizeCollateralDelta * 1e3) / newCollateralAmount` instead of `(existingPositionSizeCollateral + positionSizeCollateralDelta) * 1e3 / newCollateralAmount`, causing the `newLeverage` to be lower than it should be.

```solidity
    function va...

---

### 15. [H-01] Deprecated `safeApprove()` usage blocks collateral approval to pool

**Protocol**: Hyperlend_2025-11-21 | **Impact**: HIGH

_Resolved_

## Severity

**Impact:** Medium

**Likelihood:** High

## Description

Project uses Openzeppelin@v4.9.6, which deprecates `safeApprove()`. Safe approve usage is not safe here because it blocks every approval if approval for the collateral is non-zero:

```solidity
//    function executeOperation()

        for (uint256 i = 0; i < _collateralActions.length; ++i){
            uint256 amount = _collateralActions[i].amount;
            IERC20 token = _collateralActions[i].token;

            //transfer tokens from the caller & approve pool contract to spend them
            token.safeT...

---


## Statistics

- Total findings from Pashov Audit Group: 3,452
- Last updated: 2026-01-29
