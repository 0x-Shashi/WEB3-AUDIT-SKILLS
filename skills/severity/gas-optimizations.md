---
id: SEV-GAS-OPTIMIZATIONS
title: Gas Optimization Findings
category: severity
severity_level: gas
triggers:
  - gas optimization examples
  - gas finding reference
  - gas vs low
  - is this a gas issue
related_skills:
  - scoring/AUDIT_SCORING.md
  - patterns/severity-scoring.md
  - severity/low-severity.md
  - methodology/gas-optimization-security.md
  - methodology/audit-report-templates.md
tags:
  - severity
  - gas
  - optimization
  - findings
  - classification
last_updated: 2026-01-31
---
# GAS Severity Findings

## Overview

**Total Findings**: 3,422 (6.77% of all findings)

## Top Vulnerability Types at GAS Severity

| Rank | Vulnerability Type | Count |
|------|-------------------|-------|
| 1 | Event | 1 |
| 2 | Code Quality | 1 |

---

## Representative Examples

### 1. Remove loop when sending actions

- **Source**: Cyfrin
- **Protocol**: D2 Hype Corewriter
- **Tags**: None

**Description:** `Hype_Module::sendAction` manually allocates and copies a 4-byte header plus payload in a loop. Use packed encoding to avoid the loop and shrink bytecode, e.g.:

```solidity
bytes memory data = abi.encodePacked(bytes4(uint32(0x01000000) | uint32(actionIndex)), action);
```

This builds the prefix + payload in one go with lower gas and less code.

**D2:** Fixed in commit [`c5d3193`](https://github.com/d2sd2s/d2-contracts/commit/c5d319387671e889e1d1c6aaf5097b5653af6809)

**Cyfrin:** Verified.

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-10-16-cyfrin-d2-hype-corewriter-v2.0.md)

---

### 2. Unnecessarily complex iteration logic in `MetaVault::redeemMetaVaults` can be simplified

- **Source**: Cyfrin
- **Protocol**: Strata
- **Tags**: None

**Description:** `MetaVault::redeemMetaVaults` is currently implemented as a while loop, indexing the first array element and calling `MetaVault::removeVaultAndRedeemInner` which implements a "replace-and-pop" solution for removing elements from the `assetsArr` array:

```solidity
    function removeVaultAndRedeemInner (address vaultAddress) internal {
        // Redeem
        uint balance = IERC20(vaultAddress).balanceOf(address(this));
        if (balance > 0) {
            IERC4626(vaultAddress).redeem(balance, address(this), address(this));
        }

        // Clean
        TAsset memory emptyAsset;
        assetsMap[vaultAddress] = emptyAsset;
        uint length = assetsArr.length;
        for (uint i = 0; i < length; i++) {
            if (assetsArr[i].asset == vaultAddress) {
@>...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-06-11-cyfrin-strata-v2.1.md)

---

### 3. Remove redundant timestamp check in `Bet::resolve`

- **Source**: Cyfrin
- **Protocol**: Wannabet
- **Tags**: None

**Description:** `Bet::resolve` has this revert check:
```solidity
// Make sure the bet is active
if (_status(b) != IBet.Status.ACTIVE || block.timestamp > b.resolveBy) {
    revert InvalidStatus();
}
```

But the call to `_status(b)` already checks `block.timestamp > b.resolveBy` and returns `EXPIRED` status which triggers the revert, so having the same timestamp check here again is redundant.

**WannaBet:** Fixed in commit [45afa44](https://github.com/gskril/wannabet-v2/commit/45afa44a0adf423a2c2775c22d9f99e0ce555bbc).

**Cyfrin:** Verified.

\clearpage

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-12-24-cyfrin-wannabetv2-v2.0.md)

---

### 4. Use `type(uint256).max` when withdrawing from Aave

- **Source**: Cyfrin
- **Protocol**: Wannabet
- **Tags**: None

**Description:** When unwinding Aave positions in `Bet::resolve` and `cancel`, the contract withdraws using the current aToken balance as the `amount` parameter:
```solidity
uint256 aTokenBalance = IERC20(_aavePool.getReserveAToken(b.asset))
    .balanceOf(address(this));
_aavePool.withdraw(b.asset, aTokenBalance, address(this));
```

Aaves [recommended pattern](https://aave.com/docs/aave-v3/smart-contracts/pool?utm_source=chatgpt.com#write-methods-withdraw) for fully closing a position is to pass `type(uint256).max`, which is more robust against rounding/indexing edge cases. This also removes one external call as `withdraw` returns the amount withdrawn:
```solidity
uint256 aTokenBalance = _aavePool.withdraw(b.asset, type(uint256).max, address(this));
```

**WannaBet:** Fixed in commit [b...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-12-24-cyfrin-wannabetv2-v2.0.md)

---

### 5. Refactor away unnecessary local variables in `SecuritizeAmmNavProvider::_curveBuy, _curveSell`

- **Source**: Cyfrin
- **Protocol**: Securitize Public Stock Ramp
- **Tags**: None

**Description:** In `SecuritizeAmmNavProvider::_curveBuy, _curveSell` the local variables `X, Y, kLocal` are only read once so there is no need to use them to cache storage, just read the storage slots directly when required:
```solidity
function _curveBuy(uint256 amountInQuote) internal view initialized returns (uint256 curvePriceWad, uint256 newBase, uint256 newQuote) {
    require(amountInQuote > 0, "amountInQuote=0");

    newQuote = quoteReserves + amountInQuote;
    newBase = k / newQuote;

    uint256 deltaBase = baseReserves - newBase;
    require(deltaBase > 0, "deltaBase=0");

    curvePriceWad = (amountInQuote * WAD) / deltaBase;
}

function _curveSell(uint256 amountInBase) internal view initialized returns (uint256 curvePriceWad, uint256 newBase, uint256 newQuote) {
    require...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-12-24-cyfrin-securitize-public-stock-ramp-v2.0.md)

---

### 6. Refactor `PublicStockOnRamp::initializedNavProvider`, `BaseOffRamp::nonZeroLiquidityProvider` into internal functions to prevent identical storage reads

- **Source**: Cyfrin
- **Protocol**: Securitize Public Stock Ramp
- **Tags**: None

**Description:** `PublicStockOnRamp` has a modifier `initializedNavProvider` that reads the `navProvider` storage slot, but then later on in the functions which have this modifier (`swap, calculateDsTokenAmount`), the `navProvider` storage slot is read again even though its value has not changed.

**Impact:** Storage reads are expensive; we want to avoid reading the same storage slot multiple times when the value hasn't changed.

**Recommended Mitigation:** Refactor the modifier `initializedNavProvider` into an `internal` function:
```solidity
    function _getNavProviderStrict() internal returns(address navProviderAddr) {
        navProviderAddr = address(navProvider);
        if (navProviderAddr == address(0)) revert NavProviderNotSetError();
    }
```

Then call this internal function i...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-12-24-cyfrin-securitize-public-stock-ramp-v2.0.md)

---

### 7. Fee calculation occurs twice

- **Source**: Cyfrin
- **Protocol**: Securitize Public Stock Ramp
- **Tags**: None

**Description:** `SecuritizeOnRamp::subscribe, swap` calls `calculateDsTokenAmount` which performs an external call to calculate the fee:
```solidity
function calculateDsTokenAmount(uint256 _liquidityAmount) public view returns (uint256 dsTokenAmount, uint256 rate, uint256 fee) {
    fee = feeManager.getFee(_liquidityAmount);
    uint256 liquidityAmountExcludingFee = _liquidityAmount - fee;
```

Subsequently `BaseOnRamp::_executeLiquidityTransfer` is called which does it again:
```solidity
uint256 fee = feeManager.getFee(amount);
if (fee > 0) {
    liquidityToken.transfer(feeManager.feeCollector(), fee);
}
```

**Impact:** Duplicate storage reads of `feeManager` and duplicate external calls.

**Recommended Mitigation:** Calculate the fee once in top-level functions then pass it to child fu...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-12-24-cyfrin-securitize-public-stock-ramp-v2.0.md)

---

### 8. Use of modifier `nonZeroNavRate` in `SecuritizeOnRamp` and `SecuritizeOffRamp` results in duplicate external call with identical result

- **Source**: Cyfrin
- **Protocol**: Securitize Public Stock Ramp
- **Tags**: None

**Description:** `SecuritizeOnRamp` and `SecuritizeOffRamp` both have modifier `nonZeroNavRate` which makes an external call to enforce a positive rate:
```solidity
modifier nonZeroNavRate() {
    if (navProvider.rate() <= 0) {
        revert NonZeroNavRateError();
    }
    _;
}
```

The problem is that the functions which use this modifier (such as `swap`) subsequently call a child function (such as `calculateDsTokenAmount`) which ends up making the same `navProvider.rate` external call again.

**Impact:** The same external call is made twice in each affected transaction, even though the answer between calls can't change.

**Recommended Mitigation:** Convert the modifier into an internal function which does the revert check and returns the rate, the pass the cached rate to any child func...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-12-24-cyfrin-securitize-public-stock-ramp-v2.0.md)

---

### 9. Cache decimals of underlying asset at initialization in `SecuritizeAmmNavProvider`

- **Source**: Cyfrin
- **Protocol**: Securitize Public Stock Ramp
- **Tags**: None

**Description:** `SecuritizeAmmNavProvider` has no function to change the value of `asset` after initialization. Since ERC20 tokens typically never changed their decimals, the asset decimals can be cached at initialization to save external calls in `quoteBuyBase, quoteSellBase, executeBuyBase, executeSellBase`.

Since the decimals are only used to calculate `scaleDown`, can just cache this eg:

```diff
contract SecuritizeAmmNavProvider {
    /* snip : existing storage layout */
+   uint256 public SCALE_DOWN;

    function initialize(uint256 _baseReserves, uint256 _quoteReserves, address _asset) public onlyProxy initializer {
        /* snip : existing code */
        asset = IERC20Metadata(_asset);
+       uint8 d = asset.decimals();
+       require(d <= 18, "decimals > 18");
+       SCALE...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-12-24-cyfrin-securitize-public-stock-ramp-v2.0.md)

---

### 10. In Solidity don't initialize to default values

- **Source**: Cyfrin
- **Protocol**: Securitize Public Stock Ramp
- **Tags**: None

**Description:** In Solidity don't initialize to default values:
```solidity
SecuritizeAmmNavProvider.sol
380:        bool shouldReset = false;

off-ramp/BaseOffRamp.sol
124:        for (uint256 i = 0; i < _countries.length; i++) {
```

**Securitize:** Fixed in commits [7594671](https://bitbucket.org/securitize_dev/bc-nav-provider-sc/commits/75946718b5129603545c364a2d9c6f57902200d9), [6833173](https://github.com/securitize-io/bc-on-off-ramp-sc/commit/68331735079e5964e636c6f139e44649c7903483).

**Cyfrin:** Verified.

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-12-24-cyfrin-securitize-public-stock-ramp-v2.0.md)

---

### 11. When emitting events don't read known values from storage

- **Source**: Cyfrin
- **Protocol**: Securitize Public Stock Ramp
- **Tags**: None

**Description:** When emitting events don't read known values from storage; for example in `SecuritizeAmmNavProvider::_resetBaseline`:
```diff
    function _resetBaseline(uint256 newBase, uint256 newQuote) internal {
        require(newBase > 0, "newBase=0");
        require(newQuote > 0, "newQuote=0");

        baseReserves = newBase;
        quoteReserves = newQuote;

        baseBaseline = newBase;
        quoteBaseline = newQuote;

        k = newBase * newQuote;

-       emit BaselineReset(baseBaseline, quoteBaseline);
+       emit BaselineReset(newBase, newQuote);
    }
```

Similar optimizations can be made in:
* `AllowanceLiquidityProvider::setAllowanceProviderWallet`
* `CollateralLiquidityProvider::setExternalCollateralRedemption, setCollateralProvider`
* `BaseOffRamp::updateLiqui...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-12-24-cyfrin-securitize-public-stock-ramp-v2.0.md)

---

### 12. Emit events first to refactor away local variables storing previous values

- **Source**: Cyfrin
- **Protocol**: Securitize Public Stock Ramp
- **Tags**: None

**Description:** When values are being changed, emit events first to refactor away local variables storing previous values. For example in `SecuritizeAmmNavProvider::setPriceScaleFactor`:
```diff
    function setPriceScaleFactor(uint256 newScaleFactor) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newScaleFactor > 0, "scaleFactor = 0");

-       uint256 oldScaleFactor = priceScaleFactor;
+       emit PriceScaleFactorUpdated(priceScaleFactor, newScaleFactor);
        priceScaleFactor = newScaleFactor;

-       emit PriceScaleFactorUpdated(oldScaleFactor, newScaleFactor);
    }
```

Similar optimizations can be made in:
* `SecuritizeInternalNavProvider::setRate`
* `MbpsFeeManager::setFeePercentageMBPS, setFeeCollector`
* `AllowanceLiquidityProvider::setAllowanceProviderWallet`
* `C...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-12-24-cyfrin-securitize-public-stock-ramp-v2.0.md)

---

### 13. `BLS12381::hashToG1` can use constants for DST

- **Source**: Cyfrin
- **Protocol**: Symbiotic Bls
- **Tags**: None

**Description:** In `BLS12381::hashToG1`, the Domain Separation Tag (DST) string is passed as an inline string literal to `expandMsg`, causing unnecessary memory allocation on every call.

```solidity
function hashToG1(bytes memory message) internal view returns (G1Point memory result) {
    bytes memory uniform_bytes = expandMsg("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_", message, 0x80);
```
https://github.com/symbioticfi/relay-contracts/blob/main/src/libraries/utils/BLS12381.sol#L287

At runtime, this:
1. Allocates 43 bytes in memory for the string
2. Copies the string literal from bytecode to memory
3. Incurs memory expansion costs
4. Passes a memory pointer to `expandMsg`

**Impact:** Gas is wasted on every `hashToG1` call. Since BLS signature verification is a common operation, thi...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-12-03-cyfrin-symbiotic-bls12381-v2.0.md)

---

### 14. Optimize setters by emitting event before state updates

- **Source**: Cyfrin
- **Protocol**: Sherpa
- **Tags**: None

**Description:** Functions `SherpaUSD::setKeeper`, `SherpaUSD::setOperator`, `SherpaUSD::setAutoTransfer` and `SherpaVault::setDepositsEnabled`, `SherpaVault::setStableWrapper` create an unnecessary memory variable to store old values used for event emissions. However, this is not required if the event is emitted first.

For example, function setKeeper can be optimized in the following manner:

```solidity
function setKeeper(address _keeper) external onlyOwner {
    if (_keeper == address(0)) revert AddressMustBeNonZero();
    emit KeeperSet(keeper, _keeper);
    keeper = _keeper;
}
```

**Recommended Mitigation:** Consider removing the memory variables by emitting events first.

**Sherpa:** Fixed in commit [`7e34a6b`](https://github.com/hedgemonyxyz/sherpa-vault-smartcontracts/commit/7e34...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-11-23-cyfrin-sherpa-v2.0.md)

---

### 15. Duplicated validation in `DistributionManager::initialize` can be removed

- **Source**: Cyfrin
- **Protocol**: Benqi Governance
- **Tags**: None

**Description:** `DistributionManager::initialize` will revert if the `_initialBudgetAllocator` is equal to `address(0)`; however, this logic is not necessary as it is duplicated and already present in `_setBudgetAllocator()`.

```solidity
function initialize(
    ...
    IBudgetAllocator _initialBudgetAllocator,
    ...
) external initializer {
    if (address(_initialBudgetAllocator) == address(0))
        revert InvalidAddress("budgetAllocator");
    ...
    _setBudgetAllocator(_initialBudgetAllocator);
    ...
}

function _setBudgetAllocator(IBudgetAllocator _budgetAllocator) internal {
    if (address(_budgetAllocator) == address(0)) revert InvalidAddress("budgetAllocator");
    ...
}
```

**BENQI:** Fixed in PR [\#38](https://github.com/aragon/benqi-governance/pull/38).

**Cyfrin:** ...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-11-10-cyfrin-benqi-governance-v2.0.md)

---

### 16. Avoid return statements with named return variables

- **Source**: Cyfrin
- **Protocol**: Benqi Governance
- **Tags**: None

**Description:** When declaring named return variables such as in `GaugeRegistrar::registerGauge`, it is not necessary to explicitly execute the return statement and this can be removed to save gas.

**Recommended Mitigation:**
```diff
function registerGauge(
    address _qiToken,
    Incentive _incentive,
    address _rewardController,
    string calldata _metadataURI
) external auth(GAUGE_REGISTRAR_ROLE) returns (address gaugeAddress) {
    ...
    // Emit event
    emit GaugeRegistered(gaugeAddress, _qiToken, _incentive, _rewardController);
-
-   return gaugeAddress;
}
```

**BENQI:** Acknowledged.

**Cyfrin:** Acknowledged.

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-11-10-cyfrin-benqi-governance-v2.0.md)

---

### 17. `SpeedCalculator::calcSpeed` should return early if `_moduleBudget` is zero

- **Source**: Cyfrin
- **Protocol**: Benqi Governance
- **Tags**: None

**Description:** `SpeedCalculator::calcSpeed` currently short circuits if any of the `_totalVotes`, `_epochDuration`, or `_votes` parameters are zero. This is beneficial as it avoids wasting gas on unnecessary computation; however, this validation should also include the `_moduleBudget` as multiplication by zero would similarly result in zero being returned.

**Recommended Mitigation:**
```diff
function calcSpeed(
    uint256 _votes,
    uint256 _totalVotes,
    uint256 _moduleBudget,
    uint256 _epochDuration
) public pure returns (uint256) {
-   if (_totalVotes == 0 || _epochDuration == 0 || _votes == 0) return 0;
+   if (_totalVotes == 0 || _epochDuration == 0 || _votes == 0 || _moduleBudget == 0) return 0;

    return
        (_moduleBudget * SPEED_PRECISION * _votes) /
        (_epoc...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-11-10-cyfrin-benqi-governance-v2.0.md)

---

### 18. Avoid initializing variables to default values

- **Source**: Cyfrin
- **Protocol**: Benqi Governance
- **Tags**: None

**Description:** There are a number of instances throughout the in-scope contracts where variables are unnecessarily intiialized to default values. For example, consider the following `grep` commands that show the most common scenarios in which this occurs:

```bash
grep -E 'uint.+ *= *0;' -R --include="*.sol" --exclude-dir=lib .
grep -E 'bool.+ *= *false;' -R --include="*.sol" --exclude-dir=lib .
```

**Recommended Mitigation:** Avoid initializing variables to default values to save gas.

**BENQI:** Acknowledged.

**Cyfrin:** Acknowledged.

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-11-10-cyfrin-benqi-governance-v2.0.md)

---

### 19. Inline small `private` functions only called once

- **Source**: Cyfrin
- **Protocol**: Securitize Global Registry
- **Tags**: None

**Description:** `StandardToken::_updateName`  and `_updateSymbol` are very small `private` functions that are only ever called once by `updateNameAndSymbol`.

Hence it is more gas efficient to inline them; here is an implementation that also caches the identical storage reads so `name` and `symbol` are only read once from storage:
```solidity
function updateNameAndSymbol(string calldata _name, string calldata _symbol) external onlyMaster {
    require(!CommonUtils.isEmptyString(_name), "Name cannot be empty");
    require(!CommonUtils.isEmptyString(_symbol), "Symbol cannot be empty");

    string memory nameCache = name;
    if (!CommonUtils.isEqualString(_name, nameCache)) {
        emit NameUpdated(nameCache, _name);
        name = _name;
    }

    string memory symbolCache = symbol;
 ...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-11-06-cyfrin-securitize-global-registry-v2.0.md)

---

### 20. Unnecessary ETH to WETH conversion during swap

- **Source**: Cyfrin
- **Protocol**: Linea Burn
- **Tags**: None

**Description:** In the V3DexSwap contract, ETH is converted to WETH before processing the swap through the router as seen in the snippet below.

```solidity
IWETH9(WETH_TOKEN).deposit{ value: msg.value }();
IWETH9(WETH_TOKEN).approve(ROUTER, msg.value);
```

However, this is not required since the router supports direct ETH to Linea swaps. As we can observe below, the exactInputSingle function is marked as payable to allow direct ETH transfers when the function is called. In the router's execution path when the uniswapV3SwapCallback() calls the pay() function, it would process the router's contract balance if the token is WETH.

```solidity
File: SwapRouter.sol

/// @inheritdoc ISwapRouter
    function exactInputSingle(
        ExactInputSingleParams calldata params
    ) external payable...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-11-03-cyfrin-linea-burn-v2.2.md)

---

### 21. Storage read optimizations

- **Source**: Cyfrin
- **Protocol**: Accountable
- **Tags**: None

**Description:**
1. [`AccountableOpenTerm::_calculateRequiredLiquidity`](https://github.com/Accountable-Protocol/audit-2025-09-accountable/blob/fc43546fe67183235c0725f6214ee2b876b1aac6/src/strategies/AccountableOpenTerm.sol#L642-L655): `vault` and `_scaleFactor` can be cached. Also consider changing so that `_calculateRequiredLiquidity` takes `address vault_` as a parameter. That would allow to cache the   `vault` read in the [`_isDelinquent`](https://github.com/Accountable-Protocol/audit-2025-09-accountable/blob/fc43546fe67183235c0725f6214ee2b876b1aac6/src/strategies/AccountableOpenTerm.sol#L492-L497), [`_getAvailableLiquidity`](https://github.com/Accountable-Protocol/audit-2025-09-accountable/blob/fc43546fe67183235c0725f6214ee2b876b1aac6/src/strategies/AccountableOpenTerm.sol#L658-L663),...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-10-16-cyfrin-accountable-v2.0.md)

---

### 22. Remove return value from `DSToken::updateInvestorBalance` as it is never checked

- **Source**: Cyfrin
- **Protocol**: Securitize Dstoken Rebasing
- **Tags**: None

**Description:** `DSToken::updateInvestorBalance` is an `internal` function which returns `bool` but this return value is never checked anywhere; remove it:
```solidity
token/DSToken.sol
304:        updateInvestorBalance(_from, _value, CommonUtils.IncDec.Decrease);
305:        updateInvestorBalance(_to, _value, CommonUtils.IncDec.Increase);
308:    function updateInvestorBalance(address _wallet, uint256 _value, CommonUtils.IncDec _increase) internal override returns (bool) {

mocks/StandardTokenMock.sol
72:    function updateInvestorBalance(address, uint256, CommonUtils.IncDec) internal pure override returns (bool) {

token/TokenLibrary.sol
94:        updateInvestorBalance(_tokenData, IDSRegistryService(_services[REGISTRY_SERVICE]), _params._to, shares, CommonUtils.IncDec.Increase);
129:  ...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-10-10-cyfrin-securitize-dstoken-rebasing-v2.1.md)

---

### 23. `ComplianceServiceRegulated::getComplianceTransferableTokens` should call `IDSLockManager::getTransferableTokensForInvestor`

- **Source**: Cyfrin
- **Protocol**: Securitize Dstoken Rebasing
- **Tags**: None

**Description:** `ComplianceServiceRegulated::getComplianceTransferableTokens` already loads the registry and fetches the investor id, so therefore it should call `IDSLockManager::getTransferableTokensForInvestor` instead of `getTransferableTokens` to save again loading the registry and again fetching the investor id:
```diff
    function getComplianceTransferableTokens(
        address _who,
        uint256 _time,
        uint64 _lockTime
    ) public view override returns (uint256) {
        require(_time != 0, "Time must be greater than zero");
        string memory investor = getRegistryService().getInvestor(_who);

-       uint256 balanceOfInvestor = getLockManager().getTransferableTokens(_who, _time);
+       uint256 balanceOfInvestor = getLockManager().getTransferableTokensForInvest...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-10-10-cyfrin-securitize-dstoken-rebasing-v2.1.md)

---

### 24. Don't write to the same storage slot multiple times

- **Source**: Cyfrin
- **Protocol**: Securitize Dstoken Rebasing
- **Tags**: None

**Description:** In EVM writing to storage is expensive; ideally only write to the same storage slot once. For example `ComplianceServiceRegulated::cleanupInvestorIssuances` does this:
```solidity
        uint256 time = block.timestamp;

        uint256 currentIssuancesCount = issuancesCounters[investor];
        uint256 currentIndex = 0;

        if (currentIssuancesCount == 0) {
            return;
        }

        while (currentIndex < currentIssuancesCount) {
            uint256 issuanceTimestamp = issuancesTimestamps[investor][currentIndex];

            bool isNoLongerLocked = issuanceTimestamp <= (time - lockTime);

            if (isNoLongerLocked) {
                if (currentIndex != currentIssuancesCount - 1) {
                    issuancesTimestamps[investor][currentIndex] = ...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-10-10-cyfrin-securitize-dstoken-rebasing-v2.1.md)

---

### 25. Not possible to send native via the `TransactionRelayer` to the target contract when executing `executeByInvestorWithBlockLimit`

- **Source**: Cyfrin
- **Protocol**: Securitize Dstoken Rebasing
- **Tags**: None

**Description:** `TransactionRelayer::executeByInvestorWithBlockLimit` makes an external call to a `destination` address, one of the input parameters of this function is `value`, which is encoded in `params[0]`, and this parameter is used to specify the amount of native balance that will be transferred to the `destination` address on the external call made in `doExecuteByInvestor`.

The problem is that the `TransactionRelayer::executeByInvestorWithBlockLimit` is not payable, which means that native can't be sent as part of the txn. Also, `TransactionRelayer` reverts when attempting to fund it by transferring native from one account to another.
```solidity
    function doExecuteByInvestor(
        ...
        uint256[] memory params
    ) private {
       ...
        bool success = false;
 ...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-10-10-cyfrin-securitize-dstoken-rebasing-v2.1.md)

---

### 26. Fast fail without performing unnecessary storage reads or external calls

- **Source**: Cyfrin
- **Protocol**: Securitize Dstoken Rebasing
- **Tags**: None

**Description:** Fast fail without performing unnecessary storage reads or external calls. For example in `ComplianceServiceRegulated::preIssuanceCheck` the start of the function looks like this:
```solidity
function preIssuanceCheck(
    address[] calldata _services,
    address _to,
    uint256 _value
) public view returns (uint256 code, string memory reason) {
    ComplianceServiceRegulated complianceService = ComplianceServiceRegulated(_services[COMPLIANCE_SERVICE]);
    IDSComplianceConfigurationService complianceConfigurationService = IDSComplianceConfigurationService(_services[COMPLIANCE_CONFIGURATION_SERVICE]);
    IDSWalletManager walletManager = IDSWalletManager(_services[WALLET_MANAGER]);
    string memory toCountry = IDSRegistryService(_services[REGISTRY_SERVICE]).getCountry(ID...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-10-10-cyfrin-securitize-dstoken-rebasing-v2.1.md)

---

### 27. Perform local variable checks first prior to external calls in composite `if` statement conditions

- **Source**: Cyfrin
- **Protocol**: Securitize Dstoken Rebasing
- **Tags**: None

**Description:** When an `if` statement condition is joined together using `&&` operators from multiple composite parts, local variable checks should be performed first prior to external calls. This is because if the local variable checks evaluate to `false` there is no need to then perform the external calls.

Three places where this occurs is in `ComplianceServiceRegulated::completeTransferCheck`:
```solidity
253:            if (IDSComplianceConfigurationService(
254:                   _services[COMPLIANCE_CONFIGURATION_SERVICE]).getForceFullTransfer() &&
255:                _args.fromInvestorBalance > _args.value
256:            ) {

272:            if (IDSComplianceConfigurationService(.
273:                   _services[COMPLIANCE_CONFIGURATION_SERVICE]).getWorldWideForceFullTransfer()...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-10-10-cyfrin-securitize-dstoken-rebasing-v2.1.md)

---

### 28. Return fast in `ComplianceServiceRegulated::checkHoldUp` if platform wallet

- **Source**: Cyfrin
- **Protocol**: Securitize Dstoken Rebasing
- **Tags**: None

**Description:** `ComplianceServiceRegulated::checkHoldUp` should return fast if `_isPlatformWalletFrom == true`; there's no reason to do all the processing in that case:
```solidity
    function checkHoldUp(
        address[] memory _services,
        address _from,
        uint256 _value,
        bool _isUSLockPeriod,
        bool _isPlatformWalletFrom
    ) internal view returns (bool hasHoldUp) {
        // platform wallets have no lock period so return false (default)
        // and skip all processing if it is a platform wallet
        if(!_isPlatformWalletFrom) {
            ComplianceServiceRegulated complianceService
                = ComplianceServiceRegulated(_services[COMPLIANCE_SERVICE]);
            uint256 lockPeriod;
            if (_isUSLockPeriod) {
                lockPe...

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-10-10-cyfrin-securitize-dstoken-rebasing-v2.1.md)

---

### 29. Cache computation results instead of repeatedly performing the same computation

- **Source**: Cyfrin
- **Protocol**: Securitize Dstoken Rebasing
- **Tags**: None

**Description:** Cache computation results instead of repeatedly performing the same computation.

* `contracts/utils/TransactionRelayer.sol`
```solidity
// cache `toBytes32(investorId)` in `setInvestorNonce`
142:        uint256 investorNonce = noncePerInvestor[toBytes32(investorId)];
144:        noncePerInvestor[toBytes32(investorId)] = newNonce;

// cache `toBytes32(senderInvestor)` in `doExecuteByInvestor`
175:                        noncePerInvestor[toBytes32(senderInvestor)],
178:                        keccak256(abi.encodePacked(senderInvestor)),
190:        noncePerInvestor[toBytes32(senderInvestor)]++;
```

**Securitize:** Acknowledged.

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-10-10-cyfrin-securitize-dstoken-rebasing-v2.1.md)

---

### 30. More efficient way of comparing two strings for equality in `CommonUtils::isEqualString`

- **Source**: Cyfrin
- **Protocol**: Securitize Dstoken Rebasing
- **Tags**: None

**Description:** More efficient way of comparing two strings for equality in `CommonUtils::isEqualString` [from](https://github.com/Vectorized/solady/blob/main/src/utils/g/LibString.sol#L858-L863) Solady:
```solidity
  function isEqualString(string memory a, string memory b) internal pure returns (bool result) {
      /// @solidity memory-safe-assembly
      assembly {
          result := eq(keccak256(add(a, 0x20), mload(a)), keccak256(add(b, 0x20), mload(b)))
      }
  }
```

**Securitize:** Acknowledged.

[View Full Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-10-10-cyfrin-securitize-dstoken-rebasing-v2.1.md)

---


## Statistics

- Total GAS findings: 3,422
- Examples shown: 30
- Last updated: 2026-01-29

---

## Scoring Integration

GAS findings carry **0 points** in the [Audit Scoring System](../scoring/AUDIT_SCORING.md) efficiency metric. They do not count toward Detection Score or Precision Score. However, they still contribute to audit quality:

- Demonstrates thoroughness (Coverage Score)
- Shows protocol understanding
- Gas findings must not introduce security regressions — see [Gas Optimization Security Tradeoffs](../methodology/gas-optimization-security.md)

> **Warning**: A gas optimization that introduces a vulnerability is a HIGH/CRITICAL finding, not a GAS finding. Always verify that suggested optimizations don't break security invariants.

## Related Files

- [Low Severity](low-severity.md) — Next severity level up
- [Audit Scoring System](../scoring/AUDIT_SCORING.md) — Composite scoring (GAS = 0 weight)
- [Gas Optimization Security Tradeoffs](../methodology/gas-optimization-security.md) — When gas savings create vulnerabilities
- [Severity Scoring Decision Tree](../patterns/severity-scoring.md) — How to classify GAS vs LOW vs INFORMATIONAL
- [Audit Report Templates](../methodology/audit-report-templates.md) — Standard format for GAS findings

