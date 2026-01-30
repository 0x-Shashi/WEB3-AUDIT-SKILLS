# Change Validation Security Patterns

## Overview

**Frequency**: 6 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 5 | 0 | 0 |

**Common Sources**: Sherlock, Halborn, Hans

---

## Detection Checklist

- [ ] Check for change validation vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: M-11: priceLiquidity() may not work if PriceFeed.aggregator() is updated

**Source**: Sherlock
**Protocol**: Isomorph
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-isomorph-judging/issues/145 

## Found by 
cccz

## Summary
priceLiquidity() may not work if PriceFeed.aggregator() is updated
## Vulnerability Detail
In the constructor of the DepositReceipt_* contract, the value of minAnswer/maxAnswer in priceFeed.aggregator() is obtained and assigned to *MinPrice/*MaxPrice as the maximum/minimum price limit when calling the getOraclePrice function in priceLiquidity, and *MinPrice/*MaxPrice can not change.
```solidity
        IAccessControlledOffchainAggregator  aggregator = IAccessControlledOffchainAggregator(priceFeed.aggregator());
        //fetch the pricefeeds hard limits so we can be aware if these have been reached.
        tokenMinPrice = aggregator.minAnswer();
        tokenMaxPrice = aggregator.maxAnswer();
...
            uint256 oraclePrice = getOraclePrice(priceFeed, tokenMaxPrice, tokenMinPrice);
...
    function getOraclePrice(IAggregatorV3 _priceFeed, int192 _maxPrice, int192 _minPrice) public view returns (uint256 ) {
        (
            /*uint80 roundID*/,
            int signedPrice,
            /*uint startedAt*/,
            uint timeStamp,
            /*uint80 answeredInRound*/
        ) = _priceFeed.latestRoundData();
        //check for Chainlink oracle deviancies, force a revert if any are present. Helps prevent a LUNA like issue
        require(signedPrice > 0, "Negative Oracle Price");
        require(timeStamp >= block.timestamp - HEARTBEAT_TIME , "Stale pricefe

*[Content truncated...]*

---

### Example 2: M-2: Expired locks should not continue to earn rewards at the original high multiplier rate

**Source**: Sherlock
**Protocol**: Merit Circle
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-10-merit-circle-judging/issues/108 

## Found by 
WATCHPUG

## Summary

Expired locks should be considered as same as the deposits with no lock.

## Vulnerability Detail

The current implementation allows the deposits with expired locks to continue to enjoy the original high multiplier rate, while they can withdraw anytime they want.

The multiplier of shares amount is essentially a higher reward rate (APR) for longer period of locks.

For example:

If the regular APR is 2%; Locking for 4 years will boost the APR to 10%.

- Alice deposited 1M $MC tokens and got 10% APR;
- 4 years later, Alice's deposit's lock was expired.

Expected result:

The new APR for Alice's deposit is 2%;

Actual result:

Alice can continue to enjoy a 10% APR while she can withdraw anytime.

## Impact

Users with expired locks will take more rewards than expected, which means fewer rewards for other users.

## Code Snippet

https://github.com/Merit-Circle/merit-liquidity-mining/blob/ce5feaae19126079d309ac8dd9a81372648437f1/contracts/TimeLockPool.sol#L116-L135

## Tool used

Manual Review

## Recommendation

Curve's Gauge system introduced a method called `kick()` which allows the expired (zeroed) veCRV users to be kicked from the rewards.

See: https://github.com/curvefi/curve-dao-contracts/blob/master/contracts/gauges/LiquidityGaugeV5.vy#L430-L446

A similar method can be added to solve this issue:

```solidity
function kick(uint256 _depositId, address _u

*[Content truncated...]*

---

### Example 3: NON-STANDARD ERC20 TOKENS WILL REVERT

**Source**: Halborn
**Protocol**: Primex Contracts
**Impact**: MEDIUM

**Details**:

##### Description

The library `TokenTransfersLibrary.sol` contains the function to perform ERC20 tokens transfers in the protocol. However, this library uses the interface of `IERC20` from OpenZeppelin which enforces the return value on transfer.

This pattern is not followed by all ERC20 tokens, as for example USDT. If attempting to transfer these tokens, the contract will revert, preventing the transaction to be executed.

Code Location
-------------

[TokenTransfersLibrary.sol#L12-L19](https://github.com/primex-finance/primex_contracts/blob/f809cc0471935013699407dcd9eab63b60cd2e22/src/contracts/libraries/TokenTransfersLibrary.sol#L12-L19)

#### TokenTransfersLibrary.sol

```
function doTransferFromTo(address token, address from, address to, uint256 amount) public returns (uint256) {
    uint256 balanceBefore = IERC20(token).balanceOf(to);
    // The returned value is checked in the assembly code below.
    // Arbitrary `from` should be checked at a higher level. The library function cannot be called by the user.
    // slither-disable-next-line unchecked-transfer arbitrary-send-erc20
    IERC20(token).transferFrom(from, to, amount);

    bool success;

```

[TokenTransfersLibrary.sol#L46-L51](https://github.com/primex-finance/primex_contracts/blob/f809cc0471935013699407dcd9eab63b60cd2e22/src/contracts/libraries/TokenTransfersLibrary.sol#L46-L51)

#### TokenTransfersLibrary.sol

```
function doTransferOut(address token, address to, uint256 amount) public {
    // The retur

*[Content truncated...]*

**Reference**: [View Original Finding](https://www.halborn.com/audits/primex/primex-contracts)

---

### Example 4: H-6: Outstanding loans cannot be closed or liquidated if collateral is paused

**Source**: Sherlock
**Protocol**: Isomorph
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-isomorph-judging/issues/57 

## Found by 
0x52, HonorLt

## Summary

When a collateral is paused by governance, `collateralValid` is set to false. This causes closing and liquidating of loans to be impossible, leading to two issues. The first is that users with exist loans are unable to close their loans to recover their collateral. The second is that since debt is impossible to liquidate the protocol could end up being stuck with a lot of bad debt.

## Vulnerability Detail

    function pauseCollateralType(
        address _collateralAddress,
        bytes32 _currencyKey
        ) external collateralExists(_collateralAddress) onlyAdmin {
        require(_collateralAddress != address(0)); //this should get caught by the collateralExists check but just to be careful
        //checks two inputs to help prevent input mistakes
        require( _currencyKey == collateralProps[_collateralAddress].currencyKey, "Mismatched data");
        collateralValid[_collateralAddress] = false;
        collateralPaused[_collateralAddress] = true;
    }

When a collateral is paused `collateralValid[_collateralAddress]` is set to `false`. For `Vault_Lyra` `Vault_Synths` and `Vault_Velo` this will cause `closeLoan` and `callLiquidation` to revert. This traps existing users and prevents liquidations which will result in bad debt for the protocol

## Impact

Outstanding loans cannot be closed or liquidated, freezing user funds and causing the protocol

*[Content truncated...]*

---

### Example 5: M-11: Delisted assets can still be deposited and borrowed against by accounts that already have them

**Source**: Sherlock
**Protocol**: Sentiment
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-08-sentiment-judging/tree/main/154-M 
## Found by 
0x52, Kumpa, devtooligan, WATCHPUG

## Summary

Delisting an asset does not prevent accounts, that already contain the asset from depositing more. It blocks the deposit function but users can sidestep but sending tokens directly to their account

## Vulnerability Detail

AccountManger.sol#deposit attempts to block deposits from assets that are not on the list of supported collateral. When calculating the health of the account, the total balance of the account address is considered. An account that already has the asset on it's assets list doesn't need to use AccountManger.sol#deposit because they can transfer the tokens directly to the account contract. This means that these account can continue to add to and use delisted assets as collateral.

## Impact

One of two scenarios depending on actions taken by the protocol. If the asset is delisted from accountManager.sol and the oracle is removed then all users with loans taken against the asset will likely be immediately liquidated, which is highly unfair to users. If the asset is just delisted from accountManager.sol then existing users that already have the asset would be able to continue using the asset to take loans. If the reason an asset is being delisted is to prevent a vulnerability then the exploit would still be able to happen due to these accounts sidestepping deposit restrictions.

## Code Snippet

[AccountManager.sol#L1

*[Content truncated...]*

---

### Example 6: Admin level vulnerabilities

**Source**: Hans
**Protocol**: Meta
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Context:** [`IDO.sol#L66-69`](https://github.com/getmetafinance/meta/blob/00bbac1613fa69e4c180ff53515451df4df9f69e/contracts/ido/IDO.sol#L66-69)

**Description:**
Numerous admin functions do not check the validity of the input parameters.

- Many setter functions that set token addresses do not validate zero address (e.g. `MetaManager::setTokens`)
- `IDO::setClaimTime` - time validation
- `MetaManager::setMaxExitCycle` - use strict inequality to prevent DOS unstaking

Also some functions are not necessary and can lead to unintentional situations.

- `IDO::setPrice` - According to the documentation, the floor price is kept as constant but the current implementation allow the owner to change the price to any value.

Although we assume the admin is trusted, these issues can lead to unexpected loss by a mistake of an admin.

**Impact**
The admin can change the protocol’s behavior in unexpected ways.

**Recommendation:**
Add necessary validations to the admin functions and remove unnecessary functions.

**Meta Team:**

Fixed. In the commit :007c1b9183cdb65a500928173608ebff0a5197ef.
Actions include require statments and also to remove unnecessary functions.

**Hans:**
Verified.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Hans/2023-07-13-Meta.md)

---

## Statistics

- Total findings analyzed: 6
- Examples shown: 6
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

