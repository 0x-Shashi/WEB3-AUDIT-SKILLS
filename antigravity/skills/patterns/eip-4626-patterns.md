---
id: PAT-EIP-4626
title: Eip 4626 Security Patterns
category: standards
severity: medium
difficulty: intermediate
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - eip
  - standard
  - specification

finding_count: 9
last_updated: 2026-01-31
---
# EIP-4626 Security Patterns

## Overview

**Frequency**: 9 occurrences (0.02% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 7 | 0 | 0 |

**Common Sources**: Code4rena, Pashov Audit Group, Spearbit

---

## Detection Checklist

- [ ] Check for eip-4626 vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: WithdrawProxy allows redemptions before PublicVault callstransferWithdrawReserve

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
`WithdrawProxy.sol#L172-L175`

## Description
Anytime there is a withdrawal pending (i.e., someone holds WithdrawProxy shares), shares may be redeemed as long as `totalAssets() > 0` and `s.finalAuctionEnd == 0`. Under normal operating conditions, `totalAssets()` becomes greater than 0 when the `PublicVault` calls `transferWithdrawReserve`. 

`totalAssets()` can also be increased to a non-zero value by anyone transferring WETH to the contract. If this occurs and a user attempts to redeem, they will receive a smaller share than they are owed.

### Exploit Scenario
- Depositor redeems from `PublicVault` and receives WithdrawProxy shares.
- Malicious actor deposits a small amount of WETH into the WithdrawProxy.
- Depositor accidentally redeems, or is tricked into redeeming, from the WithdrawProxy while `totalAssets()` is smaller than it should be.
- `PublicVault` properly processes epoch and full `withdrawReserve` is sent to the WithdrawProxy.
- All remaining holders of WithdrawProxy shares receive an outsized share as the previous shares were redeemed for the incorrect value.

## Recommendation

### Option 1
Consider being explicit in opening the WithdrawProxy for redemptions (`redeem/withdraw`) by requiring `s.withdrawReserveReceived` to be a non-zero value:

```solidity
if (s.finalAuctionEnd != 0) {
    // Updated condition
    if (s.finalAuctionEnd != 0 || s.withdrawReserveReceived == 0) {
        // if finalAuctionEnd is 0, no auctions were

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 2: [H-08] Vault.sol is not EIP-4626 compliant

**Source**: Code4rena
**Protocol**: Y2k Finance
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2022-09-y2k-finance/blob/ac3e86f07bc2f1f51148d2265cc897e8b494adf7/src/Vault.sol#L244-L252>

<https://github.com/code-423n4/2022-09-y2k-finance/blob/ac3e86f07bc2f1f51148d2265cc897e8b494adf7/src/SemiFungibleVault.sol#L205-L213>

<https://github.com/code-423n4/2022-09-y2k-finance/blob/ac3e86f07bc2f1f51148d2265cc897e8b494adf7/src/SemiFungibleVault.sol#L237-L239>

<https://github.com/code-423n4/2022-09-y2k-finance/blob/ac3e86f07bc2f1f51148d2265cc897e8b494adf7/src/SemiFungibleVault.sol#L244-L246>

<https://github.com/code-423n4/2022-09-y2k-finance/blob/ac3e86f07bc2f1f51148d2265cc897e8b494adf7/src/SemiFungibleVault.sol#L251-L258>

<https://github.com/code-423n4/2022-09-y2k-finance/blob/ac3e86f07bc2f1f51148d2265cc897e8b494adf7/src/SemiFungibleVault.sol#L263-L270>

### Impact

Other protocols that integrate with Y2K may wrongly assume that the functions are EIP-4626 compliant. Thus, it might cause integration problems in the future that can lead to wide range of issues for both parties.

### Proof of Concept

All official EIP-4626 requirements can be found on it's [official page](https://eips.ethereum.org/EIPS/eip-4626#methods). Non-compliant functions are listed below along with the reason they are not compliant:

The following functions are missing but should be present:

1.  mint(uint256, address) returns (uint256)
2.  redeem(uint256, address, address) returns (uint256)

The following functions are non-compliant because they don't account for withdraw

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-y2k-finance)

---

### Example 3: [M-16] `vMaia` is ERC-4626 compliant, but the `maxWithdraw` & `maxRedeem` functions are not fully up to EIP-4626's specification

**Source**: Code4rena
**Protocol**: Maia DAO Ecosystem
**Impact**: MEDIUM

**Details**:

The `maxWithdraw` & `maxRedeem` functions should return the `0` when the withdrawal is paused. But here, it's returning `balanceOf[user]`.

### Proof of Concept

`vMaia Withdrawal` is only allowed once per month during the 1st Tuesday (UTC+0) of the month.

It's checked by the below function:

```

     102       function beforeWithdraw(uint256, uint256) internal override {
                /// @dev Check if unstake period has not ended yet, continue if it is the case.
                if (unstakePeriodEnd >= block.timestamp) return;
        
                uint256 _currentMonth = DateTimeLib.getMonth(block.timestamp);
                if (_currentMonth == currentMonth) revert UnstakePeriodNotLive();
        
                (bool isTuesday, uint256 _unstakePeriodStart) = DateTimeLib.isTuesday(block.timestamp);
                if (!isTuesday) revert UnstakePeriodNotLive();
        
                currentMonth = _currentMonth;
                unstakePeriodEnd = _unstakePeriodStart + 1 days;
    114        }
```

<https://github.com/code-423n4/2023-05-maia/blob/main/src/maia/vMaia.sol#L102C1-L114C6>

```

    173            function maxWithdraw(address user) public view virtual override returns (uint256) {
                      return balanceOf[user];
                  }
              
                  /// @notice Returns the maximum amount of assets that can be redeemed by a user.
                  /// @dev Assumes that the user has already forfeited all utility tokens.
      

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-05-maia)

---

### Example 4: [M-17] Malicious Users Can Drain The Assets Of Vault. (Due to not being ERC4626 Complaint)

**Source**: Code4rena
**Protocol**: Popcorn
**Impact**: MEDIUM

**Details**:

Malicious users can drain the assets of the vault.

### Proof of Concept

The `withdraw` function users `convertToShares` to convert the assets to the amount of shares. These shares are burned from the users account and the assets are returned to the user.

The function `withdraw` is shown below:

```solidity
function withdraw(
        uint256 assets,
        address receiver,
        address owner
    ) public nonReentrant syncFeeCheckpoint returns (uint256 shares) {
        if (receiver == address(0)) revert InvalidReceiver();

        shares = convertToShares(assets);
/// .... [skipped the code]
```

The function `convertToShares` is shown below:

```solidity
function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply(); // Saves an extra SLOAD if totalSupply is non-zero.

        return
            supply == 0
                ? assets
                : assets.mulDiv(supply, totalAssets(), Math.Rounding.Down);
    }
```

It uses `Math.Rounding.Down` , but it should use `Math.Rounding.Up`

Assume that the vault with the following state:

*   Total Asset = 1000 WETH
*   Total Supply = 10 shares

Assume that Alice wants to withdraw 99 WETH from the vault. Thus, she calls the**`Vault.withdraw(99 WETH)`**function.

The calculation would go like this:

```solidity
assets = 99
return value = assets * supply / totalAssets()
return value = 99 * 10 / 1000
return value = 0
```

The value would be rounded round to zero. This will be 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-popcorn)

---

### Example 5: [M-02] Slippage controls for calling `bHermes` contract's `ERC4626DepositOnly.deposit` and `ERC4626DepositOnly.mint` functions are missing

**Source**: Code4rena
**Protocol**: Maia DAO Ecosystem
**Impact**: MEDIUM

**Details**:

[EIPS](<https://eips.ethereum.org/EIPS/eip-4626#security-considerations>) mentions that "if implementors intend to support EOA account access directly, they should consider adding an additional function call for `deposit`/`mint`/`withdraw`/`redeem` with the means to accommodate slippage loss or unexpected deposit/withdrawal limits, since they have no other means to revert the transaction if the exact output amount is not achieved."

Using the `bHermes` contract that inherits the `ERC4626DepositOnly` contract, EOAs can call the `ERC4626DepositOnly.deposit` and `ERC4626DepositOnly.mint` functions directly. However, because no slippage controls can be specified when calling these functions, these function's `shares` and `assets` outputs can be less than expected to these EOAs.

<https://github.com/code-423n4/2023-05-maia/blob/53c7fe9d5e55754960eafe936b6cb592773d614c/src/erc-4626/ERC4626DepositOnly.sol#L32-L44>

```solidity
    function deposit(uint256 assets, address receiver) public virtual returns (uint256 shares) {
        // Check for rounding error since we round down in previewDeposit.
        require((shares = previewDeposit(assets)) != 0, "ZERO_SHARES");

        // Need to transfer before minting or ERC777s could reenter.
        address(asset).safeTransferFrom(msg.sender, address(this), assets);

        _mint(receiver, shares);

        emit Deposit(msg.sender, receiver, assets, shares);

        afterDeposit(assets, shares);
    }
```

<https://github.com/code-423n4/

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-05-maia)

---

### Example 6: [M-22] `ERC4626RouterBase.withdraw` can only be called once

**Source**: Code4rena
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

ERC4626RouterBase.withdraw will approve an amount of vault tokens to the vault, but the amount represents the number of asset tokens taken out by vault.withdraw, not the required number of vault tokens, and since it normally requires less than 1 vault token to take out 1 asset token, it will prevent ERC4626RouterBase.withdraw from using all approved vault tokens.

```solidity
  function withdraw(
    IERC4626 vault,
    address to,
    uint256 amount,
    uint256 maxSharesOut
  ) public payable virtual override returns (uint256 sharesOut) {

    ERC20(address(vault)).safeApprove(address(vault), amount);
    if ((sharesOut = vault.withdraw(amount, to, msg.sender)) > maxSharesOut) {
      revert MaxSharesError();
    }
  }
```

and since safeApprove cannot approve a non-zero value to a non-zero value, the second call to ERC4626RouterBase.withdraw will fails in safeApprove.

```solidity
    function safeApprove(
        IERC20 token,
        address spender,
        uint256 value
    ) internal {
        // safeApprove should only be called when setting an initial allowance,
        // or when resetting it to zero. To increase and decrease it, use
        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'
        require(
            (value == 0) || (token.allowance(address(this), spender) == 0),
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-astaria)

---

### Example 7: [M-06] For a public vault, minimum deposit requirement that is enforced by `ERC4626Cloned.deposit` function can be bypassed by `ERC4626Cloned.mint` function or vice versa when share price does not equal one

**Source**: Code4rena
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

The following `ERC4626Cloned.deposit` function has `require(shares > minDepositAmount(), "VALUE_TOO_SMALL")` as the minimum deposit requirement, and the `ERC4626Cloned.mint` function below has `require(assets > minDepositAmount(), "VALUE_TOO_SMALL")` as the minimum deposit requirement. For a public vault, when the share price becomes different than 1, these functions' minimum deposit requirements are no longer the same. For example, given `S` is the `shares` input value for the `ERC4626Cloned.mint` function and `A` equals `ERC4626Cloned.previewMint(S)`, when the share price is bigger than 1 and `A` equals `minDepositAmount() + 1`, such `A` will violate the `ERC4626Cloned.deposit` function's minimum deposit requirement but the corresponding `S` will not violate the `ERC4626Cloned.mint` function's minimum deposit requirement; in this case, the user can just ignore the `ERC4626Cloned.deposit` function and call `ERC4626Cloned.mint` function to become a liquidity provider. Thus, when the public vault's share price is different than 1, the liquidity provider can call the less restrictive function out of the two so the minimum deposit requirement enforced by one of the two functions is not effective at all; this can result in unexpected deposit amounts and degraded filtering of who can participate as a liquidity provider.

<https://github.com/AstariaXYZ/astaria-gpl/blob/main/src/ERC4626-Cloned.sol#L19-L36>

```solidity
  function deposit(uint256 assets, address receiver)
    public


*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-astaria)

---

### Example 8: [M-02] The ERC4626 standard is not followed correctly

**Source**: Pashov Audit Group
**Protocol**: Florence Finance
**Impact**: MEDIUM

**Details**:

**Impact:**
Medium, as functionality is not working as expected but without a value loss

**Likelihood:**
Medium, as multiple methods are not compliant with the standard

**Description**

As per EIP-4626, the `maxDeposit` method "MUST factor in both global and user-specific limits, like if deposits are entirely disabled (even temporarily) it MUST return 0.". This is not the case currently, as even if the contract is paused, the `maxDeposit` method will still return what it usually does.

When it comes to the `decimals` method, the EIP says: "Although the convertTo functions should eliminate the need for any use of an EIP-4626 Vaults decimals variable, it is still strongly recommended to mirror the underlying tokens decimals if at all possible, to eliminate possible sources of confusion and simplify integration across front-ends and for other off-chain users."
The `LoanVault` contract has hardcoded the value of 18 to be returned when `decimals` are called, but it should be the decimals of the underlying token (it might not be 18 in some case maybe).

**Recommendations**

Go through [the standard](https://eips.ethereum.org/EIPS/eip-4626) and follow it for all methods that `override` methods from the inherited ERC4626 implementation.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Pashov/2023-04-01-Florence Finance.md)

---

### Example 9: [M-23] Function `withdraw()` and `redeem()` in ERC4626RouterBase would revert always because they have unnecessary allowance setting

**Source**: Code4rena
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

<https://github.com/AstariaXYZ/astaria-gpl/blob/4b49fe993d9b807fe68b3421ee7f2fe91267c9ef/src/ERC4626RouterBase.sol#L48><br>
<https://github.com/AstariaXYZ/astaria-gpl/blob/4b49fe993d9b807fe68b3421ee7f2fe91267c9ef/src/ERC4626RouterBase.sol#L62>

Functions withdraw() and redeem()  in ERC4626RouterBase  are used to withdraw user funds from vaults and they call `vault.withdraw()` and `vault.redeem()` and logics in vault transfer user shares and user required to give spending allowance for vault and there is no need for ERC4626RouterBase to set approval for vault and because those approved tokens won't be used and code uses `safeApprove()` so next calls to `withdraw()` and `redeem()` would revert because code would tries to change allowance amount while it's not zero. those functions would revert always and AstariaRouter uses them and user won't be able to use those function and any other protocol integrating with Astaria calling those function would have broken logic. also if UI interact with protocol with router functions then UI would have broken parts too. and functions in router support users to set slippage allowance and without them users have to interact with vault directly and they may lose funds because of the slippage.

### Proof of Concept

This is `withdraw()` and `redeem()` code in ERC4626RouterBase:

      function withdraw(
        IERC4626 vault,
        address to,
        uint256 amount,
        uint256 maxSharesOut
      ) public payable virtual override return

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-astaria)

---

## Statistics

- Total findings analyzed: 9
- Examples shown: 9
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

