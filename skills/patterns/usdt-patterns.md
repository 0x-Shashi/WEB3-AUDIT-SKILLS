# USDT Security Patterns

## Overview

**Frequency**: 6 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 5 | 0 | 0 |

**Common Sources**: Spearbit, Sherlock

---

## Detection Checklist

- [ ] Check for usdt vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Decrease allowance when it is already set a non-zero value

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: HIGH

**Details**:

## Security Analysis Report

## Severity
**High Risk**

## Context
- AxelarFacet.sol#L71
- LibAsset.sol#L52
- FusePoolZap.sol#L64
- Executor.sol#L312

## Description
Non-standard tokens like USDT will revert the transaction when a contract or a user tries to approve an allowance when the spender allowance is already set to a non-zero value. For that reason, the previous allowance should be decreased before increasing the allowance in the related function.

- Performing a direct overwrite of the value in the allowances mapping is susceptible to front-running scenarios by an attacker (e.g., an approved spender). As OpenZeppelin mentioned, `safeApprove` should only be called when setting an initial allowance or when resetting it to zero.

### Function
```solidity
function safeApprove(
    IERC20 token,
    address spender,
    uint256 value
) internal {
    // safeApprove should only be called when setting an initial allowance,
    // or when resetting it to zero. To increase and decrease it, use
    // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'.
    require(
        (value == 0) || (token.allowance(address(this), spender) == 0),
        "SafeERC20: approve from non-zero to non-zero allowance"
    );
    _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
}
```

### Instances of the Issue
There are four instances of this issue:

1. **AxelarFacet.sol** is directly using the `approve` function, which does not check the return value 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 2: safeApprove indepositToken could revert for non-standard token like USDT

**Source**: Spearbit
**Protocol**: Gauntlet
**Impact**: MEDIUM

**Details**:

## Security Analysis

## Severity
**Medium Risk**

## Context
AeraVaultV1.sol#L893

## Description
Some non-standard tokens like USDT will revert when a contract or a user tries to approve an allowance when the spender allowance has already been set to a non-zero value. In the current code, we have not seen any real problem with this fact because the amount retrieved via `depositToken()` is approved and sent to the Balancer pool via `joinPool()` and `managePoolBalance()`. Balancer transfers the same amount, lowering the approval to 0 again. 

However, if the approval is not lowered to exactly 0 (due to a rounding error or another unforeseen situation), then the next approval in `depositToken()` will fail (assuming a token like USDT is used), blocking all further deposits.

**Note:** Set to medium risk because the probability of this happening is low, but the impact would be high. We also should note that OpenZeppelin has officially deprecated the `safeApprove` function, suggesting to use instead `safeIncreaseAllowance` and `safeDecreaseAllowance`.

## Recommendation
Adopt a safer approach to cover edge cases such as the abovementioned USDT token and implement the following solution:

```solidity
function depositToken(IERC20 token, uint256 amount) internal {
    token.safeTransferFrom(owner(), address(this), amount);
    // - token.safeApprove(address(bVault), amount);
    uint256 allowance = token.allowance(address(this), address(bVault));
    if (allowance > 0) {
        tok

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Gauntlet-Spearbit-Security-Review.pdf)

---

### Example 3: Not always safeApprove(..., 0)

**Source**: Spearbit
**Protocol**: Connext
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
- **NomadFacet.sol**: Lines 176-242
- **AssetLogic.sol**: Lines 308-362, 263-295
- **PortalFacet.sol**: Lines 179-197
- **Executor.sol**: Lines 142-339

## Description
Some functions like `_reconcileProcessPortal` of `BaseConnextFacet` and `_swapAssetOut` of `AssetLogic` do `safeApprove(..., 0)` first.

```solidity
contract NomadFacet is BaseConnextFacet {
    function _reconcileProcessPortal(...) {
        ...
        // Edge case with some tokens: Example USDT in ETH Mainnet, after the backUnbacked call there
        // could be a remaining allowance if not the whole amount is pulled by aave.
        // Later, if we try to increase the allowance it will fail. USDT demands if allowance is not 0,
        // it has to be set to 0 first.
        
        // Example:
        [ParaSwapRepayAdapter.sol#L138-L140](https://github.com/aave/aave-v3-periphery/blob/ca184e5278bcbc10d28c3dbbc604041d7cfac50b/contracts/adapters/paraswap/ParaSwapRepayAdapter.sol#L138-L140)
        
        safeApprove(IERC20(adopted), s.aavePool, 0);
        safeIncreaseAllowance(IERC20(adopted), s.aavePool, totalRepayAmount);
        ...
    }
}
```

While the following functions don’t do this:
- `xcall` of `BridgeFacet`
- `_backLoan` of `PortalFacet`
- `_swapAsset` of `AssetLogic`
- `execute` of `Executor`

This could result in problems with tokens like USDT.

```solidity
contract BridgeFacet is BaseConnextFacet {
    function xcall(XCallArgs calldata _args) external pa

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 4: M-17: Did Not Approve To Zero First

**Source**: Sherlock
**Protocol**: Notional
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/59 

## Found by 
xiaoming90, 0x52, csanuragjain

## Summary

Allowance was not set to zero first before changing the allowance.

## Vulnerability Detail

Some ERC20 tokens (like USDT) do not work when changing the allowance from an existing non-zero allowance value. For example Tether (USDT)'s `approve()` function will revert if the current approval is not zero, to protect against front-running changes of approvals.

The following  attempt to call the `approve()` function without setting the allowance to zero first.

https://github.com/sherlock-audit/2022-09-notional/blob/main/leveraged-vaults/contracts/utils/TokenUtils.sol#L18

```solidity
File: TokenUtils.sol
18:     function checkApprove(IERC20 token, address spender, uint256 amount) internal {
19:         if (address(token) == address(0)) return;
20: 
21:         IEIP20NonStandard(address(token)).approve(spender, amount);
22:         _checkReturnCode();
23:     }
```

However, if the token involved is an ERC20 token that does not work when changing the allowance from an existing non-zero allowance value, it will break a number of key functions or features of the protocol as the `TokenUtils.checkApprove` function is utilised extensively within the vault as shown below.

https://github.com/sherlock-audit/2022-09-notional/blob/main/leveraged-vaults/contracts/vaults/balancer/internal/pool/TwoTokenPoolUtils.sol#L159

```solidity
File: TwoTokenPoolUtils.

*[Content truncated...]*

---

### Example 5: Seaport auctions not compatible with USDT

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

## Security Analysis Report

## Severity
**Medium Risk**

## Context
`CollateralToken.sol#L173`

## Description
As per the ERC20 specification, the `approve()` function is expected to return a boolean:

```solidity
function approve(address _spender, uint256 _value) public returns (bool success)
```

However, USDT deviates from this standard, and its `approve()` method does not have a return value. Hence, if USDT is used as a payment token, the following line reverts in `validateOrder()` as it expects return data but doesn't receive it:

```solidity
paymentToken.approve(address(transferProxy), s.LIEN_TOKEN.getOwed(stack));
```

## Recommendation
Use Solmate's `safeApprove()` function to accommodate USDT's `approve()`:

```solidity
paymentToken.safeApprove(address(transferProxy), s.LIEN_TOKEN.getOwed(stack));
```

## Additional Information
- **Astaria:** Fixed in PR339.
- **Spearbit:** Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review-July.pdf)

---

### Example 6: M-4: Blacklisted creditor can block all repayment besides emergency closure

**Source**: Sherlock
**Protocol**: Real Wagmi #2
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-10-real-wagmi-judging/issues/83 

## Found by 
0x52, ArmedGoose, Bauer, tsvetanovv

After liquidity is restored to the LP, accumulated fees are sent directly from the vault to the creditor. Some tokens, such as USDC and USDT, have blacklists the prevent users from sending or receiving tokens. If the creditor is blacklisted for the hold token then the fee transfer will always revert. This forces the borrower to defualt. LPs can recover their funds but only after the user has defaulted and they request emergency closure.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-10-real-wagmi/blob/main/wagmi-leverage/contracts/abstract/LiquidityManager.sol#L306-L315

            address creditor = underlyingPositionManager.ownerOf(loan.tokenId);
            // Increase liquidity and transfer liquidity owner reward
            _increaseLiquidity(cache.saleToken, cache.holdToken, loan, amount0, amount1);
            uint256 liquidityOwnerReward = FullMath.mulDiv(
                params.totalfeesOwed,
                cache.holdTokenDebt,
                params.totalBorrowedAmount
            ) / Constants.COLLATERAL_BALANCE_PRECISION;

            Vault(VAULT_ADDRESS).transferToken(cache.holdToken, creditor, liquidityOwnerReward);

The following code is executed for each loan when attempting to repay. Here we see that each creditor is directly transferred their tokens from the vault. If the creditor is blacklisted for holdToken,

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 6
- Examples shown: 6
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
