---
id: PAT-ALLOWANCE
title: Allowance Security Patterns
category: token
severity: medium
difficulty: intermediate
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - allowance
  - approval
  - spending

finding_count: 15
last_updated: 2026-01-31
---
# Allowance Security Patterns

## Overview

**Frequency**: 15 occurrences (0.03% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 9 | 6 | 0 | 0 |

**Common Sources**: Sherlock, Spearbit, Code4rena

---

## Detection Checklist

- [ ] Check for allowance vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: allowance() doesnt limit withdraw() s

**Source**: Spearbit
**Protocol**: Gauntlet
**Impact**: HIGH

**Details**:

## High Risk Severity Report

## Context
- **PermissiveWithdrawalValidator.sol**: Lines 17-27
- **IWithdrawalValidator.sol**
- **AeraVaultV1.sol**: Lines 456-514

## Description
The `allowance()` function is meant to limit withdrawal amounts. However, `allowance()` can only read and not alter state because its visibility is set to `view`. Therefore, the `withdraw()` function can be called on demand until the entire Vault/Pool balance has been drained, rendering the `allowance()` function ineffective.

```solidity
function withdraw(uint256[] calldata amounts) ... {
    ...
    uint256[] memory allowances = validator.allowance();
    ...
    for (uint256 i = 0; i < tokens.length; i++) {
        if (amounts[i] > holdings[i] || amounts[i] > allowances[i]) {
            revert Aera__AmountExceedAvailable(... );
        }
    }
}
```

### Note on `allowance()`
```solidity
// can't update state due to view
function allowance() external view override returns (uint256[] memory amounts) {
    amounts = new uint256[](count);
    for (uint256 i = 0; i < count; i++) {
        amounts[i] = ANY_AMOUNT;
    }
}
```

## Recommendation
Remove the `view` keyword from the `allowance()` template, e.g., from both `IWithdrawalValidator.sol` and `PermissiveWithdrawalValidator.sol`, to allow for state updates in future versions of `allowance()`.

## Gauntlet
I would say we need an additional callback to the Validator to notify it of actual withdrawal amounts. In cases where allowance is greater than 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Gauntlet-Spearbit-Security-Review.pdf)

---

### Example 2: Malicious call data can DOS execute

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Vulnerability Report

## Severity
**High Risk**

## Context
`Executor.sol#L142-L243`

## Description
An attacker can Denial of Service (DOS) the executor contract by giving infinite allowance to normal users. Since the executor increases allowance before triggering an external call, the transaction will always revert if the allowance is already infinite.

```solidity
function execute(ExecutorArgs memory _args) external payable override onlyConnext returns (bool, bytes memory) {
    ...
    if (!isNative && hasValue) {
        SafeERC20.safeIncreaseAllowance(IERC20(_args.assetId), _args.to, _args.amount); // reverts if set to `infinite` before
    }
    ...
    (success, returnData) = ExcessivelySafeCall.excessivelySafeCall(...); // can set to `infinite` allowance
    ...
}
```

## Recommendation
Set the allowance to 0 before using `safeIncreaseAllowance`.

## Note
Also see issue Not always `safeApprove(..., 0)`.

## Connext
Solved in PR 1550.

## Spearbit
Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 3: [H-04] Approvals not cleared after key transfer

**Source**: Code4rena
**Protocol**: Unlock Protocol
**Impact**: HIGH

**Details**:

_Submitted by cmichel_

The locks implement three different approval types, see `onlyKeyManagerOrApproved` for an overview:

*   key manager (map `keyManagerOf`)
*   single-person approvals (map `approved`). Cleared by `_clearApproval` or `_setKeyManagerOf`
*   operator approvals (map `managerToOperatorApproved`)

The `MixinTransfer.transferFrom` requires any of the three approval types in the `onlyKeyManagerOrApproved` modifier on the tokenId to authenticate transfers from `from`.

Notice that if the `to` address previously had a key but it expired only the `_setKeyManagerOf` call is performed, which does not clear `approved` if the key manager was already set to 0:

```solidity
function transferFrom(
  address _from,
  address _recipient,
  uint _tokenId
)
  public
  onlyIfAlive
  hasValidKey(_from)
  onlyKeyManagerOrApproved(_tokenId)
{
  // @audit this is skipped if user had a key that expired
  if (toKey.tokenId == 0) {
    toKey.tokenId = _tokenId;
    _recordOwner(_recipient, _tokenId);
    // Clear any previous approvals
    _clearApproval(_tokenId);
  }

  if (previousExpiration <= block.timestamp) {
    // The recipient did not have a key, or had a key but it expired. The new expiration is the sender's key expiration
    // An expired key is no longer a valid key, so the new tokenID is the sender's tokenID
    toKey.expirationTimestamp = fromKey.expirationTimestamp;
    toKey.tokenId = _tokenId;

    // Reset the key Manager to the key owner
    // @audit  doesn't c

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-11-unlock)

---

### Example 4: H-3: CryptoPunks NFTs may be stolen via deposit frontrunning

**Source**: Sherlock
**Protocol**: Ajna
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-ajna-judging/issues/140 

## Found by 
Jeiwan

## Summary
Depositing of CryptoPunks NFTs may be front run, a malicious actor may deposit someone else's CryptoPunks NFT.
## Vulnerability Detail
Due to the CryptoPunks NFT collection not implementing the ERC721 standard, depositing of CryptoPunks NFTs is implemented via a direct sale:
1. token owner needs to call [offerPunkForSaleToAddress](https://etherscan.io/address/0xb47e3cd837ddf8e4c57f05d70ab865de6e193bbb#code) and set the `toAddress` value to the address of the pool the token will be deposited to;
1. token owner then calls the [addCollateral](https://github.com/sherlock-audit/2023-01-ajna/blob/main/contracts/src/ERC721Pool.sol#L251) function of the ERC721 pool;
1. the pool [buys the token](https://github.com/sherlock-audit/2023-01-ajna/blob/main/contracts/src/ERC721Pool.sol#L577) from its owner.

However, `addCollateral` can be called by anyone: the pool will buy the token and will deposit it on the caller's account even if the caller is not the owner of the token.
## Impact
CryptoPunks NFTs owner may lose their NFTs when trying to deposit them to an ERC721 pool. A malicious actor may front run the depositing and deposit the NFTs to their account. The malicious actor may then withdraw the NFTs.
## Code Snippet
[ERC721Pool.sol#L577](https://github.com/sherlock-audit/2023-01-ajna/blob/main/contracts/src/ERC721Pool.sol#L577)
[CryptoPunksMarket](https://etherscan.io/address/0x

*[Content truncated...]*

---

### Example 5: Receiver doesn't always reset allowance

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: HIGH

**Details**:

## Security Report

## Severity
**High Risk**

## Context
Receiver.sol#L224-L297

## Description
The function `_swapAndCompleteBridgeTokens()` of Receiver resets the approval to the executor at the end of an ERC20 transfer. However, if there is insufficient gas, the approval is not reset. This allows the executor to access any tokens (of the same type) left in the Receiver.

```solidity
function _swapAndCompleteBridgeTokens(...) {
    ...
    if (LibAsset.isNativeAsset(assetId)) {
        ...
    } else { // case 2: ERC20 asset
        ...
        token.safeIncreaseAllowance(address(executor), amount);
        if (reserveRecoverGas && gasleft() < _recoverGas) {
            token.safeTransfer(receiver, amount);
            ...
            return; // no safeApprove 0
        }
        try executor.swapAndCompleteBridgeTokens{...} {
            ...
        }
        token.safeApprove(address(executor), 0);
    }
}
```

## Recommendation
Only increase the allowance if sufficient gas is available, for example in the following way:

```solidity
function _swapAndCompleteBridgeTokens(...) {
    ...
    if (LibAsset.isNativeAsset(assetId)) {
        ...
    } else { // case 2: ERC20 asset
        ...
        - token.safeIncreaseAllowance(address(executor), amount);
        if (reserveRecoverGas && gasleft() < _recoverGas) {
            token.safeTransfer(receiver, amount);
            ...
            return;
        }
        + token.safeIncreaseAllowance(address(executor), amount);
 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-retainer1-Spearbit-Security-Review.pdf)

---

### Example 6: LibSwap may pull tokens that are different from the specified asset

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Security Report

## Severity
**Medium Risk**

## Context
**LibSwap.sol**#L30-L55

## Description
`LibSwap.swap` is responsible for executing swaps. It is designed to swap one asset at a time. The `_swapData.callData` is provided by the user, and the LiFi protocol only checks its signature. As a result, users can build calldata to swap a different asset as specified.

For example, users can set `fromAssetId = dai` while providing `addLiquidity(usdc, dai, ...)` as call data. The Uniswap router would then pull `usdc` and `dai` at the same time. If there are remaining tokens left in the LiFi protocol, users can sweep tokens from the protocol.

```solidity
library LibSwap {
    function swap(bytes32 transactionId, SwapData calldata _swapData) internal {
        ...
        if (!LibAsset.isNativeAsset(fromAssetId)) {
            LibAsset.maxApproveERC20(IERC20(fromAssetId), _swapData.approveTo, fromAmount);
            if (toDeposit != 0) {
                LibAsset.transferFromERC20(fromAssetId, msg.sender, address(this), toDeposit);
            }
        } else {
            nativeValue = fromAmount;
        }
        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory res) = _swapData.callTo.call{ value: nativeValue }(_swapData.callData);
        if (!success) {
            string memory reason = LibUtil.getRevertMsg(res);
            revert(reason);
        }
    }
}
```

## Recommendation
Recommend clearing the allowance after the external 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 7: [M-07] Deposit Feature Of The Vault Will Break If Update To A New Platform

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGmx.sol#L73>

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGmx.sol#L152>

### Proof of Concept

During initialization, the `AutoPxGMX` vault will grant max allowance to the platform (PirexGMX) to spend its GMX tokens in Line 97 of the constructor method below. This is required because the vault needs to deposit GMX tokens to the platform (PirexGMX) contract. During deposit, the platform (PirexGMX) contract will pull the GMX tokens within the vault and send them to GMX protocol for staking. Otherwise, the deposit feature within the vault will not work.

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGmx.sol#L73>

```solidity
File: AutoPxGmx.sol
73:     constructor(
74:         address _gmxBaseReward,
75:         address _gmx,
76:         address _asset,
77:         string memory _name,
78:         string memory _symbol,
79:         address _platform,
80:         address _rewardsModule
81:     ) Owned(msg.sender) PirexERC4626(ERC20(_asset), _name, _symbol) {
82:         if (_gmxBaseReward == address(0)) revert ZeroAddress();
83:         if (_gmx == address(0)) revert ZeroAddress();
84:         if (_asset == address(0)) revert ZeroAddress();
85:         if (bytes(_name).length == 0) revert InvalidAssetParam();
86:         if

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-redactedcartel)

---

### Example 8: H-5: Adding liquidity can be `DoS`ed due to calculation mismatches

**Source**: Sherlock
**Protocol**: Arrakis Valantis SOT Audit
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-03-arrakis-judging/issues/54 

## Found by 
KupiaSec, cu5t0mPe0, juaan, whitehair0330
## Summary

When users add liquidity, they send tokens to the `ArrakisPublicVaultRouter` contract. The `ValantisHOTModulePublic` contract then takes the required tokens from the `ArrakisPublicVaultRouter` contract. However, due to a calculation mismatch, the required amount is often greater than the user-sent amount, causing the transaction to be reverted.

## Vulnerability Detail

Let's consider following scenario:
1. The current state:
    - pool: `reserve0 = 1e18 + 1, reserve1 = 1e18 + 1`
    - vault: `totalSupply = 1e18 + 1`
2. Bob calls the `ArrakisPublicVaultRouter.addLiquidity()` function with the following parameters:
    - `amount0Max = 1e18, amount1Max = 1e18`
3. At [L139](https://github.com/sherlock-audit/2024-03-arrakis/blob/main/arrakis-modular/src/ArrakisPublicVaultRouter.sol#L139), the `_getMintAmounts()` function returns:
    - `(sharesReceived, amount0, amount1) = (1e18 - 1, 1e18 - 1, 1e18 - 1)`
4. The router contract takes `token0` and `token1` from Bob in amounts of `1e18 - 1` each and calls the `_addLiquidity()` function with above parameters.
5. In the `_addLiquidity()` function, `ArrakisMetaVaultPublic.mint(1e18 - 1, Bob)` is invoked at [L898](https://github.com/sherlock-audit/2024-03-arrakis/blob/main/arrakis-modular/src/ArrakisPublicVaultRouter.sol#L898).
6. In the `ArrakisMetaVaultPublic.mint()` function:
    - at [L58](

*[Content truncated...]*

---

### Example 9: M-1: Anyone can spend on behalf of roller periphery

**Source**: Sherlock
**Protocol**: Sense
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-sense-judging/issues/48 

## Found by 
8olidity, 0x52, supernova, ctf\_sec, pashov, cryptphi, minhquanym

## Summary
The approve() function in RollerPeriphery contract allows anyone to spend ERC20 token owned by the contract

## Vulnerability Detail
RollerPeriphery.approve() does not have any access control, this allows any user to be able to call the approve call which would make an ERC20 approve call to the token inputed, and allowing the 'to' address to spend. In the cases where RollerPeriphery owns some ERC20 tokens. The user will be able to transfer the tokens from the contract as a spender.

## Impact
Loss of funds

## Code Snippet
https://github.com/sherlock-audit/2022-11-sense/blob/main/contracts/src/RollerPeriphery.sol#L100-L102

```solidity
function approve(ERC20 token, address to, uint256 amount) public payable {
        token.safeApprove(to, amount);
    }
```

ERC20 approve call is:
```solidity
function approve(address spender, uint256 amount) public virtual returns (bool) {
        allowance[msg.sender][spender] = amount;

        emit Approval(msg.sender, spender, amount);

        return true;
    }
```

## Tool used
Manual Review

## Recommendation
There should be some access control, according to the provided contracts, this function is called by RollerFactory, this can be the only address allowed to call the RollerPeriphery.approve() function.

## Discussion

**jparklev**

We don't expect that the Periphery 

*[Content truncated...]*

---

### Example 10: [H-26] All user assets which are approved to VaderPoolV2 may be stolen

**Source**: Code4rena
**Protocol**: Vader Protocol
**Impact**: HIGH

**Details**:

_Submitted by TomFrenchBlockchain, also found by cmichel_

#### Impact

Total loss of funds which have been approved on `VaderPoolV2`

#### Proof of Concept

`VaderPoolV2` allows minting of fungible LP tokens with the `mintFungible` function

<https://github.com/code-423n4/2021-11-vader/blob/607d2b9e253d59c782e921bfc2951184d3f65825/contracts/dex-v2/pool/VaderPoolV2.sol#L284-L290>

Crucially this function allows a user supplied value for `from` which specifies where the `nativeAsset` and `foreignAsset` should be pulled from. An attacker can then provide any address which has a token approval onto `VaderPoolV2` and mint themselves LP tokens - stealing the underlying tokens.

#### Recommended Mitigation Steps

Remove `from` argument and use msg.sender instead.

**[SamSteinGG (Vader) disputed)](https://github.com/code-423n4/2021-11-vader-findings/issues/221#issuecomment-979180340):**
 > pool is not meant to be interacted with

**[alcueca (judge) commented](https://github.com/code-423n4/2021-11-vader-findings/issues/221#issuecomment-991472193):**
 > And how are you going to ensure that the pool is not interacted with, @SamSteinGG?

**[SamSteinGG (Vader) confirmed](https://github.com/code-423n4/2021-11-vader-findings/issues/221#issuecomment-995709116):**
 > @alcueca Upon second consideration, the functions relating to the minting of synths and wrapped tokens should have had the onlyRouter modifier and thus are indeed vulnerable. Issue accepted.
>

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-11-vader)

---

### Example 11: M-7: Rebalancing a negative Perp PnL via a Uniswap V3 token swap is broken due to the lack of token spending allowance

**Source**: Sherlock
**Protocol**: UXD Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-uxd-judging/issues/339 

## Found by 
0x52, Jeiwan, berndartmueller, koxuan, jprod15, Bahurum, cccz, CRYP70, rvierdiiev, GimelSec

## Summary

The `ISwapper spotSwapper` (i.e., `Uniswapper`) helper contract, used by the `PerpDepository._rebalanceNegativePnlWithSwap` function to perform the actual Uniswap V3 token swap, is missing the required `assetToken` spending allowance due to a lack of calling the `assetToken.approve` function.

## Vulnerability Detail

Rebalancing a negative Perp PnL with the `PerpDepository.rebalance` function calls the `_rebalanceNegativePnlWithSwap` function, which performs a Uniswap swap. However, the required `assetToken` spending allowance for the `ISwapper spotSwapper` (i.e. `Uniswapper`) helper contract is missing. This leads to a revert due to insufficient allowance.

## Impact

Rebalancing a negative Perp PnL via a Uniswap swap is missing the token approval and leads to a revert.

## Code Snippet

[integrations/perp/PerpDepository.sol#L507](https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L507)

```solidity
function _rebalanceNegativePnlWithSwap(
    uint256 amount,
    uint256 amountOutMinimum,
    uint160 sqrtPriceLimitX96,
    uint24 swapPoolFee,
    address account
) private returns (uint256, uint256) {
    uint256 normalizedAmount = amount.fromDecimalToDecimal(
        ERC20(quoteToken).decimals(),
        18
    );
    _checkNegativePn

*[Content truncated...]*

---

### Example 12: H-2: Anyone who approved quote tokens to a pool can be forced to take

**Source**: Sherlock
**Protocol**: Ajna
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-ajna-judging/issues/145 

## Found by 
Jeiwan

## Summary
Taking may be executed on behalf of any address who approved spending of quote tokens to a pool: such address will pay quote tokens and will receive collateral.
## Vulnerability Detail
[ERC20Pool](https://github.com/sherlock-audit/2023-01-ajna/blob/main/contracts/src/ERC20Pool.sol#L403) and [ERC721Pool](https://github.com/sherlock-audit/2023-01-ajna/blob/main/contracts/src/ERC721Pool.sol#L405) implement the `take` functions, which buy collateral from auction in exchange for quote tokens. The address to pull quote tokens from is specified in the `callee_` argument, which allows anyone to call the functions and pass an address that has previously approved spending of the quote token to the pool. As a result, such an address will pay for the liquidation and will receive the collateral.
## Impact
Anyone can initiate a take on behalf of another user. Such user can be a lender who has previously approved spending of the quote token to the pool. Calling `take` with the user's address specified as the `callee_` argument will result in:
1. the user [receiving collateral](https://github.com/sherlock-audit/2023-01-ajna/blob/main/contracts/src/ERC20Pool.sol#L450), which may have low value;
1. the user [paying the quote token](https://github.com/sherlock-audit/2023-01-ajna/blob/main/contracts/src/ERC20Pool.sol#L460) to repay the debt being taken.
## Code Snippet
[ERC20Pool.sol#L460]

*[Content truncated...]*

---

### Example 13: H-1: PerpDespository#reblance and rebalanceLite can be called to drain funds from anyone who has approved PerpDepository

**Source**: Sherlock
**Protocol**: UXD Protocol
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-uxd-judging/issues/288 

## Found by 
clems4ever, dipp, 0xNazgul, DecorativePineapple, ctf\_sec, unforgiven, 0x52, ck, HollaDieWaldfee, GimelSec, chiranz, berndartmueller, yixxas, Zarf, carrot, koxuan, hl\_, Ruhum, kankodu, Bahurum

## Summary

PerpDespository#reblance and rebalanceLite allows anyone to specify the account that pays the quote token. These functions allow a malicious user to abuse any allowance provided to PerpDirectory. rebalance is the worst of the two because the malicious user could sandwich attack the rebalance to steal all the funds and force the unsuspecting user to pay the `shortfall`.

## Vulnerability Detail

    function rebalance(
        uint256 amount,
        uint256 amountOutMinimum,
        uint160 sqrtPriceLimitX96,
        uint24 swapPoolFee,
        int8 polarity,
        address account // @audit user specified payer
    ) external nonReentrant returns (uint256, uint256) {
        if (polarity == -1) {
            return
                _rebalanceNegativePnlWithSwap(
                    amount,
                    amountOutMinimum,
                    sqrtPriceLimitX96,
                    swapPoolFee,
                    account // @audit user address passed directly
                );
        } else if (polarity == 1) {
            // disable rebalancing positive PnL
            revert PositivePnlRebalanceDisabled(msg.sender);
            // return _rebalancePositivePnlWithSwap(amount, am

*[Content truncated...]*

---

### Example 14: M-5: PerpDepository#_rebalanceNegativePnlWithSwap fails to approve vault for quote deposit

**Source**: Sherlock
**Protocol**: UXD Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-uxd-judging/issues/372 

## Found by 
HonorLt, 0x52, yixxas, Bahurum, rvierdiiev, GimelSec

## Summary

Throughout the entirety of the contract it grants approval to the vault before depositing either quote or asset. In this case there is no approval which means that the deposit call will fail causing PerpDepository#_rebalanceNegativePnlWithSwap to always revert.

## Vulnerability Detail

See summary.

## Impact

PerpDepository#_rebalanceNegativePnlWithSwap won't function

## Code Snippet

https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L478-L528

## Tool used

Manual Review

## Recommendation

Add the missing approve call:

        } else if (shortFall < 0) {
            // we got excess tokens in the spot swap. Send them to the account paying for rebalance
            IERC20(quoteToken).transfer(
                account,
                _abs(shortFall)
            );
        }

    +   IERC20(quoteToken).approve(address(vault), quoteAmount); 
        vault.deposit(quoteToken, quoteAmount);

        emit Rebalanced(baseAmount, quoteAmount, shortFall);
        return (baseAmount, quoteAmount);

## Discussion

**WarTech9**

This is a duplicate of #339 

**0x00052**

Two separate issues here. #339 is pointing out it's not approved for the swapper. This one is pointing out it's not approved for the vault. It should be approved for both

**WarTech9**

@0x00052 good catch. You'

*[Content truncated...]*

---

### Example 15: [M-23] Function `withdraw()` and `redeem()` in ERC4626RouterBase would revert always because they have unnecessary allowance setting

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

- Total findings analyzed: 15
- Examples shown: 15
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

