# Min/Max Cap Validation Security Patterns

## Overview

**Frequency**: 9 occurrences (0.02% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 7 | 0 | 0 |

**Common Sources**: Spearbit, Code4rena, Sherlock

---

## Detection Checklist

- [ ] Check for min/max cap validation vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: H-3: Unbounded `_unlockTime` allows the attacker to get a huge `stakedTimeBonus` and dominate the voting

**Source**: Sherlock
**Protocol**: FrankenDAO
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-frankendao-judging/issues/53 

## Found by 
Trumpero, WATCHPUG, neumo, bin2chen, curiousapple, koxuan, John, hansfriese

## Summary

`stakingSettings.maxStakeBonusTime` is not enforced, allowing the attacker to gain a huge `stakedTimeBonus` by using a huge value for `_unlockTime`.

## Vulnerability Detail

There is no max `_unlockTime` check in `_stakeToken()` to enforce the `stakingSettings.maxStakeBonusTime`.

As a result, an attacker can set a huge value for `_unlockTime` and get an enormous `stakedTimeBonus`.

## Impact

The attacker can get a huge amount of votes and dominate the voting.

## Code Snippet

https://github.com/sherlock-audit/2022-11-frankendao/blob/main/src/Staking.sol#L389-L394

https://github.com/sherlock-audit/2022-11-frankendao/blob/main/src/Staking.sol#L356-L384

## Tool used

Manual Review

## Recommendation

Change to:

```solidity
  function _stakeToken(uint _tokenId, uint _unlockTime) internal returns (uint) {
    if (_unlockTime > 0) {
      unlockTime[_tokenId] = _unlockTime;
      uint time = _unlockTime - block.timestamp;
      uint maxtime = stakingSettings.maxStakeBonusTime;
      uint maxBonus = stakingSettings.maxStakeBonusAmount;
      if (time < stakingSettings.maxStakeBonusTime){
        uint fullStakedTimeBonus = (time * maxBonus) / maxtime;
      }else{
        uint fullStakedTimeBonus = maxBonus;
      }
      stakedTimeBonus[_tokenId] = _tokenId < 10000 ? fullStakedTimeBonus : fullSta

*[Content truncated...]*

---

### Example 2: Liens cannot be bought out once we've reached the maximum number of active liens on one collateral

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
LienToken.sol#L373-375

## Description
The `buyoutLien` function is intended to transfer ownership of a lien from one user to another. In practice, it creates a new lien by calling `_createLien` and then calls `_replaceStackAtPositionWithNewLien` to update the stack.

In the `_createLien` function, there is a check to ensure we don't take out more than `maxLiens` against one piece of collateral:

```solidity
if (params.stack.length >= s.maxLiens) {
    revert InvalidState(InvalidStates.MAX_LIENS);
}
```

The result is that, when we already have `maxLiens` and we try to buy one out, this function will revert.

## Recommendation
Move this check from `_createLien` into the `_appendStack` function, which is only called when new liens are created rather than when they are bought out.

## Astaria
Fixed in PR 213.

## Spearbit
Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 3: Absence of Minimum delayBlocks

**Source**: Spearbit
**Protocol**: Connext
**Impact**: MEDIUM

**Details**:

## Vulnerability Report

## Severity
**Medium Risk**

## Context
- `RootManager.sol#L102-106`
- `SpokeConnector.sol#L218-L221`

## Description
The owner can accidentally set `delayBlocks` to `0` (or a very small delay block), which will collapse the whole fraud protection mechanism. Since there is no check for a minimum delay before setting a new delay value, even a low value will be accepted by the `setDelayBlocks` function:

```solidity
function setDelayBlocks(uint256 _delayBlocks) public onlyOwner {
    require(_delayBlocks != delayBlocks, "!delayBlocks");
    emit DelayBlocksUpdated(_delayBlocks, delayBlocks);
    delayBlocks = _delayBlocks;
}
```

## Recommendation
Introduce a variable `minDelay` that specifies the minimum possible delay allowed by the contract. Any attempt to change the delay value using the `setDelayBlocks` function should ensure that the new delay is larger than or equal to `minDelay`.

## Connext
We could add a minimum for when `delayBlocks` is not `0`, but that minimum will vary by chain/block time, so that minimum has to be configurable. We could add a separate configuration endpoint and make it so it takes 72 hours to change the delay blocks minimum. However, that feels more like DAO functionality/responsibility. For that reason, we are going with "acknowledged." At the very least, users can visibly check what the `delayBlocks` are set to on-chain to ensure it's reasonable.

## Spearbit
**Acknowledged**

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 4: [M-18] Node runners can lose all their stake rewards due to how the DAO commissions can be set to a 100%

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: MEDIUM

**Details**:

Node runners can have all their stake rewards taken by the DAO as commissions can be set to a 100%.

### Proof of Concept

There is no limits on `_updateDAORevenueCommission()` except not exceeding `MODULO`, which means it can be set to a 100%.

[LiquidStakingManager.sol#L948-L955](https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/LiquidStakingManager.sol#L948-L955)

```solidity
    function _updateDAORevenueCommission(uint256 _commissionPercentage) internal {
        require(_commissionPercentage <= MODULO, "Invalid commission");

        emit DAOCommissionUpdated(daoCommissionPercentage, _commissionPercentage);

        daoCommissionPercentage = _commissionPercentage;
    }
```

This percentage is used to calculate `uint256 daoAmount = (_received * daoCommissionPercentage) / MODULO` in `_calculateCommission()`.<br>
Remaining is then calculated with `uint256 rest = _received - daoAmount`, and in this case `rest = 0`.<br>
When node runner calls `claimRewardsAsNodeRunner()`, the node runner will receive 0 rewards.<br>

### Recommended Mitigation Steps

There should be maximum cap on how much commission DAO can take from node runners.

**[vince0656 (Stakehouse) disputed and commented](https://github.com/code-423n4/2022-11-stakehouse-findings/issues/190#issuecomment-1329453031):**
  > Node runners can see ahead of time what the % commission is and therefore, they can make a decision based on that. However, on 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 5: H-3: RageTrade senior vault USDC deposits are subject to utilization caps which can lock deposits for long periods of time leading to UXD instability

**Source**: Sherlock
**Protocol**: UXD Protocol
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-uxd-judging/issues/253 

## Found by 
clems4ever, ctf\_sec, 0x52, 0xNazgul

## Summary

RageTrade senior vault requires that it maintains deposits above and beyond the current amount loaned to the junior vault. Currently this is set at 90%, that is the vault must maintain at least 10% more deposits than loans. Currently the junior vault is in high demand and very little can be withdrawn from the senior vault. A situation like this is far from ideal because in the even that there is a strong depeg of UXD a large portion of the collateral could be locked in the vault unable to be withdrawn.

## Vulnerability Detail

[DnGmxSeniorVault.sol](https://arbiscan.io/address/0x66aca71a2e62022f9f23a50ab737ded372ad00cf#code#F31#L288)

    function beforeWithdraw(
        uint256 assets,
        uint256,
        address
    ) internal override {
        /// @dev withdrawal will fail if the utilization goes above maxUtilization value due to a withdrawal
        // totalUsdcBorrowed will reduce when borrower (junior vault) repays
        if (totalUsdcBorrowed() > ((totalAssets() - assets) * maxUtilizationBps) / MAX_BPS)
            revert MaxUtilizationBreached();

        // take out required assets from aave lending pool
        pool.withdraw(address(asset), assets, address(this));
    }

DnGmxSeniorVault.sol#beforeWithdraw is called before each withdraw and will revert if the withdraw lowers the utilization of the vault below a certain thr

*[Content truncated...]*

---

### Example 6: Limits in LIFuelFacet

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
LIFuelFacet.sol#L72-L101

## Description
The facet **LIFuelFacet** is meant for small amounts; however, it doesn't have any limits on the funds sent. This might result in funds getting stuck due to insufficient liquidity on the receiving side.

```solidity
function _startBridge(...) {
    ...
    if (LibAsset.isNativeAsset(_bridgeData.sendingAssetId)) {
        serviceFeeCollector.collectNativeGasFees{...}(...);
    } else {
        LibAsset.maxApproveERC20(...);
        serviceFeeCollector.collectTokenGasFees(...);
        ...
    }
}
```

## Recommendation
Consider enforcing limits in **LIFuelFacet**.

## LiFi
Limits apply to all bridges and depend on the liquidity on the receiving chain. This information is usually not available on the source chain. For sure, some high fixed limits could be added, but they don't really check that there is that much liquidity available. Checking limits and applying them to the calls is handled by the backend.

## Spearbit
Acknowledged.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-retainer1-Spearbit-Security-Review.pdf)

---

### Example 7: ERC721A has mint caps that are not checked by ERC721SeaDrop

**Source**: Spearbit
**Protocol**: SeaDrop
**Impact**: MEDIUM

**Details**:

## Medium Risk Severity Report

## Context
`ERC721SeaDrop.sol#L137-L145`

## Description
`ERC721SeaDrop` inherits from `ERC721A`, which packs `balance`, `numberMinted`, `numberBurned`, and an extra data chunk into one storage slot (64 bits per sub-storage) for every address. This creates an inherent cap of \( 2^{64} - 1 \) on all these different fields. Currently, there is no check in `ERC721A`'s `_mint` for quantity nor in `ERC721SeaDrop`'s `mintSeaDrop` function.

Additionally, if an owner is close to reaching the maximum cap for their balance and someone else transfers a token to this owner, an overflow may occur for the balance and possibly the number of mints in `_packedAddressData`. This overflow could potentially reduce the balance and the `numberMinted` to a much lower number, while `numberBurned` could be increased to a much higher number.

## Recommendation
We should implement an additional check to verify if the quantity would exceed the mint cap in `mintSeaDrop`.

## OpenSea
We will add checks regarding the `ERC721A` limits. A restraint has been implemented where `maxSupply` cannot be set greater than \( 2^{64} - 1 \) so that neither balance nor number minted can exceed this limit. See the commit `5a98d29`.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Seadrop-Spearbit-Security-Review.pdf)

---

### Example 8: [M-01] Attacker can list an NFT they own and inflate to zero all users contributions, keeping the NFT and all the money

**Source**: Code4rena
**Protocol**: PartyDAO
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/PartyDAO/party-contracts-c4/blob/3896577b8f0fa16cba129dc2867aba786b730c1b/contracts/crowdfund/BuyCrowdfundBase.sol#L117-L118


## Vulnerability details

## Description
Crowdfunds split the voting power and distribution of profits rights according to the percentage used to purchase the NFT. When an attacker lists his own NFT for sale and contributes to it, any sum he contributes will return to him once the sell is executed. This behavior is fine so long as the sell price is fair, as other contributors will receive a fair portion of voting power and equity.  Therefore, when a maximum price is defined, it is not considered a vulnerability that an attacker can contribute ```maximumPrice - totalContributions``` and take a potentially large stake of the Crowdfund, as user's have contributed knowing the potential maximum price. 

However, when maximum price is zero, which is allowed in BuyCrowdfund and CollectionBuyCrowdfund, the lister of the NFT can always steal the entirety of the fund and keep the NFT. Attacker can send a massive contribution, buy the NFT and pass a unanimous proposal to approve the NFT to his wallet. Attacker can use a flash loan to finance the initial contribution, which is easily paid back from the NFT lister wallet.

It is important to note that there is no way for the system to know if the Crowdfund creator and the NFT owner are the same entity, and therefore it is critical for the platform to defend users against this s

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-party)

---

### Example 9: [M-11] Position owner should set allowed slippage

**Source**: Code4rena
**Protocol**: Backd
**Impact**: MEDIUM

**Details**:

_Submitted by 0x52_

[TopUpAction.sol#L154](https://github.com/code-423n4/2022-04-backd/blob/c856714a50437cb33240a5964b63687c9876275b/backd/contracts/actions/topup/TopUpAction.sol#L154)<br>
[TopUpAction.sol#L187](https://github.com/code-423n4/2022-04-backd/blob/c856714a50437cb33240a5964b63687c9876275b/backd/contracts/actions/topup/TopUpAction.sol#L187)<br>

The default swap slippage of 5% allows malicious keepers to sandwich attack topup. Additionally, up to 40% (\_MIN_SWAPPER_SLIPPAGE) slippage allows malicious owner to sandwich huge amounts from topup

### Proof of Concept

Keeper can bundle swaps before and after topup to sandwich topup action, in fact it's actually in their best interest to do so.

### Recommended Mitigation Steps

Allow user to specify max swap slippage when creating topup similar to how it's specified on uniswap or sushiswap to block attacks from both keepers and owners.

**[chase-manning (Backd) confirmed and resolved](https://github.com/code-423n4/2022-04-backd-findings/issues/87)**

**[gzeon (judge) commented](https://github.com/code-423n4/2022-04-backd-findings/issues/87#issuecomment-1121225398):**
 > According to [C4 Judging criteria](https://docs.code4rena.com/roles/judges/how-to-judge-a-contest#notes-on-judging)
> > Unless there is something uniquely novel created by combining vectors, most submissions regarding vulnerabilities that are inherent to a particular system or the Ethereum network as a whole should be considered QA. Examples of such vu

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-04-backd)

---

## Statistics

- Total findings analyzed: 9
- Examples shown: 9
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

