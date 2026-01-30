# Grief Attack Security Patterns

## Overview

**Frequency**: 12 occurrences (0.02% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 3 | 9 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, MixBytes, Zokyo, Cyfrin

---

## Detection Checklist

- [ ] Check for grief attack vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: TRST-H-5 The attacker can use larger dust when opening a position to perform griefing attacks

**Source**: Trust Security
**Protocol**: Stella
**Impact**: HIGH

**Details**:

**Description:**
When opening a position, unused assets are sent to **dustVault** as dust, but since these dust 
are not subtracted from **inputAmt**, they are included in the calculation of 
**positionOpenUSDValueE36**, resulting in a small **netPnLE36**, which can be used by an 
attacker to perform a griefing attack. 
```solidity
            uint inputTotalUSDValueE36;
                for (uint i; i < openTokenInfos.length; ) {
                 inputTotalUSDValueE36 += openTokenInfos[i].inputAmt * tokenPriceE36s[i];
                      borrowTotalUSDValueE36 += openTokenInfos[i].borrowAmt * tokenPriceE36s[i];
                 unchecked {
            ++i;
                }
            }
                // 1.3 calculate net pnl (including strategy users & borrow profit)
            positionOpenUSDValueE36 = inputTotalUSDValueE36 + borrowTotalUSDValueE36;
            netPnLE36 = positionCurUSDValueE36.toInt256() - positionOpenUSDValueE36.toInt256();
```
Consider ETH:USDC = 1:1000, **posMinLpSlippageMultiplierE18s = 0.95e18**
1. Alice opens a position with 2.5 ETH and 2000 USDC, borrows 3 ETH and 3000 USDC, and 
then dust = 0.5 ETH is sent to **dustVault**. The value of the LP position is actually 10000 USD, 
since **lpUSDValueE36(10000) > minLpUSDValueE36(10500*0.95 = 9975),** it can pass the LP 
value validation.
```solidity
            minLpUSDValueE36 = ((inputUSDValueE36 + borrowUSDValueE36) *
               IConfig(_config).posMinLpSlippageMultiplierE18s(strategy)) / ON

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Trust Security/2023-05-29-Stella.md)

---

### Example 2: [M-01] Gas griefing/attack via creating the proposals

**Source**: Code4rena
**Protocol**: Kleidi
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2024-10-kleidi/blob/c474b9480850d08514c100b415efcbc962608c62/src/Timelock.sol#L512-L539><br>
<https://github.com/code-423n4/2024-10-kleidi/blob/c474b9480850d08514c100b415efcbc962608c62/src/Timelock.sol#L652-L665>

The timelock acts in a way that once the proposals are submitted, they need to be cancelled or executed. This behaviour opens up a griefing attack vector towards the owners of the vault in case at least `threshold` amount of owners' private keys are exposed.

When the keys are exposed, the attackers can send as many transactions as they need to the network from the safe with different salts. Even if one of the transactions go through, funds can be stolen. The protocol defence mechanisms in these situations is (1) Pause guardian can cancel all the proposals (2) Cold signers can cancel proposals.

Both these defence mechanisms require gas usage from the victim's accounts, and **it is important to note that they can not use the funds inside the Kleidi wallet**. This can lead to a gas war between attackers and the victims and can cause them to at least cause a griefing attack.

### Impact

Assumption in this section is that the victims do not get external help and they have invested most of their liquidity inside Kleidi, and only kept minimal amounts out for gas payments.

*   Imagine if victims have access to `F` amounts of funds, and 95% of those funds is locked into Kleidi.
*   The proof of concept below shows that the gas consumption o

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-10-kleidi)

---

### Example 3: [H-02] denial of service

**Source**: Code4rena
**Protocol**: Hubble
**Impact**: HIGH

**Details**:

_Submitted by danb, also found by cmichel, csanuragjain, hyh, kirk-baird, leastwood, Meta0xNull, minhquanym, Omik, robee, Ruhum, and throttle_

<https://github.com/code-423n4/2022-02-hubble/blob/main/contracts/VUSD.sol#L53><br>

processWithdrawals can process limited amount in each call.<br>
An attacker can push to withdrawals enormous amount of withdrawals with amount = 0.<br>
In order to stop the dos attack and process the withdrawal, the governance needs to spend as much gas as the attacker.<br>
If the governance doesn't have enough money to pay for the gas, the withdrawals can't be processed.

### Proof of Concept

Alice wants to attack vusd, she spends 1 millions dollars for gas to push as many withdrawals of amount = 0 as she can.<br>
If the governance wants to process the deposits after Alices empty deposits, they also need to spend at least 1 million dollars for gas in order to process Alice's withdrawals first.<br>
But the governance doesn't have 1 million dollars so the funds will be locked.

### Recommended Mitigation Steps

Set a minimum amount of withdrawal. e.g. 1 dollar

        function withdraw(uint amount) external {
            require(amount >= 10 ** 6);
            burn(amount);
            withdrawals.push(Withdrawal(msg.sender, amount));
        }

**[atvanguard (Hubble) confirmed, but disagreed with High severity and commented](https://github.com/code-423n4/2022-02-hubble-findings/issues/119#issuecomment-1049473996):**
 > Confirming this is an issue. W

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-02-hubble)

---

### Example 4: [M-14] Lender of a PAY order lending can grief renter of the payment

**Source**: Code4rena
**Protocol**: reNFT
**Impact**: MEDIUM

**Details**:

<https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L33> 

<https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L43>

In a PAY order lending, the renter is payed by the lender to rent the NFT. When the rent is stopped, [`Stop.stopRent()`](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L265), transfers the NFT from the renter's Safe back to the lender and transfers the payment to the renter.

To transfer the NFT from the Safe, [`_reclaimRentedItems()`](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L166) is used, which makes the Safe contract execute a delegatecall to `Stop.reclaimRentalOrder()`, which is inherited from [`Reclaimer.sol`](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L71). This function uses [`ERC721.safeTransferFrom()`](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L33) or [`ERC1155.safeTransferFrom()`](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/packages/Reclaimer.sol#L43) to transfer the the NFT.

If the recipient of the NFT (the lender's wallet) is a smart contract, the `safeTransferFrom()` functions will call the `onERC721Rec

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-renft)

---

### Example 5: [M-12] paused ERC721/ERC1155 could cause stopRent to revert, potentially causing issues for the lender.

**Source**: Code4rena
**Protocol**: reNFT
**Impact**: MEDIUM

**Details**:

Many ERC721/ERC1155 tokens, including well-known games such as Axie Infinity, have a pause functionality inside the contract. This pause functionality will cause the `stopRent` call to always revert and could cause issues, especially for the `PAY` order type.

### Proof of Concept

When `stopRent` /`stopRentBatch` is called, it will eventually trigger `  _reclaimRentedItems ` and execute `reclaimRentalOrder` from the safe to send back tokens to lender.

<https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L353> 

<https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L293> 

<https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L166-L183>



```solidity
    function _reclaimRentedItems(RentalOrder memory order) internal {
        // Transfer ERC721s from the renter back to lender.
        bool success = ISafe(order.rentalWallet).execTransactionFromModule(
            // Stop policy inherits the reclaimer package.
            address(this),
            // value.
            0,
            // The encoded call to the `reclaimRentalOrder` function.
            abi.encodeWithSelector(this.reclaimRentalOrder.selector, order),
            // Safe must delegate call to the stop policy so that it is the msg.sender.
            Enum.Operation.DelegateCall
        );

        // Assert that the transfer back to the len

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-renft)

---

### Example 6: [M-05] Possible DoS When calling `GammaTradeMarket::_removePosition` will cause user position to not be able to get liquidated

**Source**: Code4rena
**Protocol**: Predy
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2024-05-predy/blob/a9246db5f874a91fb71c296aac6a66902289306a/src/markets/gamma/ArrayLib.sol#L20-L32><br><https://github.com/code-423n4/2024-05-predy/blob/a9246db5f874a91fb71c296aac6a66902289306a/src/markets/gamma/GammaTradeMarket.sol#L146-L149>

### Impact

Griefing/DOS attack is possible when, a malicious user creates many very small positions, which could cause excessive gas consumed and even transactions reverted when other users are trying to liquidate any of the user's positions.

### Proof of Concept

The function `GammaTradeMarket.sol:_removePosition` is using the `ArrayLib::removeItem`, which is currently just looping over the items, until it finds the one it's looking for.

```solidity
function _removePosition(uint256 positionId) internal {x
        address trader = userPositions[positionId].owner;

@>        positionIDs[trader].removeItem(positionId);
    }
```

```solidity
 function removeItem(uint256[] storage items, uint256 item) internal {
        uint256 index = getItemIndex(items, item);

        removeItemByIndex(items, index);
    }
...

    function getItemIndex(uint256[] memory items, uint256 item) internal pure returns (uint256) {
        uint256 index = type(uint256).max;

        //@review - If items length is bigger, it could revert due to reaching block gas limit
        for (uint256 i = 0; i < items.length; i++) {
            if (items[i] == item) {
                index = i;
                break;
            }
        

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-05-predy)

---

### Example 7: M-4: Griefing attack is possible via TrueFi borrowing

**Source**: Sherlock
**Protocol**: Sherlock
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-sherlock-judging/tree/main/017-M 

## Found by 
hyh

## Summary

As TrueFiStrategy net asset value reported with _balanceOf() depends on the TrueFi liquidity situation, which can be modified by any user eligible for TrueFi loans, a griefing attack of borrowing right ahead of Sherlock requesting NAV figure from the strategy is possible.

## Vulnerability Detail

On observing a Sherlock's redeemNFT() or arbRestake() from Bob the target user, Alice the attacker will front run his transaction with borrow() call, reducing the amount of liquid funds a TrueFiPool2 has, immediately repaying her debt right afterwards. I.e. Alice will become a short term debtor for sandwiching Bob's redeemNFT(). Alice needs to be whitelisted as a borrower, which is achievable, and her status will not be affected by this attack and examined alone her actions are legitimate, i.e. she only takes are repays short-term loan, which is valid usage of TrueFi.

As loan term is small the overall cost of the attack (that consists of the loan interest along with gas costs for borrow and repay transactions) isn't substantial for Alice, while Bob can incur big enough slippage as TrueFiStrategy's _balanceOf() will observe low `liquidValue()` and thus high `liquidExitPenalty(totalAmount)` of the TrueFiPool2, diminishing the value of the Bob's withdrawal. Alice can repeat this many times over with various Sherlock users.

## Impact

Sherlock stakers who unstaked will in

*[Content truncated...]*

---

### Example 8: Attacker Can Grief Liquidations And Repayments

**Source**: Zokyo
**Protocol**: Creditswap
**Impact**: HIGH

**Details**:

**Severity** - Critical

**Status** - Resolved 

**Description**

To liquidate an unhealthy loan position the liquidate() function inside CreditorNFT can be called by anyone where the debtAmount of debt token is paid out by the liquidator.
This function in turn calls the liquidate function of LoanVault at L133.

Inside LoanVault.sol’s liquidate() it is checked if the debtAmount (initial debt amount when loan was created) is now equal to the balance of debt token in the vault , if not revert (L163)

An attacker can see a liquidation() call in the mempool and ->

a.) Frontruns this call to send the lowest amount of debt token to the vault , say 1
b.) Now when the liquidator tries to liquidate he sends out debtAmount of tokens to the vault , let’s say they were 100
c.) It is checked that debt amount and balance of debt token balance in the vault is equal
d.) But they are not since there are a total of 101 debt tokens now , liquidation reverts.

Due to this the vault/loan position can never be liquidated and the protocol will continue to incur huge losses as the collateral value falls down.

The same problem lies in repay functionality , at L150 in LoanVault.sol it will revert due to the same case as above and make it impossible for a debtor to repay their loan , resulting in forced liquidations.

**Recommendation**:

Have an internal accounting system or change the condition to if the balance in the vault is less than debt amount, then revert instead of a strict equality.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Zokyo/2023-12-22-CreditSwap.md)

---

### Example 9: Transaction DOS via `permit()` front-running

**Source**: MixBytes
**Protocol**: EYWA
**Impact**: MEDIUM

**Details**:

##### Description

The `permit()` data,  once submitted, is publicly accessible in the mempool, allowing anyone to execute the permit by replicating the transaction arguments. Once `permit()` has been called, the second call with identical parameters will revert.

In a scenario where a signed transaction includes `PERMIT_CODE`, a malicious actor could frontrun and "activate" this permit, bypassing the router's `start()` function. As a result, the legitimate user's `start()` transaction would fail:
- https://github.com/eywa-protocol/eywa-clp/blob/d68ba027ff19e927d64de123b2b02f15a43f8214/contracts/RouterV2.sol#L99-L109

Reference:
- https://www.trust-security.xyz/post/permission-denied

##### Recommendation

We recommended using the `try/catch` pattern for permit operations to prevent reverts.

**Reference**: [View Original Finding](https://github.com/mixbytes/audits_public/blob/master/EYWA/CLP/README.md#5-transaction-dos-via-permit-front-running)

---

### Example 10: M-4: Used orders or revoked token authorizations can cause `withdrawAuction` and `depositAuction` to fail

**Source**: Sherlock
**Protocol**: Opyn Crab Netting
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-opyn-judging/issues/60 

## Found by 
indijanc, Haruxe, seyni, zimu, Jeiwan, thec00n

## Summary
The owner must ensure that all orders are valid before submitting an auction, as a single order failure can revert an entire auction. The current implementation allows a market maker to invalidate their order by front-running an auction transaction, causing the auction to fail. Other ways to cause the auction functions to fail are listed below.  

## Vulnerability Detail 
A market maker can invalidate their order when `withdrawAuction()` and `depositAuction()` is submitted from the owner by:

- setting the nonce of their order as used by calling `setNonceTrue()` or by calling `checkOrder()` and setting the nonce of orders as used (see https://github.com/sherlock-audit/2022-11-opyn-thec00n/issues/1).
- By revoking permissions to transfer tokens for the `CrabNetting` contract or transferring required tokens from the trading account so that the transfer fails.  

Large user withdrawals could also occur right before the auction is submitted which could could cause the auction functions to fail. 

## Impact
A malicious market maker or user could perform a griefing attack and repeatedly cause auctions to fail. 

## Code Snippet
https://github.com/sherlock-audit/2022-11-opyn/blob/main/crab-netting/src/CrabNetting.sol#L756-L759

https://github.com/sherlock-audit/2022-11-opyn/blob/main/crab-netting/src/CrabNetting.sol#L507-L524

https://git

*[Content truncated...]*

---

### Example 11: M-16: Users can be griefed due to lack of minimum size within the Loan and Offer

**Source**: Sherlock
**Protocol**: Debita Finance V3
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-10-debita-judging/issues/557 

## Found by 
xiaoming90
### Summary

_No response_

### Root Cause

_No response_

### Internal pre-conditions

_No response_

### External pre-conditions

_No response_

### Attack Path

Assume that Bob creates a borrow offer with 10000 AERO as collateral to borrow 10000 USDC at the price/ratio of 1 AERO:1 USDC for simplicity's sake.

Malicious aggregator (aggregator is a public role and anyone can match orders) can perform griefing attacks against Bob.

The malicious aggregator can create many individual loans OR many loans with many offers within it, OR a combination of both. Each loan and offer will be small or tiny and consist of Bob's borrow order. This can be done because the protocol does not enforce any restriction on the minimum size of the loan or offer.

As a result, Bob's borrow offer could be broken down into countless (e.g., thousands or millions) of loans and offers. As a result, Bob will not be able to keep track of all the loans and offers belonging to him and will have issues paying the debt or claiming collateral.

This issue is also relevant to the lenders, and the impact is even more serious as lenders have to perform more actions against loans and offers, such as claiming debt, claiming interest, claiming collateral, or auctioning off defaulted collateral etc.

In addition, it also requires lenders and borrowers to pay a significant amount of gas fees in order to carry out the

*[Content truncated...]*

---

### Example 12: A malicious user can grief a `StakePet` contract by creating massive number of pets

**Source**: Cyfrin
**Protocol**: Stakepet
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Description:** The `StakePet::create` function facilitates the minting of a pet NFT by depositing collateral. However, its lack of a minimum deposit requirement for minting exposes it to potential abuse. A malicious user can exploit this by minting an excessive number of NFTs. Notably, this behaviour can strain functions like `StakePetManager::buryAllDeadPets`, which in turn calls `StakePetManager::getDeadNonBuriedPets`. This latter function iterates through all pet IDs to identify pets that are dead but not yet buried.

**Impact:** When a function processes an extensive and potentially unlimited list of pet IDs, there's a risk of it consuming all available gas. Consequently, it can fail, throwing an out-of-gas exception, which negatively affects users trying to interact with the contract.

**Recommended Mitigation:** To deter such griefing attacks, it's advisable to introduce a minimum deposit requirement for the creation of a new pet. Setting this threshold ensures that the mass-minting strategy becomes cost-prohibitive for attackers.

**Client:** Fixed in commit [a692abc](https://github.com/Ranama/StakePet/commit/a692abc038fdd8992916f93d213a38c30e3a9764).

**Cyfrin:** Verified.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-19-cyfrin-stakepet.md)

---

## Statistics

- Total findings analyzed: 12
- Examples shown: 12
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

