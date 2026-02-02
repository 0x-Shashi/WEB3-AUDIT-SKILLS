---
id: PAT-REFUND-ETHER
title: Refund Ether Security Patterns
category: ether
severity: medium
difficulty: advanced
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - refund
  - excess
  - return

finding_count: 12
last_updated: 2026-01-31
---
# Refund Ether Security Patterns

## Overview

**Frequency**: 12 occurrences (0.02% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 10 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Spearbit

---

## Detection Checklist

- [ ] Check for refund ether vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [M-22] ETH sent when calling executeAsSmartWallet function can be lost

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liquid-staking/LiquidStakingManager.sol#L202-L215
https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/smart-wallet/OwnableSmartWallet.sol#L52-L64


## Vulnerability details

## Impact
Calling the `executeAsSmartWallet` function by the DAO further calls the `OwnableSmartWallet.execute` function. Since the `executeAsSmartWallet` function is `payable`, an ETH amount can be sent when calling it. However, since the sent ETH amount is not forwarded to the smart wallet contract, such sent amount can become locked in the `LiquidStakingManager` contract. For example, when the DAO attempts to call the `executeAsSmartWallet` function for sending some ETH to the smart wallet so the smart wallet can use it when calling its `execute` function, if the smart wallet's ETH balance is also higher than this sent ETH amount, calling the `executeAsSmartWallet` function would not revert, and the sent ETH amount is locked in the `LiquidStakingManager` contract while such amount is deducted from the smart wallet's ETH balance for being sent to the target address. Besides that this is against the intention of the DAO, the DAO loses the sent ETH amount that becomes locked in the `LiquidStakingManager` contract, and the node runner loses the amount that is unexpectedly deducted from the corresponding smart wallet's ETH balance.

https://github.com/code-423n4/2022-11-stakehouse/blob/main/contracts/liqu

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 2: [M-08] Mistakenly sent eth could be locked

**Source**: Code4rena
**Protocol**: Debt DAO
**Impact**: MEDIUM

**Details**:

If ERC20 and eth are transferred at same time, the mistakenly sent eth will be locked.

There are several functions that could be affected and cause user fund lock:

*   `addCollateral()`
*   `addCredit()`
*   `increaseCredit()`
*   `depositAndClose()`
*   `depositAndRepay()`
*   `close()`

### Proof of Concept

In `receiveTokenOrETH()`, different logic is used to handle ERC20 and eth transfer. However, in the ERC20 if block, mistakenly sent eth will be ignored. This part of eth will be locked in the contract.

```solidity
// Line-of-Credit/contracts/utils/LineLib.sol
    function receiveTokenOrETH(
      address token,
      address sender,
      uint256 amount
    )
      external
      returns (bool)
    {
        if(token == address(0)) { revert TransferFailed(); }
        if(token != Denominations.ETH) { // ERC20
            IERC20(token).safeTransferFrom(sender, address(this), amount);
        } else { // ETH
            if(msg.value < amount) { revert TransferFailed(); }
        }
        return true;
    }
```

### Recommended Mitigation Steps

In the ERC20 part, add check for `msg.value` to ensure no eth is sent:

```solidity
        if(token != Denominations.ETH) { // ERC20
            if (msg.value > 0) { revert TransferFailed(); }
            IERC20(token).safeTransferFrom(sender, address(this), amount);
        } else { // ETH
```

**[kibagateaux (Debt DAO) confirmed](https://github.com/code-423n4/2022-11-debtdao-findings/issues/355#issuecomment-1405077581)**





*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-debtdao)

---

### Example 3: [M-08] `_payoutEth()` calculates `balance` with an offset, always leaving dust `ETH` in the contract

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: MEDIUM

**Details**:

[PA1D.sol#L391](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/enforcer/PA1D.sol#L391)<br>
[PA1D.sol#L395](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/enforcer/PA1D.sol#L395)<br>

Payout recipients can call `getEthPayout()` to transfer the ETH balance of the contract to all payout recipients.<br>
This function makes an internal call to `_payoutEth`, which sends the payment to the recipients based on their associated `bp`.

The issue is that the `balance` used in the `transfer` calls is not the contract ETH balance, but the balance minus a `gasCost`.

This means `getEthPayout()` calls will leave dust in the contract.

### Impact

If the dust is small enough, a subsequent call to `getEthPayout` is likely to revert because of [this check](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/enforcer/PA1D.sol#L390).<br>
And `enforcer/PA1D` does not have any other ETH withdrawal function. While `enforcer/PA1D` is meant to be used via delegate calls from a NFT collection contract, if the NFT contract does not have any withdrawal function either, this dust mentioned above is effectively lost.

### Proof of Concept

Let us take the example of a payout recipient trying to retrieve their share of the balance, equal to `40_000` For simplicity, assume one payout address, owned by Alice:

*   Alice calls `getEthPayout()`, w

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 4: [H-01] SpeedBumpPriceGate: Excess ether did not return to the user

**Source**: Code4rena
**Protocol**: FactoryDAO
**Impact**: HIGH

**Details**:

_Submitted by cccz, also found by 0x52, 0xYamiDancho, csanuragjain, GimelSec, gzeon, hickuphh3, horsefacts, hyh, IllIllI, kenzo, leastwood, PPrieditis, reassor, unforgiven, WatchPug, and danb_

The `passThruGate` function of the `SpeedBumpPriceGate` contract is used to charge NFT purchase fees.
Since the price of NFT will change due to the previous purchase, users are likely to send more ether than the actual purchase price in order to ensure that they can purchase NFT. However, the passThruGate function did not return the excess ether, which would cause asset loss to the user.
Consider the following scenario:

1.  An NFT is sold for 0.15 eth
2.  User A believes that the value of the NFT is acceptable within 0.3 eth, considering that someone may buy the NFT before him, so user A transfers 0.3 eth to buy the NFT
3.  When user A's transaction is executed, the price of the NFT is 0.15 eth, but since the contract does not return excess eth, user A actually spends 0.3 eth.

### Proof of Concept

<https://github.com/code-423n4/2022-05-factorydao/blob/e22a562c01c533b8765229387894cc0cb9bed116/contracts/SpeedBumpPriceGate.sol#L65-L82>


### Recommended Mitigation Steps

    -   function passThruGate(uint index, address) override external payable {
    +  function passThruGate(uint index, address payer) override external payable {
            uint price = getCost(index);
            require(msg.value >= price, 'Please send more ETH');

            // bump up the price
            Gate 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-factorydao)

---

### Example 5: [M-05] It is possible that operator loses sent ETH after calling `HolographOperator` contract's `executeJob` function

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: MEDIUM

**Details**:

ETH can be sent when calling the `HolographOperator` contract's `executeJob` function, which can execute the following code.

```solidity
File: contracts\HolographOperator.sol
419:     try
420:       HolographOperatorInterface(address(this)).nonRevertingBridgeCall{value: msg.value}(
421:         msg.sender,
422:         bridgeInRequestPayload
423:       )
424:     {
425:       /// @dev do nothing
426:     } catch {
427:       _failedJobs[hash] = true;
428:       emit FailedOperatorJob(hash);
429:     }
```

Executing the `try ... {...} catch {...}` code mentioned above will execute `HolographOperatorInterface(address(this)).nonRevertingBridgeCall{value: msg.value}(...)`. Calling the `nonRevertingBridgeCall` function can possibly execute `revert(0, 0)` if the external call to the bridge contract is not successful. When this occurs, the code in the `catch` block of the `try ... {...} catch {...}` code mentioned above will run, which does not make calling the `executeJob` function revert. As a result, even though the job is not successfully executed, the sent ETH is locked in the `HolographOperator` contract since there is no other way to transfer such sent ETH out from this contract. In this situation, the operator that calls the `executeJob` function will lose the sent ETH.

<https://github.com/code-423n4/2022-10-holograph/blob/main/contracts/HolographOperator.sol#L301-L439>

```solidity
  function executeJob(bytes calldata bridgeInRequestPayload) external payable {
    
    .

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 6: M-4: Native funds can be lost by submit() as msg.value isn't synchronized with amount

**Source**: Sherlock
**Protocol**: Telcoin
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-telcoin-judging/issues/76 

## Found by 
hyh

## Summary

When used with native funds FeeBuyback#submit() doesn't check for the `amount` argument to correspond to `msg.value` actually linked to the call. 

## Vulnerability Detail

This can lead either to bloating or to underpaying of the actual fee depending on the mechanics that will be used to call submit(). I.e. as two values can differ, and only one can be correct, the difference is a fund loss either to the `owner` (when the fee is overpaid) or to `recipient` (when the fee is underpaid vs correct formula).

## Impact

Net impact is a fund loss proportional to the difference of the `amount` and `msg.value`. This can be either incomplete setup (native funds case isn't fully covered in a calling script) or an operational mistake (it is covered correctly, but a wrong value was occasionally left from a testing, and so on) situation.

Setting the severity to be medium as this is conditional on the actual usage of submit().

## Code Snippet

submit() uses `msg.value`, which can differ from `amount`:

https://github.com/sherlock-audit/2022-11-telcoin/blob/main/contracts/fee-buyback/FeeBuyback.sol#L35-L82

```solidity
  /**
   * @notice submits wallet transactions
   * @dev a secondary swap may occur
   * @dev staking contract updates may be made
   * @dev function can be paused
   * @param wallet address of the primary transaction
   * @param walletData bytes wallet data for prim

*[Content truncated...]*

---

### Example 7: Calls to PausableZone 'sexecuteMatchAdvancedOrders and executeMatchOrders would revert if unused native tokens would need to be returned

**Source**: Spearbit
**Protocol**: SEAPORT
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
- PausableZone.sol#L34
- PausableZone.sol#L149
- PausableZone.sol#L188
- OrderCombiner.sol#L704-L707

## Description
In match (advanced) orders, one can provide native tokens as offer and consideration items. So, a PausableZone would need to provide msg.value to call the corresponding Seaport endpoints. There are a few scenarios where not all the msg.value native tokens amount provided to the Seaport marketplace will be used:

1. Rounding errors in calculating the current amount of offer or consideration items. The zone can prevent sending extra native tokens to Seaport by pre-calculating these values and making sure to have its transaction to be included in the specific block that these values were calculated for (this is important when the start and end amount of an item are not equal).
2. The zone (un)intentionally sends more native tokens than are necessary to Seaport.
3. The (advanced) orders sent for matching in Seaport include order type of CONTRACT offerer order and the offerer contract provides a different amount for at least one item that would eventually make the whole transaction not use the full amount of msg.value provided to it.

In all these cases, since PausableZone does not have a receive or fallback endpoint to accept native tokens, when Seaport tries to send back the unused native token amount, the transaction may revert.

### PausableZone not accepting native tokens:
```bash
$ export CODE=$(jq -r '.deployedBytecode' ar

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Seaport-Spearbit-Security-Review.pdf)

---

### Example 8: H-3: `TradingUtils::_executeTrade` will leak ETH to WETH

**Source**: Sherlock
**Protocol**: Notional
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/98 

## Found by 
lemonmon

## Summary

If sellToken is ETH, and using Uniswap for the dex, and it is exact out trade, too much is deposited to the WETH and does not withdraw the excess amount. It will give wrong `amountSold` value as well as accounting error.

## Vulnerability Detail

`trade.sellToken` is ETH and using Uniswap as dex, WETH should be used instead of ETH as Uniswap does not support ETH. There for TradingUtils wraps the ETH to WETH before trading.

If the trade would be exact out, the amount `trade.limit` will be deposited to WETH instead of the `trade.amount`. However, because it is exact out, not all ETH deposited will be traded. In the current implementation, there is no logic to recover the excess deposit.

As the `TradingUtils::_executeInternal`, which uses the `TradingUtils::_executeTrade` will calculate the `amountSold` based on the balance of ETH, it will return the `trade.limit` as the `amountSold`, thus resulting in accounting error.

Note: in the current implementation, the trade using Uniswap with ETH as sellToken would not even work, because the WETH is not properly approved (issue 2). This issue assumes that the issue is resolved. 

## Impact

`amountSold` will reflect not the amount really sold, rather the `trade.limit`. It is unclear whether the excess amount of ETH, which is deposited for WETH can be recovered.

## Code Snippet

https://github.com/sherlock-audit/2022-09-n

*[Content truncated...]*

---

### Example 9: [M-03] Giant pools cannot receive ETH from vaults

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantSavETHVaultPool.sol#L137><br>
<https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantMevAndFeesPool.sol#L126>

Both giant pools are affected:

1.  GiantSavETHVaultPool
2.  bringUnusedETHBackIntoGiantPool

The giant pools have a `bringUnusedETHBackIntoGiantPool` function that calls the vaults to send back any unused ETH.
Currently, any call to this function will revert.<br>
Unused ETH will not be sent to the giant pools and will stay in the vaults.

This causes an insolvency issue when many users want to withdraw ETH and there is not enough liquidity inside the giant pools.

### Proof of Concept

`bringUnusedETHBackIntoGiantPool` calls the vaults to receive ETH:<br>
<https://github.com/code-423n4/2022-11-stakehouse/blob/4b6828e9c807f2f7c569e6d721ca1289f7cf7112/contracts/liquid-staking/GiantSavETHVaultPool.sol#L137>

        function bringUnusedETHBackIntoGiantPool(
            address[] calldata _savETHVaults,
            LPToken[][] calldata _lpTokens,
            uint256[][] calldata _amounts
        ) external {
            uint256 numOfVaults = _savETHVaults.length;
            require(numOfVaults > 0, "Empty arrays");
            require(numOfVaults == _lpTokens.length, "Inconsistent arrays");
            require(numOfVaults == _amounts.length, "Inconsistent arrays");
          

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

### Example 10: [M-03] Borrower/Lender excessive ETH not refunded and permanently locked in protocol

**Source**: Code4rena
**Protocol**: Debt DAO
**Impact**: MEDIUM

**Details**:

<https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8daa231700c5afeb3a/contracts/modules/credit/LineOfCredit.sol#L292>

<https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8daa231700c5afeb3a/contracts/modules/credit/LineOfCredit.sol#L315>

<https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8daa231700c5afeb3a/contracts/modules/credit/LineOfCredit.sol#L223>

<https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8daa231700c5afeb3a/contracts/modules/credit/LineOfCredit.sol#L265>

<https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8daa231700c5afeb3a/contracts/utils/LineLib.sol#L71>

<https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8daa231700c5afeb3a/contracts/modules/credit/LineOfCredit.sol#L388>

### Impact

The protocol does not refund overpayment of ETH. Excessive ETH is not included in the protocols accounting. As a result, the funds are permanently locked in the protocol **(Loss of funds)**.

There are multiple scenarios where excessive ETH could be sent by Borrowers and Lenders to the protocol.

The vulnerability effects at least five different scenarios and locks both the lender and borrowers ETH in LineOfCredit if overpaid. **There is no way to transfer the locked ETH back to the users**, as the withdraw methods are dependent on accounting (which is not updated with locked ETH).

This vulnerability impacts EscrowedLine, LineOfCredit, SpigotedLine and SecuredLine.


*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-debtdao)

---

### Example 11: [M-02] If L1GraphTokenGateways outboundTransfer is called by a contract, the entire msg.value is blackholed, whether the ticket got redeemed or not

**Source**: Code4rena
**Protocol**: The Graph
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-10-thegraph/blob/309a188f7215fa42c745b136357702400f91b4ff/contracts/gateway/L1GraphTokenGateway.sol#L236


## Vulnerability details

The outboundTransfer function in L1GraphTokenGateway is used to transfer user's Graph tokens to L2. To do that it eventually calls the standard Arbitrum Inbox's createRetryableTicket. The issue is that it passes caller's address in the `submissionRefundAddress` and `valueRefundAddress`. This behaves fine if caller is an EOA, but if it's called by a contract it will lead to loss of the submissionRefund (ETH passed to outboundTransfer() minus the total submission fee), or in the event of failed L2 ticket creation, the whole submission fee. The reason it's fine for EOA is because of the fact that ETH and Arbitrum addresses are congruent. However, the calling contract probably does not exist on L2 and even in the rare case it does, it might not have a function to move out the refund.

The docs don't suggest contracts should not use the TokenGateway, and it is fair to assume it will be used in this way. Multisigs are inherently contracts, which is one of the valid use cases. Since likelihood is high and impact is medium (loss of submission fee), I believe it to be a HIGH severity find.

## Impact

If L1GraphTokenGateway's outboundTransfer is called by a contract, the entire msg.value is blackholed, whether the ticket got redeemed or not.

## Proof of Concept

Alice has a multisig wallet. She sends 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-thegraph)

---

### Example 12: [M-17] WeVE (FTM) may be lost forever if redemption process is failed

**Source**: Code4rena
**Protocol**: Velodrome Finance
**Impact**: MEDIUM

**Details**:

_Submitted by Chom_

[RedemptionSender.sol#L28-L51](https://github.com/code-423n4/2022-05-velodrome/blob/7fda97c570b758bbfa7dd6724a336c43d4041740/contracts/contracts/redeem/RedemptionSender.sol#L28-L51)<br>
[RedemptionReceiver.sol#L72-L105](https://github.com/code-423n4/2022-05-velodrome/blob/7fda97c570b758bbfa7dd6724a336c43d4041740/contracts/contracts/redeem/RedemptionReceiver.sol#L72-L105)<br>

WeVE (FTM) may be lost forever if redemption process is failed.

Redemption process is likely to be failed if

*   (redeemedWEVE += amountWEVE) > eligibleWEVE
*   Not enough USDC or VELO in the contract

The case that redeem more than eligible can't be fixed because eligibleWEVE is hardcoded on contract initialization.

This mean that if there are any mistake for example LayerZero slow down and user try to repeatedly redeem their WeVE, user will lose their WeVE token forever due to contract always reverted in the destination chain due to the reason that user has redeemed more than eligible.

### Proof of Concept

1.  User redeem WeVE in fantom chain using redeemWEVE function in RedemptionSender contract.
2.  LayerZero slow but user think it is failed. (But it is just slow)
3.  User repeat process 1 again
4.  LayerZero call lzReceive in RedemptionReceiver contract on Optimism chain for the first time it's success. USDC + VELO is redeemed as intended.
5.  LayerZero call lzReceive in RedemptionReceiver contract on Optimism chain again due to repeated transaction in step 3. But this time

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-velodrome)

---

## Statistics

- Total findings analyzed: 12
- Examples shown: 12
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

