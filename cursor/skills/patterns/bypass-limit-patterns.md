# Bypass limit Security Patterns

## Overview

**Frequency**: 15 occurrences (0.03% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 4 | 11 | 0 | 0 |

**Common Sources**: Code4rena, Spearbit, Sherlock

---

## Detection Checklist

- [ ] Check for bypass limit vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Reentrancy of fee payment can be used to circumvent max mints per wallet check

**Source**: Spearbit
**Protocol**: SeaDrop
**Impact**: HIGH

**Details**:

## Vulnerability Report

## Severity
**High Risk**

## Context
`SeaDrop.sol#L586`

## Description
In case of a `mintPublic` call, the function `_checkMintQuantity` checks whether the minter has exceeded the parameter `maxMintsPerWallet`, among other things. However, re-entrancy in the above fee dispersal mechanism can be used to circumvent the check.

The following is an example contract that can be employed by the `feeRecipient` (assume that `maxMintsPerWallet` is 1):

```solidity
contract MaliciousRecipient {
    bool public startAttack;
    address public token;
    SeaDrop public seaDrop;

    fallback() external payable {
        if (startAttack) {
            startAttack = false;
            seaDrop.mintPublic{value: 1 ether}({
                nftContract: token,
                feeRecipient: address(this),
                minterIfNotPayer: address(this),
                quantity: 1
            });
        }
    }

    // Call `attack` with at least 2 ether.
    function attack(SeaDrop _seaDrop, address _token) external payable {
        token = _token;
        seaDrop = _seaDrop;
        startAttack = true;
        _seaDrop.mintPublic{value: 1 ether}({
            nftContract: _token,
            feeRecipient: address(this),
            minterIfNotPayer: address(this),
            quantity: 1
        });
        token = address(0);
        seaDrop = SeaDrop(address(0));
    }
}
```

This is especially problematic when the parameter `PublicDrop.restrictFeeRecipients` is

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Seadrop-Spearbit-Security-Review.pdf)

---

### Example 2: [H-01] PartyGovernance: Can vote multiple times by transferring NFT in same block as proposal

**Source**: Code4rena
**Protocol**: PartyDAO
**Impact**: HIGH

**Details**:

_Submitted by Lambda, also found by Trust_

`PartyGovernanceNFT` uses the voting power at the time of proposal when calling `accept`. The problem with that is that a user can vote, transfer the NFT (and the voting power) to a different wallet, and then vote from this second wallet again during the same block that the proposal was created.
This can also be repeated multiple times to get an arbitrarily high voting power and pass every proposal unanimously.

The consequences of this are very severe. Any user (no matter how small his voting power is) can propose and pass arbitrary proposals animously and therefore steal all assets (including the precious tokens) out of the party.

### Proof Of Concept

This diff shows how a user with a voting power of 50/100 gets a voting power of 100/100 by transferring the NFT to a second wallet that he owns and voting from that one:

```diff
--- a/sol-tests/party/PartyGovernanceUnit.t.sol
+++ b/sol-tests/party/PartyGovernanceUnit.t.sol
@@ -762,6 +762,7 @@ contract PartyGovernanceUnitTest is Test, TestUtils {
         TestablePartyGovernance gov =
             _createGovernance(100e18, preciousTokens, preciousTokenIds);
         address undelegatedVoter = _randomAddress();
+        address recipient = _randomAddress();
         // undelegatedVoter has 50/100 intrinsic VP (delegated to no one/self)
         gov.rawAdjustVotingPower(undelegatedVoter, 50e18, address(0));
 
@@ -772,38 +773,13 @@ contract PartyGovernanceUnitTest is Test, TestUtils {

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-party)

---

### Example 3: [H-03] Withdrawal delay can be circumvented

**Source**: Code4rena
**Protocol**: prePO
**Impact**: HIGH

**Details**:

_Submitted by cmichel, also found by IllIllI and leastwood_

[Collateral.sol#L97](https://github.com/code-423n4/2022-03-prepo/blob/f63584133a0329781609e3f14c3004c1ca293e71/contracts/core/Collateral.sol#L97)<br>

After initiating a withdrawal with `initiateWithdrawal`, it's still possible to transfer the collateral tokens.
This can be used to create a second account, transfer the accounts to them and initiate withdrawals at a different time frame such that one of the accounts is always in a valid withdrawal window, no matter what time it is.
If the token owner now wants to withdraw they just transfer the funds to the account that is currently in a valid withdrawal window.

Also, note that each account can withdraw the specified `amount`. Creating several accounts and circling & initiating withdrawals with all of them allows withdrawing larger amounts **even at the same block** as they are purchased in the future.

I consider this high severity because it breaks core functionality of the Collateral token.

### Proof of Concept

For example, assume the `_delayedWithdrawalExpiry = 20` blocks. Account A owns 1000 collateral tokens, they create a second account B.

*   At `block=0`, A calls `initiateWithdrawal(1000)`. They send their balance to account B.
*   At `block=10`, B calls `initiateWithdrawal(1000)`. They send their balance to account A.
*   They repeat these steps, alternating the withdrawal initiation every 10 blocks.
*   One of the accounts is always in a valid withdraw

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-03-prepo)

---

### Example 4: [M-04] Withdrawing uncollateralized deposits is possible even though the position is in liquidation mode

**Source**: Code4rena
**Protocol**: Wise Lending
**Impact**: MEDIUM

**Details**:

Users can withdraw uncollateralized deposits even though their position is liquidable, [as opposed to the README](https://github.com/code-423n4/2024-02-wise-lending/blob/main/README.md?plain=1#L137). If the position is in liquidation mode, users should use their uncollateralized deposits to avoid liquidation instead of removing them.

### Proof of Concept

When withdrawing deposits from public pools, at the end of the tx is executed the [`WiseLending._healthStateCheck() function`](https://github.com/code-423n4/2024-02-wise-lending/blob/main/contracts/WiseLending.sol#L77-L90), which depending on the value of the `powerFarmCheck` will determine if the position's collateral is enough to cover the borrows.

- If `powerFarmCheck` is true, it will use the `bare` value of the collateral; meaning, the `collateralFactor` is not applied to the collateral's value.
- If `powerFarmCheck` is false, it will use the `weighted` value of the collateral; meaning, the `collateralFactor` is applied to the collateral's value.

When withdrawing an uncollateralized deposit, the [`WiseCore._coreWithdrawToken() function`](https://github.com/code-423n4/2024-02-wise-lending/blob/main/contracts/WiseCore.sol#L44-L100) calls the [`WiseSecurity.checksWithdraw() function`](https://github.com/code-423n4/2024-02-wise-lending/blob/main/contracts/WiseSecurity/WiseSecurity.sol#L237-L270) to determine the value of the `powerFarmCheck`. If the pool from where the tokens are being withdrawn is uncollateralized, the 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-02-wise-lending)

---

### Example 5: assets  s.depositCap invariant can be broken for public vaults with non-zero deposit caps

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
- PublicVault.sol#L207-L208
- PublicVault.sol#L231-L232

## Description
The following check in `mint` / `deposit` does not take into consideration the new shares / amount supplied to the endpoint, since the `yIntercept` in `totalAssets()` is only updated after calling `super.mint(shares, receiver)` or `super.deposit(amount, receiver)` with the `afterDeposit` hook.

```solidity
uint256 assets = totalAssets();
if (s.depositCap != 0 && assets >= s.depositCap) {
    revert InvalidState(InvalidStates.DEPOSIT_CAP_EXCEEDED);
}
```

Thus the new shares or amount provided can be a really big number compared to `s.depositCap`, but the call will still go through.

## Recommendation
To have the inequality `assets < s.depositCap` to be always correct, we would need to calculate the to-be-updated value of `assets` beforehand and then perform the check.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 6: [M-04] Lender can trade claimToken in a malicious way to steal the borrower’s money via claimAndRepay() in SpigotedLine by using malicious zeroExTradeData

**Source**: Code4rena
**Protocol**: Debt DAO
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/debtdao/Line-of-Credit/blob/audit/code4rena-2022-11-03/contracts/modules/credit/SpigotedLine.sol#L106-L112
https://github.com/debtdao/Line-of-Credit/blob/audit/code4rena-2022-11-03/contracts/utils/SpigotedLineLib.sol#L75-L85


## Vulnerability details

## Impact

Lender can trade claimToken in a malicious way to steal the borrower's money via claimAndRepay() in SpigotedLine by using malicious zeroExTradeData.

In the design of the protocol, the lender can use the function claimAndRepay(), the lender can take claimToken by spigot.claimEscrow and then trade the claimToken to the CreditTOken via ZeroEx exchange, then repay the credit. 

```
function claimAndRepay(address claimToken, bytes calldata zeroExTradeData) external
        whileBorrowing
        nonReentrant
        returns (uint256) { 

...
// Line 106 - Line 112
uint256 newTokens = claimToken == credit.token ?
          spigot.claimEscrow(claimToken) :  // same asset. dont trade
          _claimAndTrade(                   // trade revenue token for debt obligation
              claimToken,
              credit.token,
              zeroExTradeData
          );
...
// Line 128 - Line 130 
 credits[id] = _repay(credit, id, repaid);

        emit RevenuePayment(claimToken, repaid);

...

}

```

```
function _claimAndTrade(
      address claimToken,
      address targetToken,
      bytes calldata zeroExTradeData
    )
        internal
        returns (uint256)
    {
        (uint256 tok

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-debtdao)

---

### Example 7: [M-07] Oracle’s two-day feature can be gamed

**Source**: Code4rena
**Protocol**: Inverse Finance
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-10-inverse/blob/main/src/Oracle.sol#L124


## Vulnerability details

## Impact
The two-day feature of the oracle can be gamed where you only have to manipulate the oracle for ~2 blocks.

## Proof of Concept
The oracle computes the day using:
```sol
uint day = block.timestamp / 1 days;
```

Since we're working with `uint` values here, the following is true:
$1728799 / 86400 = 1$
$172800 / 86400 = 2$

Meaning, if you manipulate the oracle at the last block of day $X$, e.g. 23:59:50, and at the first block of day $X + 1$, e.g. 00:00:02, you bypass the two-day feature of the oracle. You only have to manipulate the oracle for two blocks.

This is quite hard to pull off. I'm also not sure whether there were any instances of Chainlink oracle manipulation before. But, since you designed this feature to prevent small timeframe oracle manipulation I think it's valid to point this out.

## Tools Used
none

## Recommended Mitigation Steps
If you increase it to a three-day interval you can fix this issue. Then, the oracle has to be manipulated for at least 24 hours.

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-inverse)

---

### Example 8: enableTradingWithWeights allow the Treasury to change the pool’s weights even if the swap is not disabled

**Source**: Spearbit
**Protocol**: Gauntlet
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
AeraVaultV1.sol#L574-L583

## Description
`enableTradingWithWeights` is a function that can only be called by the owner of the Aera Vault contract and that should be used only to re-enable the swap feature on the pool while updating token weights. The function does not verify if the pool’s swap feature is enabled and for this reason, it allows the Treasury to act as the manager who is the only actor allowed to change the pool weights. The function should add a check to ensure that it is only callable when the pool’s swap is disabled.

## Recommendation
Update the function to revert when the pool’s swap is enabled.

```solidity
function enableTradingWithWeights(uint256[] calldata weights)
external
override
onlyOwner
whenInitialized
{
  bool isSwapEnabled = pool.getSwapEnabled();
  if( isSwapEnabled ) {
    revert Aera__PoolSwapIsAlreadyEnabled();
  }
  uint256 timestamp = block.timestamp;
  pool.updateWeightsGradually(timestamp, timestamp, weights);
  setSwapEnabled(true);
}
```

## Gauntlet
Fixed in PR #126.

## Spearbit
Acknowledged.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Gauntlet-Spearbit-Security-Review.pdf)

---

### Example 9: [M-06] Manager can get around min reserves check, draining all funds from Collateral.sol

**Source**: Code4rena
**Protocol**: prePO
**Impact**: MEDIUM

**Details**:

When a manager withdraws funds from Collateral.sol, there is a check in the `managerWithdrawHook` to confirm that they aren't pushing the contract below the minimum reserve balance.

```solidity
require(collateral.getReserve() - _amountAfterFee >= getMinReserve(), "reserve would fall below minimum");
```

However, a similar check doesn't happen in the `withdraw()` function.

The manager can use this flaw to get around the reserve balance by making a large deposit, taking a manager withdrawal, and then withdrawing their deposit.

### Proof of Concept

Imagine a situation where the token has a balance of 100, deposits of 1000, and a reserve percentage of 10%. In this situation, the manager should not be able to make any withdrawal.

But, with the following series of events, they can:

*   Manager calls `deposit()` with 100 additional tokens
*   Manager calls `managerWithdraw()` to pull 100 tokens from the contract
*   Manager calls `withdraw()` to remove the 100 tokens they added

The result is that they are able to drain the balance of the contract all the way to zero, avoiding the intended restrictions.

### Recommended Mitigation Steps

Include a check on the reserves in the `withdraw()` function as well as `managerWithdraw()`.

**[Picodes (judge) commented](https://github.com/code-423n4/2022-12-prepo-findings/issues/254#issuecomment-1356147341):**
 > From what I understand, although it's not clear from the documentation or the code, this `minReserve` requirement is here to 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-prepo)

---

### Example 10: [H-02] A whale user is able to cause freeze of funds of other users by bypassing withdraw limit

**Source**: Code4rena
**Protocol**: prePO
**Impact**: HIGH

**Details**:

<https://github.com/prepo-io/prepo-monorepo/blob/3541bc704ab185a969f300e96e2f744a572a3640/apps/smart-contracts/core/contracts/WithdrawHook.sol#L61>

<https://github.com/prepo-io/prepo-monorepo/blob/3541bc704ab185a969f300e96e2f744a572a3640/apps/smart-contracts/core/contracts/WithdrawHook.sol#L68>

### Description

In Collateral.sol, users may withdraw underlying tokens using withdraw. Importantly, the withdrawal must be approved by withdrawHook if set:

    function withdraw(uint256 _amount) external override nonReentrant {
      uint256 _baseTokenAmount = (_amount * baseTokenDenominator) / 1e18;
      uint256 _fee = (_baseTokenAmount * withdrawFee) / FEE_DENOMINATOR;
      if (withdrawFee > 0) { require(_fee > 0, "fee = 0"); }
      else { require(_baseTokenAmount > 0, "amount = 0"); }
      _burn(msg.sender, _amount);
      uint256 _baseTokenAmountAfterFee = _baseTokenAmount - _fee;
      if (address(withdrawHook) != address(0)) {
        baseToken.approve(address(withdrawHook), _fee);
        withdrawHook.hook(msg.sender, _baseTokenAmount, _baseTokenAmountAfterFee);
        baseToken.approve(address(withdrawHook), 0);
      }
      baseToken.transfer(msg.sender, _baseTokenAmountAfterFee);
      emit Withdraw(msg.sender, _baseTokenAmountAfterFee, _fee);
    }

The hook requires that two checks are passed:

    if (lastGlobalPeriodReset + globalPeriodLength < block.timestamp) {
      lastGlobalPeriodReset = block.timestamp;
      globalAmountWithdrawnThisPeriod = _amountBefor

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-prepo)

---

### Example 11: Supplying and borrowing can recreate p2p credit lines even if p2p is disabled

**Source**: Spearbit
**Protocol**: Morpho
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

**Context:** 
- aave-v2/EntryPositionsManager.sol#L117
- aave-v2/EntryPositionsManager.sol#L215
- compound/PositionsManager.sol#L258
- compound/PositionsManager.sol#L354

**Description:**  
When supplying/borrowing, the algorithm attempts to reduce the deltas `p2pBorrowDelta` and `p2pSupplyDelta` by moving borrowers and suppliers back to P2P. However, it does not check if P2P is enabled. This oversight has significant implications, especially when governance disables P2P and aims to redirect users and liquidity back to the pool through `increaseDelta` calls. Users could inadvertently re-enter P2P by supplying and borrowing.

**Recommendation:**  
Disable matching the initial delta-matching step in supply and borrow if P2P is disabled. This precaution is necessary only for supply and borrow operations and not for repay and withdraw. For repay and withdraw, while we are also reducing the delta, we are not creating new P2P credit lines (as `p2pAmount` also decreases, resulting in a differential of zero). This process can be viewed as unmatching our P2P balance, reducing the delta, shifting our P2P balance to the pool, and then withdrawing from the pool.

**Morpho:** Fixed in PR 1453.

**Spearbit:** Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/MorphoV1-Spearbit-Security-Review.pdf)

---

### Example 12: [M-01] Bypass `userWithdrawLimitPerPeriod` check

**Source**: Code4rena
**Protocol**: prePO
**Impact**: MEDIUM

**Details**:

User can bypass the `userWithdrawLimitPerPeriod` check by transferring the balance to another account.

### Proof of Concept

1.  Assume `userWithdrawLimitPerPeriod` is set to `1000`
2.  User A has current deposit of amount `2000` and wants to withdraw everything instantly
3.  User A calls the withdraw function and takes out the `1000` amount

<!---->

    function withdraw(uint256 _amount) external override nonReentrant {
        uint256 _baseTokenAmount = (_amount * baseTokenDenominator) / 1e18;
        uint256 _fee = (_baseTokenAmount * withdrawFee) / FEE_DENOMINATOR;
        if (withdrawFee > 0) { require(_fee > 0, "fee = 0"); }
        else { require(_baseTokenAmount > 0, "amount = 0"); }
        _burn(msg.sender, _amount);
        uint256 _baseTokenAmountAfterFee = _baseTokenAmount - _fee;
        if (address(withdrawHook) != address(0)) {
          baseToken.approve(address(withdrawHook), _fee);
          withdrawHook.hook(msg.sender, _baseTokenAmount, _baseTokenAmountAfterFee);
          baseToken.approve(address(withdrawHook), 0);
        }
        baseToken.transfer(msg.sender, _baseTokenAmountAfterFee);
        emit Withdraw(msg.sender, _baseTokenAmountAfterFee, _fee);
      }

4.  Remaining `1000` amount cannot be withdrawn since `userWithdrawLimitPerPeriod` is reached

<!---->

    function hook(
        address _sender,
        uint256 _amountBeforeFee,
        uint256 _amountAfterFee
      ) external override onlyCollateral {
    ...
    require(userToAmountWit

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-prepo)

---

### Example 13: FeeCollector not well integrated

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context: FeeCollector.sol

### Description
There is a contract to pay fees for using the bridge: **FeeCollector**. This is used by crafting a transaction via the frontend API, which then calls the contract through `_executeAndCheckSwaps()`. 

Here is an example of the contract of such a transaction. It is whitelisted, so no fees are paid if a developer is using the LiFi contracts directly. However, the current mechanism isn't suited for this purpose. The `_executeAndCheckSwaps()` function is geared for swaps and has several checks on balances. These (and future) checks could interfere with fee payments. Additionally, this is a complicated and non-transparent approach. The project has suggested viewing `_executeAndCheckSwaps()` as a multicall mechanism.

### Recommendation
- Use a dedicated mechanism to pay for fees.
- If `_executeAndCheckSwaps()` is intended to be a multicall mechanism, then rename the function.

## LiFi
We acknowledge the risk and encourage integrators to utilize our API at this time.

## Spearbit
Acknowledged.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 14: [M-06] User can initiate withdraw for previous epoch if rebase hasn't been called since end of epoch

**Source**: Code4rena
**Protocol**: Yieldy
**Impact**: MEDIUM

**Details**:

_Submitted by 0x52_

User is able to withdraw unstaked asset sooner than they should be.

### Proof of Concept

`Unstake()` allows the user to bypass the rebase() call by setting \_trigger to false. Since rebase() is bypassed, epoch.number could potentially be stale i.e. doesn't match the Tokemak epoch. A user could potentially call unstake() with \_trigger = false immediately after an epoch has ended but expiry would be set using the stale epoch.number because it wouldn't be updated by rebase(). This would allow the user to withdraw early before their funds were actually available in the contract because their withdrawal would be considered to be in the epoch before they actually initiated the withdrawal.

### Recommended Mitigation Steps

`Rebase()` cannot be optional when calling unstake.

**[toshiSat (Yieldy) acknowledged and commented](https://github.com/code-423n4/2022-06-yieldy-findings/issues/28#issuecomment-1168978499):**
 > We use a coolDownAmount of 2 to get around this.



***

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-yieldy)

---

### Example 15: M-4: Users can avoid performance fees by withdrawing before the end of the epoch forcing other users to pay their fees

**Source**: Sherlock
**Protocol**: Knox Finance
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-knox-judging/issues/75 

## Found by 
0x52

## Summary

No performance fees are taken when user withdraws early from the vault but their withdrawal value will be used to take fees, which will be taken from other users.

## Vulnerability Detail

    uint256 adjustedTotalAssets = _totalAssets() + l.totalWithdrawals;

    if (adjustedTotalAssets > l.lastTotalAssets) {
        netIncome = adjustedTotalAssets - l.lastTotalAssets;

        feeInCollateral = l.performanceFee64x64.mulu(netIncome);

        ERC20.safeTransfer(l.feeRecipient, feeInCollateral);
    }

When taking the performance fees, it factors in both the current assets of the vault as well as the total value of withdrawals that happened during the epoch. Fees are paid from the collateral tokens in the vault, at the end of the epoch. Paying the fees like this reduces the share price of all users, which effectively works as a fee applied to all users. The problem is that withdraws that take place during the epoch are not subject to this fee and the total value of all their withdrawals are added to the adjusted assets of the vault. This means that they don't pay any performance fee but the fee is still taken from the vault collateral. In effect they completely avoid the fee force all there other users of the vault to pay it for them.

## Impact

User can avoid performance fees and force other users to pay them

## Code Snippet

[VaultInternal.sol#L504-L532](https://githu

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 15
- Examples shown: 15
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
