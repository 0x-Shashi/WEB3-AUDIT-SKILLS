# Missing Check Security Patterns

## Overview

**Frequency**: 23 occurrences (0.05% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 7 | 14 | 2 | 0 |

**Common Sources**: Code4rena, Sherlock, Pashov Audit Group, Cyfrin, Codehawks

---

## Detection Checklist

- [ ] Check for missing check vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-02] A malicious user can avoid unfavorable score updates after alpha/multiplier changes, resulting in accrual of outsized rewards for the attacker at the expense of other users

**Source**: Code4rena
**Protocol**: Venus Protocol
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2023-09-venus/blob/main/contracts/Tokens/Prime/Prime.sol#L397-L405> 

<https://github.com/code-423n4/2023-09-venus/blob/main/contracts/Tokens/Prime/Prime.sol#L704-L756> 

<https://github.com/code-423n4/2023-09-venus/blob/main/contracts/Tokens/Prime/Prime.sol#L623-L639> 

<https://github.com/code-423n4/2023-09-venus/blob/main/contracts/Tokens/Prime/Prime.sol#L827-L833> 

<https://github.com/code-423n4/2023-09-venus/blob/main/contracts/Tokens/Prime/Prime.sol#L200-L219> 

<https://github.com/code-423n4/2023-09-venus/blob/main/tests/hardhat/Prime/Prime.ts#L294-L301>

Please note: All functions/properties referred to are in the `Prime.sol` contract.

### Impact

A malicious user can accrue outsized rewards at the expense of other users after `updateAlpha()` or `updateMultipliers()` is called.

### Proof of Concept

An attacker can prevent their score from being updated and decreased after the protocol's alpha or multipliers change. This is done by manipulatively decreasing the value of `pendingScoreUpdates`, then ensuring that only other user scores are updated until `pendingScoreUpdates` reaches zero, at which point calls to `updateScores()` will revert with the error `NoScoreUpdatesRequired()`. This can be done via the attacker calling `updateScores()` to update other users' scores first and/or DoSing calls to `updateScores()` that would update the attacker's score (see the issue titled "DoS and gas griefing of Prime.updateScores()").

The core of 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-09-venus)

---

### Example 2: [H-03] Poor detection of disputed trees allows claiming tokens from a disputed tree

**Source**: Code4rena
**Protocol**: Angle Protocol
**Impact**: HIGH

**Details**:

<https://github.com/AngleProtocol/merkl-contracts/blob/1825925daef8b22d9d6c0a2bc7aab3309342e786/contracts/Distributor.sol#L200>

Users can claim rewards from a Merkle tree that's being disputed. This can potentially lead to loss of funds since a malicious trusted EOA can claim funds from a malicious tree while it's being disputed.

### Proof of Concept

The [Distribution.getMerkleRoot](https://github.com/AngleProtocol/merkl-contracts/blob/1825925daef8b22d9d6c0a2bc7aab3309342e786/contracts/Distributor.sol#L199) function is used to get the current Merkle root during claiming. The function is aware of the dispute period of the current root and returns the previous root if the current tree is still in the dispute period.

However, the function doesn't take into account the situation when:

1.  a tree was disputed (i.e. [the disputer address is set](https://github.com/AngleProtocol/merkl-contracts/blob/1825925daef8b22d9d6c0a2bc7aab3309342e786/contracts/Distributor.sol#L237));
2.  and the dispute period has finished (i.e. when `block.timestamp >= endOfDisputePeriod`).

Such situations can happen realistically when a tree is disputed closer to the end of its dispute period and/or when the governor/guardian takes longer time to resolve the dispute. In such situations, the dispute period checks in the above functions will pass, however the `disputer` address will be set, which means that the tree is being disputed and shouldn't be used in claims.

As an example exploit scenario, a mal

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-dev-test-repo)

---

### Example 3: [H-04] If insider deposits and unlocks in quick succession, attacker can steal their NFT and their deposit funds

**Source**: ZachObront
**Protocol**: Dyad
**Impact**: HIGH

**Details**:

The dNFT contract allows the owner to mint a predefined quantity of "insider" NFTs without any deposit attached to them. These NFTs begin in a locked state, which stops them from being immediately liquidated due to their lack of deposits.

The protocol enforces that, in order for insider's to mint any DYAD, they must unlock their NFTs (so that they will be subject to liquidation, like all other users).

However, there is no safety check for the opposite case, where an insider unlocks their NFT before making a deposit. In this situation, any user could liquidate them and steal their NFT.

This is especially dangerous because if a user calls both of these functions in quick succession, they may both be in the mempool at the same time. If this is the case, a malicious attacker can create a flashbots bundle to sandwich their liquidation transaction between the unlock() and deposit() transactions, with the result that:

- The attacker will successfully liquidate and steal the insider's NFT
- The deposit transaction will deposit the insider's ETH to the stolen NFT, securing it for the attacker

**Recommendation**

I would recommend adding a check to the unlock() function to ensure this situation is avoided:

```solidity
function unlock(uint id)
external
isNftOwner(id)
{
if (!id2Locked[id]) revert NotLocked();
if (id2Shared[id] == 0) revert MustDepositFirst();
id2Locked[id] = false;
emit Unlocked(id);
}
```

Note: This requires adding a MustDepositFirst() error to IDNft.sol.

**Revi

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/ZachObront/2023-02-12-Dyad.md)

---

### Example 4: H-1: Can steal gOhm by calling Clearinghouse.claimDefaulted on loans not made by Clearinghouse

**Source**: Sherlock
**Protocol**: Cooler Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-08-cooler-judging/issues/28 

## Found by 
detectiveking, jkoppel, mert\_eren

`Clearinghouse.claimDefaulted` assumes that all loans passed in were originated by the Clearinghouse. However, nothing guarantees that. An attacker can wreak havoc by calling it with a mixture of Clearinghouse-originated and external loans. In particular, they can inflate the computed `totalCollateral` recovered to steal excess gOhm from defaulted loans.

## Vulnerability Detail

1. Alice creates a Cooler. 9 times, she calls `requestLoan` (not through the Clearinghouse) to request a loan of 0.000001 DAI collateralized by 2 gOhm. For each loan, she then calls `clearLoan` and loans the 0.000001 DAI to herself.
1. One week later, Bob calls `Clearinghouse.lendToCooler` and takes a loan for 3000 DAI collateralized by 1 gOHM
3. Alice defaults on the loans she made to herself and waits 7 days
4. Bob defaults on his loan
5. Alice calls `Clearinghouse.claimDefaulted`, passing in both her loans to herself and Bob's loan from the Clearinghouse. `Clearinghouse.claimDefaulted` calls `Cooler.claimDefaulted` on each, returning 18 gOhm to Alice and 1 gOhm to the Clearinghouse.
6. For each of Alice's loan, the keeper reward is incremented by the max award of 0.1 gOhm. For Bob's loan, the keeper reward is incremented by somewhere between 0 and 0.05 gOhm,  depending on how much time has elapsed since Bob's loan defaulted. 
8. The keeper reward is transferred to Alice. Al

*[Content truncated...]*

---

### Example 5: H-1: MarginTrading.sol: Missing flash loan initiator check allows attacker to open trades, close trades and steal funds

**Source**: Sherlock
**Protocol**: DODO Margin Trading
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-05-dodo-judging/issues/34 

## Found by 
0xHati, BAHOZ, Bauer, BowTiedOriole, CRYP70, Jiamin, Juntao, Quantish, Tendency, VAD37, alexzoid, carrotsmuggler, circlelooper, curiousapple, nobody2018, oot2k, pengun, qbs, roguereddwarf, rvierdiiev, sashik\_eth, shaka, shogoki, smiling\_heretic, theOwl
## Summary
The `MarginTrading.executeOperation` function is called when a flash loan is made (and it can only be called by the `lendingPool`).

The wrong assumption by the protocol is that the flash loan can only be initiated by the `MarginTrading` contract itself.

However this is not true. A flash loan can be initiated for any `receiverAddress`.

This is actually a known mistake that devs make and the aave docs warn about this (although admittedly the warning is not very clear):
https://docs.aave.com/developers/v/2.0/guides/flash-loans

![2023-05-11_12-43](https://github.com/sherlock-audit/2023-05-dodo-roguereddwarf/assets/118631472/1bc59eb4-407b-4b5f-a38b-9c415932caf1)

So an attacker can execute a flash loan with the `MarginTrading` contract as `receiverAddress`. Also the funds that are needed to pay back the flash loan are pulled from the `receiverAddress` and NOT from the `initiator`:

https://github.com/aave/protocol-v2/blob/30a2a19f6d28b6fb8d26fc07568ca0f2918f4070/contracts/protocol/lendingpool/LendingPool.sol#L532-L536

This means the attacker can close a position or repay a position in the `MarginTrading` contract.

By crafting a

*[Content truncated...]*

---

### Example 6: [M-02] `pause/unpause` functionalities not implemented in many pausable contracts

**Source**: Code4rena
**Protocol**: Stader Labs
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2023-06-stader/blob/main/contracts/SocializingPool.sol#L21> <br><https://github.com/code-423n4/2023-06-stader/blob/main/contracts/Auction.sol#L14> <br><https://github.com/code-423n4/2023-06-stader/blob/main/contracts/StaderOracle.sol#L17><br><https://github.com/code-423n4/2023-06-stader/blob/main/contracts/OperatorRewardsCollector.sol#L16>

The following contracts: `SocializingPool`, `StaderOracle`, `OperatorRewardsCollector` and `Auction` are supposed to be pausable (as they all inherit from `PausableUpgradeable`), but they don't implement the external `pause/unpause` functionalities which means it will never be possible to pause them.

### Proof of Concept

All the following contracts `SocializingPool`, `StaderOracle`, `OperatorRewardsCollector` and `Auction` inherit from the openzeppelin `PausableUpgradeable` extension which means that they contain internal functions `_pause` and `_unpause`.

Because those functions are internal, the contract must implement two other public/external `pause` and `unpause` functions to allow the manager to pause and unpause the contracts when necessary. None of the aforementioned contracts implement those functions, which means even if those contracts are supposed to be pausable (and have the `pause/unpause` functionalities), none of them can be paused.

### Recommended Mitigation Steps

Add public/external `pause` and `unpause` functions in the aforementioned contracts to allow them to be pausable, this can be

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-stader)

---

### Example 7: [M-03] User can lock tokens from the TemporaryHolding for an "infinite" amount of time

**Source**: Pashov Audit Group
**Protocol**: Subsquid
**Impact**: MEDIUM

**Details**:

## Severity

**Impact:** Medium, admin won't be able to retrieve tokens after lock time has passed

**Likelihood:** Medium, attacker needs to be a temporary holding beneficiary

## Description

`TemporaryHoldings.sol` allows the `beneficiary` address to use tSQD in the whitelisted protocol contracts for a limited amount of time

```solidity
  function execute(address to, bytes calldata data, uint256 requiredApprove) public returns (bytes memory) {
    require(_canExecute(msg.sender), "Not allowed to execute");
    require(router.networkController().isAllowedVestedTarget(to), "Target is not allowed");

    // It's not likely that following addresses will be allowed by network controller, but just in case
    require(to != address(this), "Cannot call self");
    require(to != address(tSQD), "Cannot call tSQD");

    if (requiredApprove > 0) {
      tSQD.approve(to, requiredApprove);
    }
    return to.functionCall(data);
  }
```

after `lockedUntil` amount of time has passed `admin` regains control over the funds inside

```solidity
  function _canExecute(address executor) internal view override returns (bool) {
    if (block.timestamp < lockedUntil) {
      return executor == beneficiary;
    }
    return executor == admin;
  }
```

One of the whitelisted targets is the `GatewayRegistry`. A savvy beneficiary can stake tokens from `TemporaryHolding` for a time far in the future and enjoy boosted CU, while admin cannot unstake these tokens even after `lockedUntil`

```solidity


*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/Subsquid-security-review.md)

---

### Example 8: M-3: Repaying loans with small amounts of debt tokens can lead to underflowing in the `roll` function

**Source**: Sherlock
**Protocol**: Cooler
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-cooler-judging/issues/263 

## Found by 
tsvetanovv, rvierdiiev, ck, zaskoh, Allarious, Trumpero, Breeje, berndartmueller, jonatascm, Deivitto

## Summary

Due to precision issues when repaying a loan with small amounts of debt tokens, the `loan.amount` can be reduced whereas the `loan.collateral` remains unchanged. This can lead to underflowing in the `roll` function.

## Vulnerability Detail

The `decollateralized` calculation in the `repay` function rounds down to zero if the `repaid` amount is small enough. This allows iteratively repaying a loan with very small amounts of debt tokens without reducing the collateral.

The consequence is that the `roll` function can revert due to underflowing the `newCollateral` calculation once the `loan.collateral` is greater than `collateralFor(loan.amount, req.loanToCollateral)` (`loan.amount` is reduced by repaying the loan)

As any ERC-20 tokens with different decimals can be used, this precision issue is amplified if the decimals of the collateral and debt tokens differ greatly.

## Impact

The `roll` function can revert due to underflowing the `newCollateral` calculation if the `repay` function is (iteratively) called with small amounts of debt tokens.

## Code Snippet

[Cooler.sol#L114](https://github.com/sherlock-audit/2023-01-cooler/blob/main/src/Cooler.sol#L114)

```solidity
function repay (uint256 loanID, uint256 repaid) external {
    Loan storage loan = loans[loanID];

    if

*[Content truncated...]*

---

### Example 9: [M-02] Soft Restricted Staker Role can withdraw stUSDe for USDe

**Source**: Code4rena
**Protocol**: Ethena Labs
**Impact**: MEDIUM

**Details**:

A requirement is stated that a user with the `SOFT_RESTRICTED_STAKER_ROLE` is not allowed to withdraw `USDe` for `stUSDe`.

The code does not satisfy that condition, when a holder has the `SOFT_RESTRICTED_STAKER_ROLE`, they can exchange their `stUSDe` for `USDe` using `StakedUSDeV2`.

### Description

The Ethena readme has the following decription of legal requirements for the Soft Restricted Staker Role: <br><https://github.com/code-423n4/2023-10-ethena/blob/ee67d9b542642c9757a6b826c82d0cae60256509/README.md?plain=1#L98>

    Due to legal requirements, there's a `SOFT_RESTRICTED_STAKER_ROLE` and `FULL_RESTRICTED_STAKER_ROLE`. 
    The former is for addresses based in countries we are not allowed to provide yield to, for example USA. 
    Addresses under this category will be soft restricted. They cannot deposit USDe to get stUSDe or withdraw stUSDe for USDe. 
    However they can participate in earning yield by buying and selling stUSDe on the open market.

In summary, legal requires are that a `SOFT_RESTRICTED_STAKER_ROLE`:

*   MUST NOT deposit USDe to get stUSDe
*   MUST NOT withdraw USDe for USDe
*   MAY earn yield by trading stUSDe on the open market

As `StakedUSDeV2` is a `ERC4626`, the `stUSDe` is a share on the underlying `USDe` asset. There are two distinct entrypoints for a user to exchange their share for their claim on the underlying the asset, `withdraw` and `redeem`. Each cater for a different input (`withdraw` being by asset, `redeem` being by share), however

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-10-ethena)

---

### Example 10: [M-01] LibHelpers.piecewiseLinear will revert when the value is less than the first element of the array

**Source**: Code4rena
**Protocol**: Angle Protocol
**Impact**: MEDIUM

**Details**:

<https://github.com/AngleProtocol/angle-transmuter/blob/9707ee4ed3d221e02dcfcd2ebaa4b4d38d280936/contracts/transmuter/facets/Redeemer.sol#L156-L157> <br><https://github.com/AngleProtocol/angle-transmuter/blob/9707ee4ed3d221e02dcfcd2ebaa4b4d38d280936/contracts/transmuter/libraries/LibSetters.sol#L230-L240> <br><https://github.com/AngleProtocol/angle-transmuter/blob/9707ee4ed3d221e02dcfcd2ebaa4b4d38d280936/contracts/transmuter/libraries/LibHelpers.sol#L77-L80>

`LibHelpers.piecewiseLinear` reverts when the value is less than the first element of the array. This method is used in Redeemer contract and if the collateral ratio is below the first element of xRedemptionCurve, the redepmtion will revert.

### Proof of Concept

In `Redeemer._quoteRedemptionCurve`, a penalty factor is applied when the protocol is under-collateralized using `LibHelpers.piecewiseLinear`.

Redeemer.sol#L156-L157

```solidity
        uint64[] memory xRedemptionCurveMem = ts.xRedemptionCurve;
        penaltyFactor = uint64(LibHelpers.piecewiseLinear(collatRatio, xRedemptionCurveMem, yRedemptionCurveMem));
```

`xRedemptionCurveMem` is strictly increasing and upper bounded by `BASE_9`, and there's no more limitations.

LibSetters.sol

```solidity
230        (action == ActionType.Redeem && (xFee[n - 1] > BASE_9 || yFee[n - 1] < 0 || yFee[n - 1] > int256(BASE_9)))
           
233        for (uint256 i = 0; i < n - 1; ++i) {
234            if (
           
240                (action == ActionType.Redeem && (xFe

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-dev-test-repo)

---

### Example 11: [H-01] Missing user input validation can lead to stuck funds

**Source**: Pashov Audit Group
**Protocol**: Baton Launchpad
**Impact**: HIGH

**Details**:

**Severity**

**Impact:**
High, as all mint fees can be stuck forever

**Likelihood:**
Medium, as users can easily misconfigure inputs

**Description**

There are multiple insufficiencies in the input validation of the arguments of the `initialize` method in `Nft`:

1. The sum of the `supply` of all `categories_` can be less than the `maxMintSupply_` - this would lead to the mint never completing, which results in all of the ETH in the `Nft` contract coming from mints so far being stuck in it forever
2. The `duration` of the `vestingParams_` should have a lower and upper bound as for example a too big of a duration can mean vesting can never complete or a division rounding error
3. The `mintEndTimestamp` of `refundParams_` should not be too further away in the future otherwise refund & vesting mechanisms would never work, and if it is too close then the mint mechanism won't work.

**Recommendations**

Add a validation that the sum of all categories' supply is more than or equal to the `maxMintSupply`. Also add sensible upper and lower bounds for both `duration` for the vesting mechanism and `mintEndTimestamp` for the refund mechanism.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Pashov/2023-07-01-Baton Launchpad.md)

---

### Example 12: [H-01] Attacker can call sweepRewardToken() when `bribesProcessor==0` and reward funds will be lost because there is no check in sweepRewardToken() and _handleRewardTransfer() and _sendTokenToBribesProcessor()

**Source**: Code4rena
**Protocol**: BadgerDAO
**Impact**: HIGH

**Details**:

_Submitted by unforgiven, also found by GimelSec, and zzzitron_

<https://github.com/Badger-Finance/vested-aura/blob/d504684e4f9b56660a9e6c6dfb839dcebac3c174/contracts/MyStrategy.sol#L107-L113>

<https://github.com/Badger-Finance/vested-aura/blob/d504684e4f9b56660a9e6c6dfb839dcebac3c174/contracts/MyStrategy.sol#L405-L413>

<https://github.com/Badger-Finance/vested-aura/blob/d504684e4f9b56660a9e6c6dfb839dcebac3c174/contracts/MyStrategy.sol#L421-L425>

### Impact

If the value of `bribesProcessor` was `0x0` (the default is `0x0` and `governance()`  can set to `0x0`) then attacker can call `sweepRewardToken()` make contract to send his total balance in attacker specified token to `0x0` address.

### Proof of Concept

The default value of `bribesProcessor` is `0x0` and `governance` can set the value to `0x0` at any time. Rewards are stacking in contract address and they are supposed to send to `bribesProcessor`.

This is `sweepRewardToken()` and `_handleRewardTransfer()` and `_sendTokenToBribesProcessor()` code:

      /// @dev Function to move rewards that are not protected
      /// @notice Only not protected, moves the whole amount using _handleRewardTransfer
      /// @notice because token paths are hardcoded, this function is safe to be called by anyone
      /// @notice Will not notify the BRIBES_PROCESSOR as this could be triggered outside bribes
      function sweepRewardToken(address token) public nonReentrant {
          _onlyGovernanceOrStrategist();
          _onlyNot

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-badger)

---

### Example 13: M-4: Loss of option token from Teller and reward from OTLM if L2 sequencer goes down

**Source**: Sherlock
**Protocol**: Bond Options
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-bond-judging/issues/82 

## Found by 
ctf\_sec, qandisa
## Summary

Loss of option token from Teller and reward from OTLM if L2 sequencer goes down

## Vulnerability Detail

In the current implementation, if the option token expires, the user is not able to [exerise the option at strike price](https://github.com/sherlock-audit/2023-06-bond/blob/fce1809f83728561dc75078d41ead6d60e15d065/options/src/fixed-strike/FixedStrikeOptionTeller.sol#L336)

```solidity
    // Validate that option token is not expired
        if (uint48(block.timestamp) >= expiry) revert Teller_OptionExpired(expiry);
```

if the option token expires, the user lose rewards from OTLM as well when [claim the reward](https://github.com/sherlock-audit/2023-06-bond/blob/fce1809f83728561dc75078d41ead6d60e15d065/options/src/fixed-strike/liquidity-mining/OTLM.sol#L496)

```solidity
    function _claimRewards() internal returns (uint256) {
        // Claims all outstanding rewards for the user across epochs
        // If there are unclaimed rewards from epochs where the option token has expired, the rewards are lost

        // Get the last epoch claimed by the user
        uint48 userLastEpoch = lastEpochClaimed[msg.sender];

```

and

```solidity
    // If the option token has expired, then the rewards are zero
        if (uint256(optionToken.expiry()) < block.timestamp) return 0;
```

And in the onchain context, the protocol intends to deploy the contract in arbitr

*[Content truncated...]*

---

### Example 14: M-3: Blocklisted address can be used to lock the option token minter's fund

**Source**: Sherlock
**Protocol**: Bond Options
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-bond-judging/issues/81 

## Found by 
Vagner, berndartmueller, bin2chen, caventa, ctf\_sec
## Summary

Blocklisted address can be used to lock the option token minter's fund

## Vulnerability Detail

When deploy a token via the teller contract, the contract validate that [receiver address is not address(0)](https://github.com/sherlock-audit/2023-06-bond/blob/fce1809f83728561dc75078d41ead6d60e15d065/options/src/fixed-strike/FixedStrikeOptionTeller.sol#L139)

However, a malicious option token creator can save a seemingly favorable strike price and pick a blocklisted address and set the blocklisted address as receiver

https://github.com/d-xo/weird-erc20#tokens-with-blocklists

> Some tokens (e.g. USDC, USDT) have a contract level admin controlled address blocklist. If an address is blocked, then transfers to and from that address are forbidden.

> Malicious or compromised token owners can trap funds in a contract by adding the contract address to the blocklist. This could potentially be the result of regulatory action against the contract itself, against a single user of the contract (e.g. a Uniswap LP), or could also be a part of an extortion attempt against users of the blocked contract.

then user would see the favorable strike price and mint the option token using payout token for call option or use quote token for put option

However, they can never exercise their option because the transaction would revert when [transferri

*[Content truncated...]*

---

### Example 15: M-1: Funds can be stolen from the `FixedStrikeOptionTeller` contract by creating put option tokens without providing collateral

**Source**: Sherlock
**Protocol**: Bond Options
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-bond-judging/issues/61 

## Found by 
berndartmueller, pks\_, techOptimizor
## Summary

Due to a rounding error when calculating the `quoteAmount` in the `create` function of the `FixedStrikeOptionTeller` contract, it is possible to create (issue) option tokens without providing the necessary collateral. A malicious receiver can exploit this to steal funds from the `FixedStrikeOptionTeller` contract.

## Vulnerability Detail

Anyone can create (issue) put option tokens with the `create` function in the `FixedStrikeOptionTeller` contract. However, by specifying a very small `amount_`, the `quoteAmount` calculation in line 283 can potentially round down to zero. This is the case if the result of the multiplication in line 283, $amount * strikePrice$ is smaller than $10^{decimals}$, where `decimals` is the number of decimals of the payout token.

For example, assume the following scenario:

| Parameter                | Description                                                                                      |
| ------------------------ | ------------------------------------------------------------------------------------------------ |
| Quote token              | $USDC. 6 decimals                                                                                |
| Payout token             | $GMX. 18 decimals                                                                                |
| $payoutToken_{decimals}$ | 18 decim

*[Content truncated...]*

---

### Example 16: [M-03] Contract inherits from `Pausable` but does not expose pausing/unpausing functionality

**Source**: Pashov Audit Group
**Protocol**: Parcel Payroll
**Impact**: MEDIUM

**Details**:

**Impact:**
Low, as methods do not have `whenNotPaused` modifier

**Likelihood:**
High, as it is certain that contract can't be paused at all

**Description**

The `Organizer` smart contract inherits from OpenZeppelin's `Pausable` contract, but the `_pause` and `_unpause` methods are not exposed externally to be callable and also no method actually uses the `whenNotPaused` modifier. This shows that `Pausable` was used incorrectly and is possible to give out a false sense of security when actually contract is not pausable at all.

**Recommendations**

Either remove `Pausable` from the contract or add `whenNotPaused` modifier to the methods that you want to be safer and also expose the `_pause` and `_unpause` methods externally with access control.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Pashov/2023-02-01-Parcel Payroll.md)

---

### Example 17: Validation is missing for tokenA in `SwapExchange::calculateMultiSwap()`

**Source**: Cyfrin
**Protocol**: Swapexchange
**Impact**: LOW

**Details**:

**Severity:** Low

**Description:** The protocol supports claiming a chain of swaps and the function `SwapExchange::calculateMultiSwap()` is used to do some calculations including the amount of tokenA that can be received for a given amount of tokenB.
Looking at the implementation, the protocol does not validate that the tokenA of the last swap in the chain is actually the same as the tokenA of `multiClaimInput`.
Because this view function is supposed to be used by the frontend to 'preview' the result of a `MultiSwap`, this does not imply a direct security risk but can lead to unexpected results. (It is notable that the actual swap function `SwapExchange::_claimMultiSwap()` implemented a proper validation.)

```solidity
SwapExchange.sol
150:     function calculateMultiSwap(SwapUtils.MultiClaimInput calldata multiClaimInput) external view returns (SwapUtils.SwapCalculation memory) {
151:         uint256 swapIdCount = multiClaimInput.swapIds.length;
152:         if (swapIdCount == 0 || swapIdCount > _maxHops) revert Errors.InvalidMultiClaimSwapCount(_maxHops, swapIdCount);
153:         if (swapIdCount == 1) {
154:             SwapUtils.Swap memory swap = swaps[multiClaimInput.swapIds[0]];
155:             return SwapUtils._calculateSwapNetB(swap, multiClaimInput.amountB, _feeValue, _feeDenominator, _fixedFee);
156:         }
157:         uint256 matchAmount = multiClaimInput.amountB;
158:         address matchToken = multiClaimInput.tokenB;
159:         uint256 swapId;
160:    

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-19-cyfrin-swapexchange.md)

---

### Example 18: User can create small position after exit with bid

**Source**: Codehawks
**Protocol**: DittoETH
**Impact**: MEDIUM

**Details**:

### Relevant GitHub Links
<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-09-ditto/blob/main/contracts/facets/ExitShortFacet.sol#L175-L180">https://github.com/Cyfrin/2023-09-ditto/blob/main/contracts/facets/ExitShortFacet.sol#L175-L180</a>


## Summary
User can create small position after exit with bid, because there is no validation after matching.
## Vulnerability Details
Shorter can partially exit from position using `ExitShortFacet.exitShort` function. This function acccepts `buyBackAmount` param which is debt amount that user wants to repay.
In order to cover debt, function [will create force bid](https://github.com/Cyfrin/2023-09-ditto/blob/main/contracts/facets/ExitShortFacet.sol#L210-L212) on behalf of user with `buyBackAmount` as needed asset.

In the beginning function checks that [position will not be too small](https://github.com/Cyfrin/2023-09-ditto/blob/main/contracts/facets/ExitShortFacet.sol#L175-L180) after this action. In case if `buyBackAmount == e.ercDebt` then this check is skipped. This is needed in order to not allow small positions as it creates risks for the system.

The problem is that such check is not enough and it should be actually done after the bid matching, when you know how many assets were purchased. This is because, matching doesn't guarantee, that there is enough amount that can be sold. As result, not whole `buyBackAmount` can be acquired.
So in case if user provides `buyBackAmount == e.ercDebt` then check is ski

*[Content truncated...]*

---

### Example 19: [M-01] Insufficient input validation

**Source**: Pashov Audit Group
**Protocol**: Gtrade
**Impact**: MEDIUM

**Details**:

**Severity**

**Impact:**
High, as it can lead to stuck funds

**Likelihood:**
Low, as it requires a bad user error

**Description**

In `GNSStakingV6_4_1::createUnlockSchedule` we have the `UnlockScheduleInput calldata _input` parameter, where most of the fields in the struct are properly validated to be in range of valid values. The issue is that the `start` field of the `UnlockScheduleInput` is not sufficiently validated, as it can be too further away in the future - for example 50 years in the future, due to a user error when choosing the timestamp. This would result in (almost) permanent lock of the `GNS` funds sent to the method.

**Recommendations**

Add a validation that the `start` field is not too further away in the future, for example it should be max 1 year in the future.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Pashov/2023-08-01-gTrade.md)

---

### Example 20: Admin level vulnerabilities

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

### Example 21: [M-14] No check for Individual mint amount surpassing 10% when the circulation reaches 10\_000\_000 in `mint()` of `LybraEUSDVaultBase` contract

**Source**: Code4rena
**Protocol**: Lybra Finance
**Impact**: MEDIUM

**Details**:

### Lines of code

<https://github.com/code-423n4/2023-06-lybra/blob/7b73ef2fbb542b569e182d9abf79be643ca883ee/contracts/lybra/pools/base/LybraEUSDVaultBase.sol#L124> <br><https://github.com/code-423n4/2023-06-lybra/blob/7b73ef2fbb542b569e182d9abf79be643ca883ee/contracts/lybra/pools/base/LybraEUSDVaultBase.sol#L126>

### Impact

The mint functions in `LybraEUSDVaultBase` have no checks for when the supplied amount to mint is more than 10% if circulation reaches 10,000,000, as specified in the comments explaining the logic of the function.

### Proof of Concept

Lets have a look at `mint()` code in the `LybraEUSDVaultBase` contract:

        /**
         * @notice The mint amount number of EUSD is minted to the address
         * Emits a `Mint` event.
         *
         * Requirements:
         * - `onBehalfOf` cannot be the zero address.
         * - `amount` Must be higher than 0. Individual mint amount shouldn't surpass 10% when the circulation 
              reaches 10_000_000
         */
        function mint(address onBehalfOf, uint256 amount) external {
            require(onBehalfOf != address(0), "MINT_TO_THE_ZERO_ADDRESS");
            require(amount > 0, "ZERO_MINT");
            _mintEUSD(msg.sender, onBehalfOf, amount, getAssetPrice());
        }

        function _mintEUSD(address _provider, address _onBehalfOf, uint256 _mintAmount, uint256 _assetPrice) internal virtual {
            require(poolTotalEUSDCirculation + _mintAmount <= configurator.mintVaultMaxSuppl

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-lybra)

---

### Example 22: M-3: No check for sequencer uptime can lead to dutch auctions executing at bad prices

**Source**: Sherlock
**Protocol**: Index Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-Index-judging/issues/40 

## Found by 
0x52
## Summary

When purchasing from dutch auctions on L2s there is no considering of sequencer uptime. When the sequencer is down, all transactions must originate from the L1. The issue with this is that these transactions use an aliased address. Since the set token contracts don't implement any way for these aliased addressed to interact with the protocol, no transactions can be processed during this time even with force L1 inclusion. If the sequencer goes offline during the the auction period then the auction will continue to decrease in price while the sequencer is offline. Once the sequencer comes back online, users will be able to buy tokens from these auctions at prices much lower than market price.

## Vulnerability Detail

See summary.

## Impact

Auction will sell/buy assets at prices much lower/higher than market price leading to large losses for the set token

## Code Snippet

[AuctionRebalanceModuleV1.sol#L772-L836](https://github.com/sherlock-audit/2023-06-Index/blob/main/index-protocol/contracts/protocol/modules/v1/AuctionRebalanceModuleV1.sol#L772-L836)

## Tool used

Manual Review

## Recommendation

Check sequencer uptime and invalidate the auction if the sequencer was ever down during the auction period



## Discussion

**pblivin0x**

What exactly is the remediation here? To check an external uptime feed https://docs.chain.link/data-feeds/l2-sequencer-feeds ?

Not sur

*[Content truncated...]*

---

### Example 23: Missing checks for `address(0)` when assigning values to address state variables

**Source**: Cyfrin
**Protocol**: Stake Link
**Impact**: LOW

**Details**:

```solidity
File: PriorityPool.sol

399:         distributionOracle = _distributionOracle;

```

**Client:**
Acknowledged.

**Cyfrin:** Acknowledged.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-08-25-cyfrin-stake-link.md)

---

## Statistics

- Total findings analyzed: 23
- Examples shown: 23
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
