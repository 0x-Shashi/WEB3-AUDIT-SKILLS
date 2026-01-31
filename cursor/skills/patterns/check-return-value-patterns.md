---
id: PAT-CHECK-RETURN-VALUE
title: Check Return Value Security Patterns
category: validation
severity: medium
difficulty: intermediate
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - validation
  - require
  - missing-check

finding_count: 7
last_updated: 2026-01-31
---
# Check Return Value Security Patterns

## Overview

**Frequency**: 7 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 3 | 4 | 0 | 0 |

**Common Sources**: Sherlock, Spearbit, Halborn, TrailOfBits

---

## Detection Checklist

- [ ] Check for check return value vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Return value of low-level .call() not checked

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: HIGH

**Details**:

## Vulnerability Report

## Severity
**High Risk**

## Context
Locations:
- Receiver.sol#L209
- Receiver.sol#L238
- Receiver.sol#L257

## Description
The low-level primitive `.call()` doesn't revert in the caller's context when the callee reverts. If its return value is not checked, it can lead the caller to falsely believe that the call was successful. The `Receiver.sol` contract uses `.call()` to transfer the native token to the receiver. If the receiver reverts, this can lead to locked ETH in the `Receiver` contract.

## Recommendation
Check the return value and revert if false is returned:

```solidity
-receiver.call{ value: amount }("");
+(bool success, ) = receiver.call{ value: amount }("");
+require(success);
```

## Additional Information
- **LiFi:** Fixed in PR 244.
- **Spearbit:** Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-retainer1-Spearbit-Security-Review.pdf)

---

### Example 2: Missing check of return value of transfer and transferFrom

**Source**: TrailOfBits
**Protocol**: Frax Solidity
**Impact**: HIGH

**Details**:

## Frax Solidity Security Assessment

## Difficulty: Medium

## Type: Undefined Behavior

## Target: TWAMM.sol

### Description
Some tokens, such as BAT, do not precisely follow the ERC20 specification and will return
false or fail silently instead of reverting. Because the codebase does not consistently use
OpenZeppelins SafeERC20 library, the return values of calls to `transfer` and
`transferFrom` should be checked. However, return value checks are missing from these
calls in many areas of the code, opening the TWAMM contract (the time-weighted automated
market maker) to severe vulnerabilities.

```solidity
function provideLiquidity(uint256 lpTokenAmount) external {
    require(totalSupply() != 0, 'EC3');
    // execute virtual orders
    longTermOrders.executeVirtualOrdersUntilCurrentBlock(reserveMap);
    // the ratio between the number of underlying tokens and the number of lp tokens
    // must remain invariant after mint
    uint256 amountAIn = lpTokenAmount * reserveMap[tokenA] / totalSupply();
    uint256 amountBIn = lpTokenAmount * reserveMap[tokenB] / totalSupply();
    ERC20(tokenA).transferFrom(msg.sender, address(this), amountAIn);
    ERC20(tokenB).transferFrom(msg.sender, address(this), amountBIn);
}
```
*Figure 20.1: contracts/FPI/TWAMM.sol#L125-136*

### Exploit Scenario
Frax deploys the TWAMM contract. Pools are created with tokens that do not revert on
failure, allowing an attacker to call `provideLiquidity` and mint LP tokens for free; the
attacker does 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/trailofbits/publications/blob/master/reviews/FraxQ42021.pdf)

---

### Example 3: M-5: stakingContext.auraBooster.deposit boolean return value not handled in Boosted3TokenPoolUtils.sol

**Source**: Sherlock
**Protocol**: Notional
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/117 

## Found by 
ctf\_sec

## Summary

stakingContext.auraBooster.deposit boolean return value not handled in Boosted3TokenPoolUtils.sol

## Vulnerability Detail

the function _joinPoolAndStake in Boosted3TokenPoolUtils.sol is used extensively when handling the token stake.

However, when entering the stake and interacting with external contract, the logic does not handle the returned boolean value in the code below

```solidity
        // Transfer token to Aura protocol for boosted staking
        stakingContext.auraBooster.deposit(stakingContext.auraPoolId, bptMinted, true); // stake = true
```

In the AuraBooster implmenetation, a Boolean is indeed returned to acknowledge that deposit is completely successfully. 

https://etherscan.io/address/0x7818A1DA7BD1E64c199029E86Ba244a9798eEE10#code#F34#L1

```solidity
    /**
     * @notice  Deposits an "_amount" to a given gauge (specified by _pid), mints a `DepositToken`
     *          and subsequently stakes that on Convex BaseRewardPool
     */
    function deposit(uint256 _pid, uint256 _amount, bool _stake) public returns(bool){
```

## Impact

Notional -> AuraBooster -> BaseRewardPool

Without handling the boolean value explitily, there is risk that transaction may be fail sliently.

Because there are two layers of external call

## Code Snippet

https://github.com/sherlock-audit/2022-09-notional/blob/main/leveraged-vaults/contracts/vaults/balancer/i

*[Content truncated...]*

---

### Example 4: M-4: stakingContext.auraRewardPool.withdrawAndUnwrap boolean return value not handled in Boosted3TokenPoolUtils.sol and TwoTokenPoolUtils.sol

**Source**: Sherlock
**Protocol**: Notional
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/118 

## Found by 
ctf\_sec

## Summary

stakingContext.auraRewardPool.withdrawAndUnwrap boolean return value not handled in Boosted3TokenPoolUtils.sol and TwoTokenPoolUtils.sol

## Vulnerability Detail

When calling function _unstakeAndExitPool,

the contract withdraw BPT tokens back to the vault for redemption

by calling 

```solidity
stakingContext.auraRewardPool.withdrawAndUnwrap(bptClaim, false);
```

however, the underlying call withdrawAndUnwrap returns boolean value, the contract does not handle the return value.

The see the interface of the IAuraRewardPool already indicate that the underlying call returns value

```solidity
interface IAuraRewardPool {
    function withdrawAndUnwrap(uint256 amount, bool claim) external returns(bool);
```

and the underlying call with BaseRewardConvexPool.sol also returns the boolean

https://github.com/convex-eth/platform/blob/ece5998c54b0354a60f092e0dda1aa1f040ec8bd/contracts/contracts/BaseRewardPool.sol#L238

```solidity
    function withdrawAndUnwrap(uint256 amount, bool claim) public updateReward(msg.sender) returns(bool){
```

## Impact

Because there are stacks of external call:

Notional -> auraRewardPool -> BaseRewardPool,

without handling the return value explicitly, the transaction may risk fails silently.

## Code Snippet

https://github.com/sherlock-audit/2022-09-notional/blob/main/leveraged-vaults/contracts/vaults/balancer/internal/pool/Boosted3T

*[Content truncated...]*

---

### Example 5: NON-STANDARD ERC20 TOKENS WILL REVERT

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

### Example 6: H-1: AuraSpell#openPositionFarm fails to return all rewards to user

**Source**: Sherlock
**Protocol**: Blueberry Update #2
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-05-blueberry-judging/issues/29 

## Found by 
0x52, nobody2018
## Summary

When a user adds to an existing position on AuraSpell, the contract burns their current position and remints them a new one. The issues is that WAuraPool will send all reward tokens to the contract but it only sends Aura back to the user, causing all other rewards to be lost.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-05-blueberry/blob/main/blueberry-core/contracts/wrapper/WAuraPools.sol#L256-L261

        for (uint i = 0; i < rewardTokens.length; i++) {
            IERC20Upgradeable(rewardTokens[i]).safeTransfer(
                msg.sender,
                rewards[i]
            );
        }

Inside WAuraPools#burn reward tokens are sent to the user.

https://github.com/sherlock-audit/2023-05-blueberry/blob/main/blueberry-core/contracts/spell/AuraSpell.sol#L130-L140

        IBank.Position memory pos = bank.getCurrentPositionInfo();
        if (pos.collateralSize > 0) {
            (uint256 pid, ) = wAuraPools.decodeId(pos.collId);
            if (param.farmingPoolId != pid)
                revert Errors.INCORRECT_PID(param.farmingPoolId);
            if (pos.collToken != address(wAuraPools))
                revert Errors.INCORRECT_COLTOKEN(pos.collToken);
            bank.takeCollateral(pos.collateralSize);
            wAuraPools.burn(pos.collId, pos.collateralSize);
            _doRefundRewards(AURA);
        }

We see above that t

*[Content truncated...]*

---

### Example 7: authAllowedForToken() returns prematurely in certain scenarios causing an authentication DoS

**Source**: Spearbit
**Protocol**: Sudoswap LSSVM2
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
LSSVMPairFactory.sol#L330-L377

## Description
Tokens listed on Nifty or Foundation (therefore returning a valid `niftyRegistry` or `foundationTreasury`) where the `proposedAuthAddress` is not a valid Nifty sender or a valid Foundation Treasury admin will cause an authentication DoS if the token were also listed on Digitalax or ArtBlocks and the `proposedAuthAddress` had admin roles on those platforms.

This happens because the return values of `valid` and `isAdmin` for `isValidNiftySender(proposedAuthAddress)` and `isAdmin(proposedAuthAddress)` respectively are returned as-is instead of returning only if/when they are true, but continuing the checks for authorization otherwise (if/when they are false) on Digitalax and ArtBlocks. 

`toggleSettingsForCollection` and `reclaimPair` (which utilize `authAllowedForToken`) would incorrectly fail for valid `proposedAuthAddress` in such scenarios.

## Recommendation
Check the return values of `valid` and `isAdmin` for `isValidNiftySender(proposedAuthAddress)` and `isAdmin(proposedAuthAddress)` and return if they are true (as done for Digitalax). Continue with the authorization checks otherwise, if/when they are false.

## Sudorandom Labs
Addressed in PR#64.

## Spearbit
Verified that this is fixed by PR#64.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/SudoswapLSSVM2-Spearbit-Security-Review.pdf)

---

## Statistics

- Total findings analyzed: 7
- Examples shown: 7
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

