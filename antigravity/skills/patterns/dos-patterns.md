---
id: PAT-DOS
title: Dos Security Patterns
category: dos
severity: medium
difficulty: beginner
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - denial-of-service
  - gas
  - griefing

finding_count: 66
last_updated: 2026-01-31
---
# DOS Security Patterns

## Overview

**Frequency**: 66 occurrences (0.13% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 23 | 43 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Spearbit, MixBytes, Pashov Audit Group

---

## Detection Checklist

- [ ] Check for dos vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: VaultImplementation.buyoutLien can be DoSed by calls to LienToken.buyoutLien

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Vulnerability Report

## Severity: High Risk

### Context
- LienToken.sol#L102
- LienToken.sol#L121
- VaultImplementation.sol#L305

### Description
Anyone can call into `LienToken.buyoutLien` and provide params of the type `LienActionBuyout`:  
`params.incoming` is not used, so for example, vault signatures or strategy validation is skipped. There are a few checks for `params.encumber`.

Let's define the following variables:

| Parameter | Value |
|-----------|-------|
| i         | params.position |
| kj        | params.encumber.stack[j].point.position |
| tj        | params.encumber.stack[j].point.last |
| ej        | params.encumber.stack[j].point.end |
| e0       | itnow+D0 |
| i         | lj params.encumber.stack[j].point.lienId |
| l0       | ih(N0 i,V0 i,S0 i,c0 i, (A0max i,r0 i,D0 i,P0 i,L0 i)) where h is the keccak256 of the encoding |
| rj        | params.encumber.stack[j].lien.details.rate : old rate |
| r0       | params.encumber.lien.details.rate : new rate |
| c         | params.encumber.collateralId |

| Parameter | Value |
|-----------|-------|
| cj        | params.encumber.stack[j].lien.collateralId |
| c0       | params.encumber.lien.collateralId |
| Aj        | params.encumber.stack[j].point.amount |
| A0       | params.encumber.amount |
| Amax     | params.encumber.stack[j].lien.details.maxAmount |
| A0max    | params.encumber.lien.details.maxAmount |
| R         | params.encumber.receiver |
| Nj        | params.encumber.stack[j].lien.token |
| N0      

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 2: DOS attack on the Nomad Home.sol Contract

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Severity: High Risk

**Context:** Home.sol#L332, Queue.sol#L119-L130

**Description:**  
Upon calling `xcall()`, a message is dispatched via Nomad. A hash of this message is inserted into the merkle tree and the new root will be added at the end of the queue. Whenever the updater of `Home.sol` commits to a new root, `improperUpdate()` will check that the new update is not fraudulent. In doing so, it must iterate through the queue of merkle roots to find the correct committed root. Because anyone can dispatch a message and insert a new root into the queue, it is possible to impact the availability of the protocol by preventing honest messages from being included in the updated root.

```solidity
function improperUpdate(..., bytes32 _newRoot, ... ) public notFailed returns (bool) {
    ...
    // if the _newRoot is not currently contained in the queue,
    // slash the Updater and set the contract to FAILED state
    if (!queue.contains(_newRoot)) {
        _fail();
        ...
    }
    ...
}
```

```solidity
function contains(Queue storage _q, bytes32 _item) internal view returns (bool) {
    for (uint256 i = _q.first; i <= _q.last; i++) {
        if (_q.queue[i] == _item) {
            return true;
        }
    }
    return false;
}
```

**Recommendation:**  
Consider altering the queuing system such that `improperUpdate()` takes in an index argument that is greater than the old root. By specifying the index, we can check that the new root is valid in O(1) time instead o

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 3: [H-02] `Staking.sol#stake()` DoS by staking 1 wei for the recipient when `warmUpPeriod  0`

**Source**: Code4rena
**Protocol**: Yieldy
**Impact**: HIGH

**Details**:

_Submitted by WatchPug, also found by BowTiedWardens, cccz, minhquanym, parashar, pashov, shung, and zzzitron_

```solidity
if (warmUpPeriod == 0) {
    IYieldy(YIELDY_TOKEN).mint(_recipient, _amount);
} else {
    // create a claim and mint tokens so a user can claim them once warm up has passed
    warmUpInfo[_recipient] = Claim({
        amount: info.amount + _amount,
        credits: info.credits +
            IYieldy(YIELDY_TOKEN).creditsForTokenBalance(_amount),
        expiry: epoch.number + warmUpPeriod
    });

    IYieldy(YIELDY_TOKEN).mint(address(this), _amount);
}
```

`Staking.sol#stake()` is a public function and you can specify an arbitrary address as the `_recipient`.

When `warmUpPeriod > 0`, with as little as 1 wei of `YIELDY_TOKEN`, the `_recipient`'s `warmUpInfo` will be push back til `epoch.number + warmUpPeriod`.

### Recommended Mitigation Steps

Consider changing to not allow deposit to another address when `warmUpPeriod > 0`.

**[Dravee (warden) commented](https://github.com/code-423n4/2022-06-yieldy-findings/issues/187#issuecomment-1167621029):**
 > Should be high right? Funds are locked.
> See https://github.com/code-423n4/2022-06-yieldy-findings/issues/245#issuecomment-1167616593

**[moose-code (judge) increased severity to High and commented](https://github.com/code-423n4/2022-06-yieldy-findings/issues/187#issuecomment-1198122754):**
> Agree this should be high. The cost of the attack is negligible and could cause basic perpetual grievance on all

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-yieldy)

---

### Example 4: H-3: Bull can prevent `settleContract()`

**Source**: Sherlock
**Protocol**: Bull v Bear
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-bullvbear-judging/issues/111 

## Found by 
Bahurum, KingNFT, ak1, ElKu, WATCHPUG

## Summary

The bull can intentionally cause out-of-gas and revert the transaction and prevent `settleContract()`.

## Vulnerability Detail

As `IERC721(order.collection).safeTransferFrom()` is used in `settleContract()` which will call `IERC721Receiver(to).onERC721Received()` when the `to` address is an contract. 

This gives the bull a chance to intentionally prevent the transaction from happening by consuming a lot of gas and revert the whole transaction.

## Impact

The bear (victim) can not `settleContract()` therefore cannot exercise their put option rights. The bull (attacker) always wins.

## Code Snippet

https://github.com/sherlock-audit/2022-11-bullvbear/blob/main/bvb-protocol/src/BvbProtocol.sol#L374-L411


## Tool used

Manual Review

## Recommendation

```diff
function settleContract(Order calldata order, uint tokenId) public nonReentrant {
    bytes32 orderHash = hashOrder(order);

    // ContractId
    uint contractId = uint(orderHash);

    address bear = bears[contractId];

    // Check that only the bear can settle the contract
    require(msg.sender == bear, "ONLY_BEAR");

    // Check that the contract is not expired
    require(block.timestamp < order.expiry, "EXPIRED_CONTRACT");

    // Check that the contract is not already settled
    require(!settledContracts[contractId], "SETTLED_CONTRACT");

    address bull = bulls[c

*[Content truncated...]*

---

### Example 5: H-2: Netting and withdraw auction can be frozen permanently

**Source**: Sherlock
**Protocol**: Opyn Crab Netting
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-opyn-judging/issues/219 

## Found by 
joestakey, bin2chen, hyh, libratus, KingNFT, Zarf, yixxas, cccz

## Summary

An attacker can permanently block the auctions by using a blocked address to fail USDC transfers, which are now required for the auction to proceed.

## Vulnerability Detail

Say Bob knows that one of his addresses is blocked by USDC. He has/can obtain CRAB, which he can transfer to this address.

As withdraw queue requires each transfer call to be successful, this will permanently freezes the functionality, i.e. all future auctions will be blocked.

Knowing that, Bob will block the auctions when it's beneficial to him the most.

## Impact

netAtPrice() and withdrawAuction() will be blocked as long as Bob's withdrawal is queued. There is no way for the owner to manually alter this state.

As auction timing can have material impact on the beneficiaries, the inability to perform netting and withdraw auction will lead to losses for them as Bob will choose the moment to execute the attack to benefit himself at the expense of the participants.

Setting the severity to be high as this is permanent freeze of the core functionality fully controllable by the attacker only.

## Code Snippet

netAtPrice() will be reverting at Bob's withdrawal:

https://github.com/sherlock-audit/2022-11-opyn/blob/main/crab-netting/src/CrabNetting.sol#L389-L419

```solidity
        // process withdraws and send usdc
        i = withdrawsIndex

*[Content truncated...]*

---

### Example 6: DoS `KintoWallet` contract

**Source**: MixBytes
**Protocol**: Kinto
**Impact**: HIGH

**Details**:

##### Description

- https://github.com/KintoXYZ/kinto-core/blob/f7dd98f66b9dfba1f73758703b808051196e740b/src/wallet/KintoWallet.sol#L235

`_resetSigners` does not take into account the current `SignerPolicy` in any way. A user can accidentally call `resetSigners` with an array length of 1 (with current `policy > 1`). A sample code is below:

```solidity
abi.encodeWithSignature(
    'resetSigners(address[])', 
    [address1, address2])

abi.encodeWithSignature(
    'setSignerPolicy(uint8)',
    2)

abi.encodeWithSignature(
    'resetSigners(address[])',
    [address1])

// _kintoWalletv1.signerPolicy() == 2
// _kintoWalletv1.getOwnersCount() == 1
```

Thus, the following code (https://github.com/KintoXYZ/kinto-core/blob/f7dd98f66b9dfba1f73758703b808051196e740b/src/wallet/KintoWallet.sol#L220) will be called:
```solidity
...
else {
    (signatures[0], signatures[1], signatures[2]) = 
        ByteSignature.extractThreeSignatures(
            userOp.signature);
}
for (uint i = 0; i < owners.length; i++) {
    if (
        owners[i] == hash.recover(signatures[i])
        ) {
        requiredSigners--;
    }
}
return requiredSigners;
```

and since `owners.length == 1`, the `_validateSignature` method will always return an error. You will need to wait for 7 days and restore the account (`finishRecovery`).

##### Recommendation
We recommend that when calling `resetSigners` you also check the `policy` variable and adjust it if necessary.

**Reference**: [View Original Finding](https://github.com/mixbytes/audits_public/blob/master/Kinto/README.md#4-dos-kintowallet-contract)

---

### Example 7: DoS of an account using frontrun

**Source**: MixBytes
**Protocol**: Kinto
**Impact**: HIGH

**Details**:

##### Description

- https://github.com/KintoXYZ/kinto-core/blob/f7dd98f66b9dfba1f73758703b808051196e740b/src/wallet/KintoWalletFactory.sol#L130

In `KintoWalletFactory`, a hacker can make a `deployContract` frontrun before calling `createAccount`. Thus, `deployContract` will create a valid `KintoWallet` without configuring the `walletTs` value.

The following is an example:
```solidity
vm.prank(_hackerWithKYC);
bytes memory a = abi.encodeWithSelector(
    KintoWallet.initialize.selector,
    _owner,
    _owner
);                   
_walletFactory.deployContract(
    0,
    abi.encodePacked(
        type(SafeBeaconProxy).creationCode,
        abi.encode(address(_beacon), a)
    ),
    bytes32(someSalt)
);
vm.startPrank(_owner);

// create2 will not be called
_kintoWalletv1 = 
    _walletFactory.createAccount(
        _owner, _owner, someSalt);

// _walletFactory.getWalletTimestamp(
// address(_kintoWalletv1)
// ) == 0
```

If the user sends tokens to it by mistake, they will be permanently blocked.

Such a contract cannot be recovered in any way, and also the `Recovery` mechanism will not work, since there is no way to call `KintoWallet` via `EntryPoint` on any `owners`.

##### Recommendation
We recommend not allowing `KintoWallet` accounts to be created via the `deployContract` method. A single fake-KYC or leaked account can create potential problems for all members of the Kinto network.

**Reference**: [View Original Finding](https://github.com/mixbytes/audits_public/blob/master/Kinto/README.md#3-dos-of-an-account-using-frontrun)

---

### Example 8: Malicious target can make `_endVote()` revert forever by forceUnstaking/staking again

**Source**: Cyfrin
**Protocol**: Streamr
**Impact**: HIGH

**Details**:

**Severity:** High

**Description:** In `_endVote()`, we update `forfeitedStakeWei` or `lockedStakeWei[target]` according to the `target`'s staking status.

```solidity
File: contracts\OperatorTokenomics\SponsorshipPolicies\VoteKickPolicy.sol
179:     function _endVote(address target) internal {
180:         address flagger = flaggerAddress[target];
181:         bool flaggerIsGone = stakedWei[flagger] == 0;
182:         bool targetIsGone = stakedWei[target] == 0;
183:         uint reviewerCount = reviewers[target].length;
184:
185:         // release stake locks before vote resolution so that slashings and kickings during resolution aren't affected
186:         // if either the flagger or the target has forceUnstaked or been kicked, the lockedStakeWei was moved to forfeitedStakeWei
187:         if (flaggerIsGone) {
188:             forfeitedStakeWei -= flagStakeWei[target];
189:         } else {
190:             lockedStakeWei[flagger] -= flagStakeWei[target];
191:         }
192:         if (targetIsGone) {
193:             forfeitedStakeWei -= targetStakeAtRiskWei[target];
194:         } else {
195:             lockedStakeWei[target] -= targetStakeAtRiskWei[target]; //@audit revert after forceUnstake() => stake() again
196:         }
```

We consider the target is still active if he has a positive staking amount. But we don't know if he has unstaked and staked again, so the below scenario would be possible.

- The target staked 100 amount and a flagger reported him.
- In `on

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-11-03-cyfrin-streamr.md)

---

### Example 9: [H-03] The settle feature will be broken if attacker arbitrarily transfer collateral tokens to the PerpetualAtlanticVaultLP

**Source**: Code4rena
**Protocol**: Dopex
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2023-08-dopex/blob/eb4d4a201b3a75dd4bddc74a34e9c42c71d0d12f/contracts/perp-vault/PerpetualAtlanticVaultLP.sol#L199-L205> 

<https://github.com/code-423n4/2023-08-dopex/blob/eb4d4a201b3a75dd4bddc74a34e9c42c71d0d12f/contracts/perp-vault/PerpetualAtlanticVault.sol#L359-L361> 

<https://github.com/code-423n4/2023-08-dopex/blob/eb4d4a201b3a75dd4bddc74a34e9c42c71d0d12f/contracts/core/RdpxV2Core.sol#L772-L774>

`RdpxV2Core.settle` reverts and the protocol stops.

### Proof of Concept

If a collateral token(WETH) is arbitrarily sent to PerpetualAtlanticVaultLP, the values of `collateral.balanceOf(address(this))` and `_totalCollateral` will be different.

Since `PerpetualAtlanticVaultLP.subtractLoss` requires that `collateral.balanceOf(address(this))` exactly match with `_totalCollateral - loss`, `PerpetualAtlanticVaultLP.subtractLoss` will be failed if an attacker arbitrarily transfers collateral tokens to the PerpetualAtlanticVaultLP contract.

```solidity
function subtractLoss(uint256 loss) public onlyPerpVault {
  require(
    collateral.balanceOf(address(this)) == _totalCollateral - loss,
    "Not enough collateral was sent out"
  );
  _totalCollateral -= loss;
}
```

<https://github.com/code-423n4/2023-08-dopex/blob/eb4d4a201b3a75dd4bddc74a34e9c42c71d0d12f/contracts/perp-vault/PerpetualAtlanticVaultLP.sol#L199-L205>

Since there is no function that synchronizes `_totalCollateral` with `collateral.balanceOf(address(this))` without moving tokens, eve

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-08-dopex)

---

### Example 10: [H-02] `UniswapV2PriceOracle.sol` `currentCumulativePrices()` will revert when `priceCumulative` addition overflow

**Source**: Code4rena
**Protocol**: Phuture Finance
**Impact**: HIGH

**Details**:

_Submitted by WatchPug_

[UniswapV2PriceOracle.sol#L62](https://github.com/code-423n4/2022-04-phuture/blob/594459d0865fb6603ba388b53f3f01648f5bb6fb/contracts/UniswapV2PriceOracle.sol#L62)<br>

```solidity
(uint price0Cumulative, uint price1Cumulative, uint32 blockTimestamp) = address(pair).currentCumulativePrices();
```

Because the Solidity version used by the current implementation of `UniswapV2OracleLibrary.sol` is `>=0.8.7`, and there are some breaking changes in Solidity v0.8.0:

> Arithmetic operations revert on underflow and overflow.

Ref: <https://docs.soliditylang.org/en/v0.8.13/080-breaking-changes.html#silent-changes-of-the-semantics>

While in `UniswapV2OracleLibrary.sol`, subtraction overflow is desired at `blockTimestamp - blockTimestampLast` in `currentCumulativePrices()`:

<https://github.com/Uniswap/v2-periphery/blob/master/contracts/libraries/UniswapV2OracleLibrary.sol#L25-L33>

```solidity
if (blockTimestampLast != blockTimestamp) {
    // subtraction overflow is desired
    uint32 timeElapsed = blockTimestamp - blockTimestampLast;
    // addition overflow is desired
    // counterfactual
    price0Cumulative += uint(FixedPoint.fraction(reserve1, reserve0)._x) * timeElapsed;
    // counterfactual
    price1Cumulative += uint(FixedPoint.fraction(reserve0, reserve1)._x) * timeElapsed;
}
```

In another word, `Uniswap/v2-periphery/contracts/libraries/UniswapV2OracleLibrary` only works at solidity < `0.8.0`.

As a result, when `price0Cumulative` or `price1Cumu

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-04-phuture)

---

### Example 11: External calls in loop can lead to denial of service

**Source**: TrailOfBits
**Protocol**: Origin Dollar
**Impact**: HIGH

**Details**:

## Type: Auditing and Logging
## Target: Several contracts

### Difficulty: Low

### Description
Several function calls are made in unbounded loops. This pattern is error-prone as it can trap the contracts due to the gas limitations or failed transactions. For example, `AaveStrategy` has several loops that iterate over the `assetsMapped` items, including `safeApproveAllTokens`:

```solidity
function safeApproveAllTokens() external onlyGovernor {
    uint256 assetCount = assetsMapped.length;
    address lendingPoolVault = _getLendingPoolCore();
    // approve the pool to spend the bAsset
    for (uint256 i = 0; i < assetCount; i++) {
        address asset = assetsMapped[i];
        // Safe approval
        IERC20(asset).safeApprove(lendingPoolVault, 0);
        IERC20(asset).safeApprove(lendingPoolVault, uint256(-1));
    }
}
```

*Figure 20.1: AaveStrategy.sol#L114-L124*

`assetsMapped` is an unbounded array that can only grow. `safeApproveAllTokens` can be trapped if:
- A call to an asset fails (for example, the asset is paused).
- Items in `assetsMapped` increase the gas cost beyond a certain limit.

Similar patterns exist in:
- `CompoundStrategy.liquidate()`
- `CompoundStrategy.safeApproveAllTokens()`
- `MixOracle.priceMin(string)`
- `MixOracle.priceMax(string)`
- `RebaseHooks.postRebase(bool)`
- `AaveStrategy.liquidate()`
- `Governor.execute(uint256)`

### Exploit Scenario
Over time, the governor adds dozens of assets in `assetsMapped`. As a result, `safeApproveAllTokens`

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/trailofbits/publications/blob/master/reviews/OriginDollar.pdf)

---

### Example 12: [M-38] DoS of `RootBridgeAgent` due to missing negation of return values for `UniswapV3Pool.swap()`

**Source**: Code4rena
**Protocol**: Maia DAO Ecosystem
**Impact**: MEDIUM

**Details**:

### Lines of code

<https://github.com/code-423n4/2023-05-maia/blob/main/src/ulysses-omnichain/RootBridgeAgent.sol#L684><br><https://github.com/code-423n4/2023-05-maia/blob/main/src/ulysses-omnichain/RootBridgeAgent.sol#L728>

### Vulnerability details

Both `RootBridgeAgent._gasSwapIn()` and `RootBridgeAgent._gasSwapOut()` do not negate the negative returned value of `UniswapV3Pool.swap()` before casting to `uint256`. That will cause the parent functions `anyExecute()` and `_manageGasOut()` to revert on overflow when casting return values of `_gasSwapIn()` and `_gasSwapOut()` with `SafeCastLib.toUint128()`.

### Impact

Several external functions in `RootBridgeAgent` (such as `anyExecute()`,  `callOut()`, `callOutAndBridge()`, `callOutAndBridgeMultiple()`, etc) are affected by this issue. That means `RootBridgeAgent` will not function properly at all, causing a DoS of the Ulysses Omnichain.

### Detailed Explanation

`UniSwapV3Pool.swap()` returns a negative value for exact input swap (see [documentation](<https://docs.uniswap.org/contracts/v3/reference/core/UniswapV3Pool#swap>)).

This is evident in UniswapV3's `SwapRouter.sol`, which shows that the returned value is negated before casting to `uint256`.

<https://github.com/Uniswap/v3-periphery/blob/main/contracts/SwapRouter.sol#L111>

```Solidity
    function exactInputInternal(
        uint256 amountIn,
        address recipient,
        uint160 sqrtPriceLimitX96,
        SwapCallbackData memory data
    ) private returns

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-05-maia)

---

### Example 13: [M-07] Possible DoS attack when creating Joins in Wand

**Source**: Code4rena
**Protocol**: Yield
**Impact**: MEDIUM

**Details**:

## Handle

shw


## Vulnerability details

## Impact

It is possible for an attacker to intendedly create a fake `Join` corresponding to a specific token beforehand to make `Wand` unable to deploy the actual `Join`, causing a DoS attack.

## Proof of Concept

The address of `Join` corresponding to an underlying `asset` is determined as follows and thus unique:

```solidity
Join join = new Join{salt: keccak256(abi.encodePacked(asset))}();
```

Besides, the function `createJoin` in the contract `JoinFactory` is permissionless: Anyone can create the `Join` corresponding to the `asset`. An attacker could then deploy a large number of `Joins` with different common underlying assets (e.g., DAI, USDC, ETH) before the `Wand` deploying them. The attempt of deploying these `Joins` by `Wand` would fail since the attacker had occupied the desired addresses with fake `Joins`, resulting in a DoS attack.

Moreover, the attacker can also perform DoS attacks on newly added assets: He monitors the mempool to find transactions calling the function `addAsset` of `Wand` and front-runs them to create the corresponding `Join` to make the benign transaction fail.

Referenced code:
[JoinFactory.sol#L64-L75](https://github.com/code-423n4/2021-05-yield/blob/main/contracts/JoinFactory.sol#L64-L75)
[Wand.sol#L53](https://github.com/code-423n4/2021-05-yield/blob/main/contracts/Wand.sol#L53)

## Recommended Mitigation Steps

Enable access control in `createJoin` (e.g., adding the `auth` modifier) and allow

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-05-yield)

---

### Example 14: [M-06] [Denial-of-Service] Contract Owner Could Block Users From Withdrawing Their Strike

**Source**: Code4rena
**Protocol**: Putty
**Impact**: MEDIUM

**Details**:

_Submitted by xiaoming90, also found by berndartmueller_

When users withdraw their strike escrowed in Putty contract, Putty will charge a certain amount of fee from the strike amount. The fee will first be sent to the contract owner, and the remaining strike amount will then be sent to the users.

<https://github.com/code-423n4/2022-06-putty/blob/3b6b844bc39e897bd0bbb69897f2deff12dc3893/contracts/src/PuttyV2.sol#L500>

```solidity
function withdraw(Order memory order) public {
	..SNIP..

	// transfer strike to owner if put is expired or call is exercised
	if ((order.isCall && isExercised) || (!order.isCall && !isExercised)) {
		// send the fee to the admin/DAO if fee is greater than 0%
		uint256 feeAmount = 0;
		if (fee > 0) {
			feeAmount = (order.strike * fee) / 1000;
			ERC20(order.baseAsset).safeTransfer(owner(), feeAmount);
		}

		ERC20(order.baseAsset).safeTransfer(msg.sender, order.strike - feeAmount);

		return;
	}
	..SNIP..
}
```

There are two methods on how the owner can deny user from withdrawing their strike amount from the contract

#### Method #1 - Set the `owner()` to `zero` address

Many of the token implementations do not allow transfer to `zero` address ([Reference](https://github.com/d-xo/weird-erc20#revert-on-transfer-to-the-zero-address)). Popular ERC20 implementations such as the following Openzeppelin's ERC20 implementation do not allow transfer to `zero` address, and will revert immediately if the `to` address (recipient) points to a `zero` address d

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-putty)

---

### Example 15: Atomic fees delivery susceptible to funds lockout

**Source**: Spearbit
**Protocol**: CLOBER
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
- OrderBook.sol#L791-L798 
- OrderBook.sol#L804-L805

## Description
The `collectFees` function delivers the `quoteToken` part of fees as well as the `baseToken` part of fees atomically and simultaneously to both the DAO and the host. In case a single address is blacklisted (e.g., via USDC blacklist feature) or a token in a pair is maliciously configured, it is possible for transfers to one of the addresses to revert, blocking fees delivery.

```solidity
function collectFees() external nonReentrant { // @audit delivers both tokens atomically
    require(msg.sender == _host(), Errors.ACCESS);
    if (_baseFeeBalance > 1) {
        _collectFees(_baseToken, _baseFeeBalance - 1);
        _baseFeeBalance = 1;
    }
    if (_quoteFeeBalance > 1) {
        _collectFees(_quoteToken, _quoteFeeBalance - 1);
        _quoteFeeBalance = 1;
    }
}
```

```solidity
function _collectFees(IERC20 token, uint256 amount) internal { // @audit delivers to both wallets
    uint256 daoFeeAmount = (amount * _DAO_FEE) / _FEE_PRECISION;
    uint256 hostFeeAmount = amount - daoFeeAmount;
    _transferToken(token, _daoTreasury(), daoFeeAmount);
    _transferToken(token, _host(), hostFeeAmount);
}
```

There are multiple scenarios where this situation can occur. For instance, a malicious host might block the function for the DAO to prevent collecting at least the guaranteed valuable `quoteToken`, or a hacked DAO could swap the treasury to an invalid address and renoun

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Clober-Spearbit-Security-Review.pdf)

---

### Example 16: [M-03] DOS risk if enough tokens are minted in Quest.claim can lead, at least, to transaction fee lost

**Source**: Code4rena
**Protocol**: RabbitHole
**Impact**: MEDIUM

**Details**:

<https://github.com/rabbitholegg/quest-protocol/blob/8c4c1f71221570b14a0479c216583342bd652d8d/contracts/Quest.sol#L99><br>
<https://github.com/rabbitholegg/quest-protocol/blob/8c4c1f71221570b14a0479c216583342bd652d8d/contracts/RabbitHoleReceipt.sol#L117-L133>

`claim` function can be summaraized in next steps:

1.  Check that the quest is active
2.  Check the contract is not paused
3.  Get tokens corresponding to msg.sender for `questId` using `rabbitHoleReceiptContract.getOwnedTokenIdsOfQuest`: **DOS**
4.  Check that msg.sender owns at least one token
5.  Count non claimed tokens
6.  Check there is at least 1 unclaimed token
7.  Calculate redeemable rewards: `_calculateRewards(redeemableTokenCount);`
8.  Set all token to claimed state
9.  Update `redeemedTokens`
10. Emit claim event

The problem with this functions relays in its dependency on `RabbitHoleReceipt.getOwnedTokenIdsOfQuest`. It's behaviour can be summarized in next steps:

1.  Get queried balance (claimingAddress\_)
2.  Get claimingAddress\_ owned tokens
3.  Filter tokens corresponding to questId\_
4.  Return token of claimingAddress\_ corresponding to questId\_

If a user actively participates in multiple quests and accumulates a large number of tokens, the claim function may eventually reach the block gas limit. As a result, the user may be unable to successfully claim their earned tokens.

### Impact

It can be argued that function `ERC721.burn` can address the potential DOS risk in the claim process. However,

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-rabbithole)

---

### Example 17: [M-07] Denial of service when `baseAmount` is equal to zero

**Source**: Code4rena
**Protocol**: SIZE
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-11-size/blob/main/src/SizeSealed.sol#L217><br>
<https://github.com/code-423n4/2022-11-size/blob/main/src/SizeSealed.sol#L269><br>
<https://github.com/transmissions11/solmate/blob/main/src/utils/FixedPointMathLib.sol#L44>

There is a `finalize` function in the `SizeSealed` smart contract. The function traverses the array of the bids sorted by price descending. On each iteration, it [calculates the `quotePerBase`](https://github.com/code-423n4/2022-11-size/blob/main/src/SizeSealed.sol#L269). When this variable is calculated, the whole transaction may be reverted due to the internal logic of the calculation.

Here is a part of the logic on the cycle iteration:

```solidity
bytes32 decryptedMessage = ECCMath.decryptMessage(sharedPoint, b.encryptedMessage);
// If the bidder didn't faithfully submit commitment or pubkey
// Or the bid was cancelled
if (computeCommitment(decryptedMessage) != b.commitment) continue;

// First 128 bits are the base amount, last are random salt
uint128 baseAmount = uint128(uint256(decryptedMessage >> 128));

// Require that bids are passed in descending price
uint256 quotePerBase = FixedPointMathLib.mulDivDown(b.quoteAmount, type(uint128).max, baseAmount);
```

Let's `baseAmount == 0`, then

```solidity
uint256 quotePerBase = FixedPointMathLib.mulDivDown(b.quoteAmount, type(uint128).max, 0);
```

According to the implementation of the `FixedPointMathLib.mulDivDown`, the transaction will be reverted.

### Attack scenar

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-size)

---

### Example 18: [M-18] DoS: Attacker may significantly increase the cost of withdrawExcessRewards() by creating a significant number of excess receipts

**Source**: Code4rena
**Protocol**: FactoryDAO
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-05-factorydao/blob/db415804c06143d8af6880bc4cda7222e5463c0e/contracts/PermissionlessBasicPoolFactory.sol#L245


## Vulnerability details

## Impact

An attacker may cause a DoS attack on `withdrawExcessRewards()` by creating a excessive number of `receipts` with minimal value. Each of these receipts will need to be withdrawn before the owner can call `withdrawExcessRewards()`. 

The impact is the owner would have to pay an unbounded amount of gas to `withdraw()` all the accounts and receive their excess funds.

## Proof of Concept

`withdrawExcessRewards()` has the requirement that `totalDepositsWei` for the pool is zero before the owner may call this function as seen on line 245.

```solidity
        require(pool.totalDepositsWei == 0, 'Cannot withdraw until all deposits are withdrawn');
```

`pool.totalDepositsWei` is added to each time a user calls `deposit()`. It is increased by the amount the user deposits. There are no restrictions on the amount that may be deposited as a result a user may add 1 wei (or the smallest unit on any currency) which has negligible value.

The owner can force withdraw these accounts by calling `withdraw()` so long as `block.timestamp > pool.endTime`. They would be required to do this for each account that was created.

This could be a significant amount of gas costs, especially if the gas price has increased since the attacker originally made the deposits.

## Recommended Mitigation Steps

C

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-factorydao)

---

### Example 19: [M-15] Malicious Stakers can grief Keepers

**Source**: Code4rena
**Protocol**: Backd
**Impact**: MEDIUM

**Details**:

_Submitted by sseefried_

A Staker -- that has their top-up position removed after `execute` is called by a Keeper -- can always cause the transaction to revert. They can do this by deploying a smart contract to the `payer` address that has implemented a `receive()` function that calls `revert()`. The revert will be triggered by the following [lines](https://github.com/code-423n4/2022-04-backd/blob/c856714a50437cb33240a5964b63687c9876275b/backd/contracts/actions/topup/TopUpAction.sol#L727-L729) in `execute`

```solidity
if (vars.removePosition) {
    gasBank.withdrawUnused(payer);
}
```

This will consume some gas from the keeper while preventing them accruing any rewards for performing the top-up action.

### Proof of Concept

I have implemented a [PoC](https://github.com/sseefried/codearena-backd-2022-04/blob/4d3c3ba7a0139bea01a0bdee9e84a7921572a9fd/backd/tests/top_up_action/sseefried_test_staker_grief.py) in a fork of the contest repo. The attacker's contract can be found [here](https://github.com/sseefried/codearena-backd-2022-04/blob/4d3c3ba7a0139bea01a0bdee9e84a7921572a9fd/backd/contracts/AliceAttacker.sol).

### Recommend Mitigation Steps

To prevent this denial of service attack some way of blacklisting badly behaved Stakers should be added.

**[chase-manning (Backd) confirmed](https://github.com/code-423n4/2022-04-backd-findings/issues/194)**



***

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-04-backd)

---

### Example 20: H-1: DOS in the claimWithdraw function due to an incorrect check of the lastFinalizedRequestId in the EEtherAdapter.sol

**Source**: Sherlock
**Protocol**: Napier Finance - LST/LRT Integrations
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-05-napier-update-judging/issues/55 

## Found by 
Drynooo, KupiaSec, blutorque, merlin, whitehair0330
## Summary
The `claimWithdrawal` function has an incorrect check of `lastFinalizedRequestId`, which lead to a DOS vulnerability in the `EEtherAdapter.claimWithdraw` function.
```solidity
if (_requestId < ETHERFI_WITHDRAW_NFT.lastFinalizedRequestId()) revert RequestInQueue();
```

## Vulnerability Detail
Let's discuss how `WithdrawRequestNFT` handles withdrawal request IDs. When `requestWithdraw` is called, the `nextRequestId` is increased by one.
```solidity
uint256 requestId = nextRequestId++;
```
For a user to successfully call the `claimWithdraw` function, the admin of `WithdrawRequestNFT` must call `finalizeRequests` with our `requestId`:
```solidity
function finalizeRequests(uint256 requestId) external onlyAdmin {
        lastFinalizedRequestId = uint32(requestId);
    }
```
So, if a `requestId` is created and the admin finalizes our request id, then the user will be able to claim the withdrawal amount.

However, the issue lies in the fact that `EEtherAdapter.claimWithdrawal` checks whether `_requestId >= ETHERFI_WITHDRAW_NFT.lastFinalizedRequestId()`, otherwise the call will fail.
```solidity
if (_requestId < ETHERFI_WITHDRAW_NFT.lastFinalizedRequestId()) revert RequestInQueue();
```

However, when we examine the `WithdrawRequestNFT.claimWithdrawal` function, we see a completely different check:
```solidity
require(tokenId 

*[Content truncated...]*

---

### Example 21: TRST-H-1 An attacker can drain Mozaic Vaults by manipulating the LP price

**Source**: Trust Security
**Protocol**: Mozaic Archimedes
**Impact**: HIGH

**Details**:

**Description:**
The controller is tasked with synchronizing LP token price across all chains. It implements a 
lifecycle. An admin initiates the snapshot phase, where Controller requests all Vaults to report 
the total stable ($) value and LP token supply. Once all reports are in, admin calls the settle 
function which dispatches the aggregated value and supply to all vaults. At this point, vaults 
process all deposits and withdrawals requested up to the last snapshot, using the universal 
value/supply ratio. 
The described pipeline falls victim to an economic attack, stemming from the fact that LP 
tokens are LayerZero OFT tokens which can be bridged. An attacker can use this property to 
bypass counting of their LP tokens across all chains. When the controller would receive a
report with correct stable value and artificially low LP supply, it would cause queued LP 
withdrawals to receive incorrectly high dollar value.
To make vaults miscalculate, attacker can wait for Controller to initiate snapshotting. At that 
moment, they can start bridging a large amount of tokens. They may specify custom LayerZero 
adapter params to pay a miniscule gas fee, which will guarantee that the bridge-in transaction 
will fail due to out-of-gas. At this point, they simply wait until all chains have been
snapshotted, and then finish bridging-in with a valid gas amount. Finally, Controller will order 
vaults to settle, at which point the attacker converts their LP tokens at an artificially hig

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Trust Security/2023-05-23-Mozaic Archimedes.md)

---

### Example 22: [H-04] Unbounded loop in _removeNft could lead to a griefing/DOS attack

**Source**: Code4rena
**Protocol**: Visor
**Impact**: HIGH

**Details**:

## Handle

shw


## Vulnerability details

## Impact

Griefing/DOS attack is possible when a malicious NFT contract sends many NFTs to the vault, which could cause excessive gas consumed and even transactions reverted when other users are trying to unlock or transfer NFTs.

## Proof of Concept

1. The function `_removeNft` uses an unbounded loop, which iterates the array `nfts` until a specific one is found. If the NFT to be removed is at the very end of the `nfts` array, this function could consume a large amount of gas.
2. The function `onERC721Received` is permissionless. The vault accepts any NFTs from any NFT contract and pushes the received NFT into the array `nfts`.
3. A malicious user could write an NFT contract, which calls `onERC721Received` of the vault many times to make to array `nfts` grow to a large size. Besides, the malicious NFT contract reverts when anyone tries to transfer (e.g., `safeTransferFrom`) its NFT.
4. The vault then has no way to remove the transferred NFT from the malicious NFT contract. The two only functions to remove NFTs, `transferERC721` and `timeUnlockERC721`, fail since the malicious NFT contract reverts all `safeTransferFrom` calls.
5. As a result, benign users who unlock or transfer NFTs would suffer from large and unnecessary gas consumption. The consumed gas could even exceed the block gas limit and cause the transaction to fail every time.

Referenced code:
[Visor.sol#L127-L140](https://github.com/code-423n4/2021-05-visorfinance/blob

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-05-visorfinance)

---

### Example 23: Renouncing ownership or admin role could affect the normal operation of Connext

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Security Assessment Report

## Severity: High Risk

### Context
- Affected Contracts: `WatcherClient.sol`, `WatchManager.sol`, `Merkle.sol`, `RootManager.sol`, `ConnextPriceOracle.sol`, `Upgrade-BeaconController.sol`, `ProposedOwnableFacet.sol#L276-L285`

### Description
Consider the following scenarios:

#### Instance 1 - Renouncing Ownership
All the contracts that extend from `ProposedOwnable` or `ProposedOwnableUpgradeable` inherit a method called `renounceOwnership`. The owner of the contract can use this method to give up their ownership, thereby leaving the contract without an owner. If that were to happen, it would not be possible to perform any owner-specific functionality on that contract anymore.

The following is a summary of the affected contracts and their impact if the ownership has been renounced. One of the most significant impacts is that Connext's message system cannot recover after a fraud has been resolved since there is no way to unpause and add the connector back to the system.

#### Instance 2 - Renouncing Admin Role
All the contracts that extend from `ProposedOwnableFacet` inherit a method called `revokeRole`. 

1. Assume that the Owner has renounced its power and the only Admin remaining used `revokeRole` to renounce its Admin role.
2. Now the contract is left with Zero Owner & Admin.
3. All swap operations collect admin fees via the `SwapUtils.sol` contract. In the absence of any Admin & Owner, these fees will get stuck in the contract with no way

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 24: [M-02] Twav.sol#_getTwav() will revert when timestamp  4294967296

**Source**: Code4rena
**Protocol**: Nibbl
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-06-nibbl/blob/8c3dbd6adf350f35c58b31723d42117765644110/contracts/Twav/Twav.sol#L35-L42


## Vulnerability details

```solidity
function _getTwav() internal view returns(uint256 _twav){
    if (twavObservations[TWAV_BLOCK_NUMBERS - 1].timestamp != 0) {
        uint8 _index = ((twavObservationsIndex + TWAV_BLOCK_NUMBERS) - 1) % TWAV_BLOCK_NUMBERS;
        TwavObservation memory _twavObservationCurrent = twavObservations[(_index)];
        TwavObservation memory _twavObservationPrev = twavObservations[(_index + 1) % TWAV_BLOCK_NUMBERS];
        _twav = (_twavObservationCurrent.cumulativeValuation - _twavObservationPrev.cumulativeValuation) / (_twavObservationCurrent.timestamp - _twavObservationPrev.timestamp);
    }
}
```

Since `_blockTimestamp` is `uint32`, subtraction underflow is desired at `_twavObservationCurrent.timestamp - _twavObservationPrev.timestamp`.

See: https://github.com/Uniswap/v2-periphery/blob/master/contracts/examples/ExampleOracleSimple.sol#L43

```solidity
function update() external {
    (uint price0Cumulative, uint price1Cumulative, uint32 blockTimestamp) =
        UniswapV2OracleLibrary.currentCumulativePrices(address(pair));
    uint32 timeElapsed = blockTimestamp - blockTimestampLast; // overflow is desired
```

Because the solidity version used by the current implementation is `0.8.10`, and there are some breaking changes in Solidity v0.8.0:

> Arithmetic operations revert on underflow and overflow

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-nibbl)

---

### Example 25: [H-01] Permanent DOS in `liquidity_lockbox` for under $10

**Source**: Code4rena
**Protocol**: Olas
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2023-12-autonolas/blob/main/lockbox-solana/solidity/liquidity_lockbox.sol#L54> <br><https://github.com/code-423n4/2023-12-autonolas/blob/main/lockbox-solana/solidity/liquidity_lockbox.sol#L181-L184>

The `liquidity_lockbox` contract in the `lockbox-solana` project is vulnerable to permanent DOS due to its storage limitations. The contract uses a Program Derived Address (PDA) as a data account, which is created with a maximum size limit of 10 KB.

Every time the `deposit()` function is called, a new element is added to `positionAccounts`, `mapPositionAccountPdaAta`, and `mapPositionAccountLiquidity`, which decreases the available storage by `64 + 32 + 32 = 128` bits. This means that the contract will run out of space after at most `80000 / 128 = 625` deposits.

Once the storage limit is reached, no further deposits can be made, effectively causing a permanent DoS condition. This could be exploited by an attacker to block the contract's functionality at a very small cost.

### Proof of Concept

An attacker can cause a permanent DoS of the contract by calling `deposit()` with the minimum position size only 625 times. This will fill up the storage limit of the PDA, preventing any further deposits from being made.

Since neither the contract nor seemingly Orca's pool contracts impose a limitation on the minimum position size, this can be achieved at a very low cost of `625 * dust * transaction fees`:

<img width="400" alt="no min deposit in SOL/OLAS 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-12-autonolas)

---

## Statistics

- Total findings analyzed: 66
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

