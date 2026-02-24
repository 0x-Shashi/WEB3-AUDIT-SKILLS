---
id: PAT-DOS-GAS
title: Dos Gas Security Patterns
category: gas
severity: low
difficulty: advanced
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - optimization
  - efficiency
  - gas-limit
related_patterns:
  - vulnerability
finding_count_source: 66
finding_count_note: "Count reflects DOS tag only (66). Related tags: gas-limit (18), broken-loop (7). See STATISTICS.md."
last_updated: 2026-02-24
---
# DoS & Gas Security Patterns (Consolidated)

> **Denial of Service attacks make protocols unusable. Gas griefing extracts value from users.**

---

## Quick Summary

| Issue | Description | Severity |
|-------|-------------|----------|
| Unbounded Loop | Loop over user-controlled array | High |
| External Call in Loop | One failure reverts entire batch | High |
| Block Gas Limit | Transaction too large to execute | High |
| Griefing | Attacker makes operations expensive | Medium |
| Fund Lock | Funds become permanently stuck | Critical |
| Push Over Pop | Array grows unbounded | Medium |

---

## Detection Strategy

### Unbounded Loop
```solidity
// VULNERABLE: Array can grow infinitely
function processAll() external {
    for (uint i = 0; i < users.length; i++) {  // If users.length = 10000, OOG
        process(users[i]);
    }
}

// SAFE: Paginated processing
function processBatch(uint start, uint count) external {
    uint end = min(start + count, users.length);
    for (uint i = start; i < end; i++) {
        process(users[i]);
    }
}
```

### External Call in Loop
```solidity
// VULNERABLE: One revert blocks all
function distributeRewards(address[] calldata recipients) external {
    for (uint i = 0; i < recipients.length; i++) {
        payable(recipients[i]).transfer(reward);  // If one reverts, all fail
    }
}

// SAFE: Pull pattern or try/catch
function claimReward() external {
    uint reward = rewards[msg.sender];
    rewards[msg.sender] = 0;
    payable(msg.sender).transfer(reward);
}
```

### Fund Lock Prevention
```solidity
// VULNERABLE: No way to withdraw if stuck
function stake(uint amount) external {
    token.transferFrom(msg.sender, address(this), amount);
    // No unstake function = funds locked forever!
}

// SAFE: Always have emergency withdraw
function emergencyWithdraw() external onlyOwner {
    token.transfer(owner, token.balanceOf(address(this)));
}
```

### Audit Checklist
- [ ] All loops have bounded iteration count
- [ ] No external calls inside loops (or handled with try/catch)
- [ ] Pull pattern used instead of push for distributions
- [ ] Emergency withdrawal mechanism exists
- [ ] No user can grief others' gas costs significantly
- [ ] Arrays that grow have corresponding cleanup mechanism

---

## Included Pattern Files

- dos-patterns.md, denial-of-service-patterns.md
- gas-limit-patterns.md, gas-price-patterns.md
- broken-loop-patterns.md, array-patterns.md, array-reorder-patterns.md
- dust-patterns.md, revert-by-sending-dust-patterns.md
- grief-attack-patterns.md, fund-lock-patterns.md
- withdraw-0-patterns.md, withdraw-pattern-patterns.md

---

## Full Pattern Details

---
## dos-patterns.md
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


---
## denial-of-service-patterns.md
# Denial-Of-Service Security Patterns

## Overview

**Frequency**: 36 occurrences (0.07% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 10 | 26 | 0 | 0 |

**Common Sources**: Sherlock, Code4rena, Pashov Audit Group, TrailOfBits, Trust Security

---

## Detection Checklist

- [ ] Check for denial-of-service vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-02] `Staking.sol#stake()` DoS by staking 1 wei for the recipient when `warmUpPeriod  0`

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

### Example 2: [H-01] Holders array can be manipulated by transferring or burning with amount 0, stealing rewards or bricking certain functions

**Source**: Code4rena
**Protocol**: Althea Liquid Infrastructure
**Impact**: HIGH

**Details**:

### Lines of code

<https://github.com/code-423n4/2024-02-althea-liquid-infrastructure/blob/main/liquid-infrastructure/contracts/LiquidInfrastructureERC20.sol#L214-L231>

### Impact

`LiquidInfrastructureERC20._beforeTokenTransfer()` checks if the `to` address has a balance of `0`, and if so, adds the address to the holders array.

[LiquidInfrastructureERC20#L142-145](https://github.com/code-423n4/2024-02-althea-liquid-infrastructure/blob/main/liquid-infrastructure/contracts/LiquidInfrastructureERC20.sol#L142-L145)

```solidity
bool exists = (this.balanceOf(to) != 0);
if (!exists) {
    holders.push(to);
}
```

However, the ERC20 contract allows for transferring and burning with `amount = 0`, enabling users to manipulate the holders array.

An approved user that has yet to receive tokens can initiate a transfer from another address to themself with an amount of `0`. This enables them to add their address to the holders array multiple times. Then, `LiquidInfrastructureERC20.distribute()` will loop through the user multiple times and give the user more rewards than it should.

```solidity
for (i = nextDistributionRecipient; i < limit; i++) {
    address recipient = holders[i];
    if (isApprovedHolder(recipient)) {
        uint256[] memory receipts = new uint256[](
            distributableERC20s.length
        );
        for (uint j = 0; j < distributableERC20s.length; j++) {
            IERC20 toDistribute = IERC20(distributableERC20s[j]);
            uint256 entitlement = er

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-02-althea-liquid-infrastructure)

---

### Example 3: [H-02] `UniswapV2PriceOracle.sol` `currentCumulativePrices()` will revert when `priceCumulative` addition overflow

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

### Example 4: [M-07] Possible DoS attack when creating Joins in Wand

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

### Example 5: [M-03] DOS risk if enough tokens are minted in Quest.claim can lead, at least, to transaction fee lost

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

### Example 6: H-5: Adding liquidity can be `DoS`ed due to calculation mismatches

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

### Example 7: H-8: It is possible to DoS batch auctions by submitting invalid AltBn128 points when bidding

**Source**: Sherlock
**Protocol**: Axis Finance
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-03-axis-finance-judging/issues/147 

## Found by 
hash, underdog
## Summary

Bidders can submit invalid points for the AltBn128 elliptic curve. The invalid points will make the decrypting process always revert, effectively DoSing the auction process, and locking funds forever in the protocol.

## Vulnerability Detail

Axis finance supports a sealed-auction type of auctions, which is achieved in the Encrypted Marginal Price Auction module by leveraging the ECIES encryption scheme. Axis will specifically use a simplified ECIES implementation that uses the AltBn128 curve, which is a curve with generator point (1,2) and the following formula:

$$
y^2 = x^3 + 3
$$

Bidders will submit encrypted bids to the protocol. One of the parameters required to be submitted by the bidders so that bids can later be decrypted is a public key that will be used in the EMPA decryption process:

```solidity
// EMPAM.sol

function _bid(
        uint96 lotId_, 
        address bidder_,
        address referrer_,
        uint96 amount_,
        bytes calldata auctionData_
    ) internal override returns (uint64 bidId) {
        // Decode auction data 
        (uint256 encryptedAmountOut, Point memory bidPubKey) = 
            abi.decode(auctionData_, (uint256, Point));
 
        ...

        // Check that the bid public key is a valid point for the encryption library
        if (!ECIES.isValid(bidPubKey)) revert Auction_InvalidKey(); 
   
       ...

    

*[Content truncated...]*

---

### Example 8: [H-02] denial of service

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

### Example 9: [H-03] DoS: `claimForAllWindows()` May Be Made Unusable By An Attacker

**Source**: Code4rena
**Protocol**: Joyn
**Impact**: HIGH

**Details**:

_Submitted by kirk-baird, also found by hyh and Ruhum_

When the value of `currentWindow` is raised sufficiently high `Splitter.claimForAllWindows()` will not be able to be called due to the block gas limit.

`currentWindow` can only ever be incremented and thus will always increase. This value will naturally increase as royalties are paid into the contract.

Furthermore, an attacker can continually increment `currentWindow` by calling `incrementWindow()`. An attacker can impersonate a `IRoyaltyVault` and send 1 WEI worth of WETH to pass the required checks.

### Proof of Concept

Excerpt from `Splitter.claimForAllWindows()` demonstrating the for loop over `currentWindow` that will grow indefinitely.

            for (uint256 i = 0; i < currentWindow; i++) {
                if (!isClaimed(msg.sender, i)) {
                    setClaimed(msg.sender, i);

                    amount += scaleAmountByPercentage(
                        balanceForWindow[i],
                        percentageAllocation
                    );
                }
            }

`Splitter.incrementWindow()` may be called by an attacker increasing `currentWindow`.

        function incrementWindow(uint256 royaltyAmount) public returns (bool) {
            uint256 wethBalance;

            require(
                IRoyaltyVault(msg.sender).supportsInterface(IID_IROYALTY),
                "Royalty Vault not supported"
            );
            require(
                IRoyaltyVault(msg.sender).getSplitter(

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-03-joyn)

---

### Example 10: [M-05] Possible DoS When calling `GammaTradeMarket::_removePosition` will cause user position to not be able to get liquidated

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

### Example 11: [M-02] Twav.sol#_getTwav() will revert when timestamp  4294967296

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

### Example 12: [H-01] Permanent DOS in `liquidity_lockbox` for under $10

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

### Example 13: M-14: Attackers Can DOS Balancer Vaults By Bypassing The BPT Threshold

**Source**: Sherlock
**Protocol**: Notional
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/66 

## Found by 
xiaoming90

## Summary

Malicious users can lock up all the leverage vaults offered by Notional causing denial-of-service by bypassing the BPT threshold and subseqently trigger an emergency settlement against the vaults.

## Vulnerability Detail

The current BPT threshold is set to 20% of the total BTP supply based on the environment file provided during the audit.

https://github.com/sherlock-audit/2022-09-notional/blob/main/leveraged-vaults/scripts/BalancerEnvironment.py#L41

```solidity
File: BalancerEnvironment.py
40:             "oracleWindowInSeconds": 3600,
41:             "maxBalancerPoolShare": 2e3, # 20%
42:             "settlementSlippageLimitPercent": 5e6, # 5%
```

https://github.com/sherlock-audit/2022-09-notional/blob/main/leveraged-vaults/contracts/vaults/balancer/internal/BalancerVaultStorage.sol#L60

```solidity
File: BalancerVaultStorage.sol
60:     function _bptThreshold(StrategyVaultSettings memory strategyVaultSettings, uint256 totalBPTSupply) 
61:         internal pure returns (uint256) {
62:         return (totalBPTSupply * strategyVaultSettings.maxBalancerPoolShare) / BalancerConstants.VAULT_PERCENT_BASIS;
63:     }
```

When the total number of BPT owned by the vault exceeds the BPT threshold, no one will be able to enter the vault as per the require check at Line 295-296 within the `TwoTokenPoolUtils._joinPoolAndStake` function.

https://github.com/sherlock-a

*[Content truncated...]*

---

### Example 14: M-1: When one of the plugins is broken or paused, `deposit()` or `withdraw()` of the whole Vault contract can malfunction

**Source**: Sherlock
**Protocol**: Mycelium
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-10-mycelium-judging/tree/main/006-M 

## Found by 
ctf\_sec, IllIllI, berndartmueller, ak1, WATCHPUG

## Summary

One malfunctioning plugin can result in the whole Vault contract malfunctioning.

## Vulnerability Detail

A given plugin can temporally or even permanently becomes malfunctioning (cannot deposit/withdraw) for all sorts of reasons.

Eg, Aave V2 Lending Pool can be paused, which will prevent multiple core functions that the Aave v2 plugin depends on from working, including `lendingPool.deposit()` and `lendingPool.withdraw()`.

https://github.com/aave/protocol-v2/blob/master/contracts/protocol/lendingpool/LendingPool.sol#L54

```soldity
  modifier whenNotPaused() {
    _whenNotPaused();
    _;
  }
```

https://github.com/aave/protocol-v2/blob/master/contracts/protocol/lendingpool/LendingPool.sol#L142-L146

```solidity
  function withdraw(
    address asset,
    uint256 amount,
    address to
  ) external override whenNotPaused returns (uint256) {
```

That's because the deposit will always goes to the first plugin, and withdraw from the last plugin first.

## Impact

When Aave V2 Lending Pool is paused, users won't be able to deposit or withdraw from the vault.

Neither can the owner remove the plugin nor rebalanced it to other plugins to resume operation.

Because withdrawal from the plugin can not be done, and removing a plugin or rebalancing both rely on this.

## Code Snippet

https://github.com/sherlock-audit/2022-

*[Content truncated...]*

---

### Example 15: M-9: [M] Incorrect Validation in `Pool.sol#transferLPs` lead to a DOS attack

**Source**: Sherlock
**Protocol**: Ajna
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-ajna-judging/issues/116 

## Found by 
oxcm

## Summary

The code in the transferLPs function has an incorrect validation check, where it requires `allowances_` to be strictly equal to `lenderLpBalance`, instead of just `allowances_` being greater than `transferAmount`.

## Vulnerability Detail

In the `transferLPs()` function, `transferAmount` is being compared to `allowances_[owner_][newOwner_][index]` and `lenderLpBalance`. If the values are not strictly equal, the function will revert with a `NoAllowance` error. 

Due to the requirement of `transferLPs()` that `allowances_` must equal `lenderLpBalance`, the user can only enter `lpsAmountToApprove_` as the current `lenderLpBalance` when using `approveLpOwnership()`.

This results in `transferLPs()` reverting with `NoAllowance` if `lenderLpBalance` undergoes any change, allowing attackers to design a DOS attack.

However, this validation is not necessary as it should only require `allowances_` to be greater than `transferAmount`.

## Impact

An attacker could exploit this vulnerability by transferring a small amount of LP tokens to the owner before the transfer to the new owner is initiated. This would cause the `allowances_` value to be less than `lenderLpBalance`, causing the transfer to revert and the tokens to remain in the original owner's account.

## Code Snippet

Relevant code snippet from transferLPs function:
 
https://github.com/sherlock-audit/2023-01-ajna/blob/ma

*[Content truncated...]*

---

### Example 16: M-1: Auction fails if the 'Honorarium Rate' is 0%

**Source**: Sherlock
**Protocol**: RadicalxChange
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-02-radicalxchange-judging/issues/31 

## Found by 
Al-Qa-qa, sammy
## Summary
The Honorarium Rate is the required percentage of a winning Auction Pitch bid that the Steward makes to the Creator Circle at the beginning of each Stewardship Cycle. 

`$$ Winning Bid * Honorarium Rate = Periodic Honorarium $$`

To mimic the dynamics of private ownership, the _Creator Circle_ may choose a 0% _Honorarium Rate_. However, doing so breaks the functionality of the protocol.
## Vulnerability Detail
To place a bid, a user must call the [`placeBid`](https://github.com/RadicalxChange/pco-art/blob/4acd6b06840028ba616b6200439ce0d6aa1e6276/contracts/auction/facets/EnglishPeriodicAuctionFacet.sol#L153) function in `EnglishPeriodicAuctionFacet.sol` and deposit collateral(`collateralAmount`) equal to `bidAmount + feeAmount`. The `feeAmount` here represents the _Honorarium Rate_ mentioned above. 
The `placeBid` function calls the [`_placeBid`](https://github.com/RadicalxChange/pco-art/blob/4acd6b06840028ba616b6200439ce0d6aa1e6276/contracts/auction/EnglishPeriodicAuctionInternal.sol#L286) internal function in `EnglishPeriodicAuctionInternal.sol` which calculates the  `totalCollateralAmount` as follows : 
```solidity
uint256 totalCollateralAmount = bid.collateralAmount + collateralAmount;
```
Here, `bid.collateralAmount` is the cumulative collateral deposited by the bidder in previous bids during the current auction round(i.e, zero if no bids were place

*[Content truncated...]*

---

### Example 17: H-4: Malicious user can DOS pool and avoid liquidation by creating secondary liquidity pool for Velodrome token pair

**Source**: Sherlock
**Protocol**: Isomorph
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-isomorph-judging/issues/72 

## Found by 
0x52

## Summary

For every Vault_Velo interaction the vault attempts to price the liquidity of the user. This calls priceLiquidity in the corresponding DepsoitReciept. The prices the underlying assets by swapping them through the Velodrome router. Velodrome can have both a stable and volatile pool for each asset pair. When calling the router directly it routes through the pool that gives the best price. In priceLiquidity the transaction will revert if the router routes through the wrong pool (i.e. trading the volatile pool instead of the stable pool). A malicious user can use this to their advantage to avoid being liquidated.  They could manipulate the price of the opposite pool so that any call to liquidate them would route through the wrong pool and revert.

## Vulnerability Detail

        uint256 amountOut; //amount received by trade
        bool stablePool; //if the traded pool is stable or volatile.
        (amountOut, stablePool) = router.getAmountOut(HUNDRED_TOKENS, token1, USDC);
        require(stablePool == stable, "pricing occuring through wrong pool" );

DepositReceipt uses the getAmountOut call the estimate the amountOut. The router will return the best rate between the volatile and stable pool. If the wrong pool give the better rate then the transaction will revert. Since pricing is called during liquidation, a malicious user could manipulate the price of the wrong pool

*[Content truncated...]*

---

### Example 18: [M-08] OOG error in `clearLoop()`

**Source**: Pashov Audit Group
**Protocol**: Primodium_2024-10-02
**Impact**: MEDIUM

**Details**:

## Severity

**Impact:** High

**Likelihood:** Low

## Description

Function `ResetClearLoopSubsystem.clearLoop()` calls `PointsMap.clear(empire)` to clear all utilities associated with an empire. The issue is that this function loops through all players of the empire and clears their data and if the player's count is very big then the execution can encounter OOG.

```solidity
  function clear(EEmpire empire) internal {
    bytes32[] memory players = keys(empire);
    for (uint256 i = 0; i < players.length; i++) {
      Value_PointsMap.deleteRecord(empire, players[i]);
      Meta_PointsMap.deleteRecord(empire, players[i]);
    }
    Keys_PointsMap.deleteRecord(empire);
    Empire.setPointsIssued(empire, 0);
  }
```

## Recommendations

Add restriction to the number of players or avoid looping through all of them in one transaction.

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/Primodium-security-review_2024-10-02.md)

---

### Example 19: [M-02] DoS and gas griefing of calls to Prime.updateScores()

**Source**: Code4rena
**Protocol**: Venus Protocol
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2023-09-venus/blob/main/contracts/Tokens/Prime/Prime.sol#L200-L230> 

<https://github.com/code-423n4/2023-09-venus/blob/main/tests/hardhat/Prime/Prime.ts#L294-L301>

`updateScores()` is meant to be called to update the scores of many users after reward alpha is changed or reward multipliers are changed. An attacker can cause calls to `Prime.updateScores()` to out-of-gas revert, delaying score updates. Rewards will be distributed incorrectly until scores are properly updated.

### Proof of Concept

`updateScores()` will run out of gas and revert if any of the `users` passed in the argument array have already been updated. This is due to the `continue` statement and the incrementing location of `i`:

        function updateScores(address[] memory users) external {
            if (pendingScoreUpdates == 0) revert NoScoreUpdatesRequired();
            if (nextScoreUpdateRoundId == 0) revert NoScoreUpdatesRequired();

            for (uint256 i = 0; i < users.length; ) {
                address user = users[i];

                if (!tokens[user].exists) revert UserHasNoPrimeToken();
                if (isScoreUpdated[nextScoreUpdateRoundId][user]) continue;
                ...
                unchecked {
                    i++;
                }

                emit UserScoreUpdated(user);
            }
        }

An attacker can frontrun calls to `updateScores()` with a call to `updateScores()`, passing in a 1-member array of one of the addresses 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-09-venus)

---

### Example 20: TRST-M-3 BaseV1Pair could break because of overflow

**Source**: Trust Security
**Protocol**: Satin.Exchange
**Impact**: MEDIUM

**Details**:

**Description:**
In the function _update(), called internally by `mint()`, `burn()` and `swap()`, the following code 
is executed:
```solidity
    uint256 timeElapsed = blockTimestamp - blockTimestampLast;
     // overflow is desired
    if (timeElapsed > 0 && _reserve0 != 0 && _reserve1 != 0) {
      reserve0CumulativeLast += _reserve0 * timeElapsed;
        reserve1CumulativeLast += _reserve1 * timeElapsed;
     }
```
This is forked from UniswapV2 source code, and its meant and known to overflow. It works 
fine if solidity < 0.8.0 is used but reverts when solidity >= 0.8.0 is used.
If this happens all the core functionalities of the pool would break, including `mint()`, `burn()`, 
and `swap()`.

**Recommended Mitigation:**
Wrap the operation around an unchecked{} block so that when the variable overflows it 
loops back to 0 instead of reverting.

**Team Response:**
Fixed

**Mitigation Review:**
The issue has been resolved as suggested, the operation has been wrapped around an 
unchecked{} block

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Trust Security/2023-02-24-Satin.Exchange.md)

---

### Example 21: M-5: PositionManager will revert when trying to return back to user excess of the premium transferred from the user when minting position

**Source**: Sherlock
**Protocol**: Smilee Finance
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-02-smilee-finance-judging/issues/40 

## Found by 
juan, panprog
## Summary

`PositionManager.mint` calculates preliminary premium to be paid for buying the option and transfers it from the user. The actual premium paid may differ, and if it's smaller, excess is returned back to user. However, it is returned using the `safeTransferFrom`:
```solidity
    if (obtainedPremium > premium) {
        baseToken.safeTransferFrom(address(this), msg.sender, obtainedPremium - premium);
    }
```

The problem is that `PositionManager` doesn't approve itself to transfer baseToken to `msg.sender`, and USDC `transferFrom` implementation requires approval even if address is transferring from its own address. Thus the transfer will revert and user will be unable to open position.

## Vulnerability Detail

Both `transferFrom` implementations in USDC on Arbitrum (USDC and USDC.e) require approval from any address, including when doing transfers from your own address.
https://arbiscan.io/address/0x1efb3f88bc88f03fd1804a5c53b7141bbef5ded8#code
```solidity
    function transferFrom(address sender, address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(sender, recipient, amount);
        _approve(sender, _msgSender(), _allowances[sender][_msgSender()].sub(amount, "ERC20: transfer amount exceeds allowance"));
        return true;
    }
```

https://arbiscan.io/address/0x86e721b43d4ecfa71119dd38c0f938a75fdb57b3#code


*[Content truncated...]*

---

### Example 22: M-3: Whenever swapPrice  oraclePrice, minting via PositionManager will revert, due to not enough funds being obtained from user.

**Source**: Sherlock
**Protocol**: Smilee Finance
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-02-smilee-finance-judging/issues/32 

## Found by 
cawfree, juan, panprog
## Summary
In [`PositionManager::mint()`](https://github.com/sherlock-audit/2024-02-smilee-finance/blob/3241f1bf0c8e951a41dd2e51997f64ef3ec017bd/smilee-v2-contracts/src/periphery/PositionManager.sol#L91-L178), `obtainedPremium` is calculated in a different way to the actual premium needed, and this will lead to a revert, denying service to users.

## Vulnerability Detail
In [`PositionManager::mint()`](https://github.com/sherlock-audit/2024-02-smilee-finance/blob/3241f1bf0c8e951a41dd2e51997f64ef3ec017bd/smilee-v2-contracts/src/periphery/PositionManager.sol#L91-L178), the PM gets `obtainedPremium` from `DVP::premium()`:
```solidity
(obtainedPremium, ) = dvp.premium(params.strike, params.notionalUp, params.notionalDown);
```

Then the actual premium used when minting by the DVP is obtained via the following [code](https://github.com/sherlock-audit/2024-02-smilee-finance/blob/3241f1bf0c8e951a41dd2e51997f64ef3ec017bd/smilee-v2-contracts/src/DVP.sol#L152-L155):
<details>
<summary>Determining option premium</summary>

```js
    uint256 swapPrice = _deltaHedgePosition(strike, amount, true);
    uint256 premiumOrac = _getMarketValue(strike, amount, true, IPriceOracle(_getPriceOracle()).getPrice(sideToken, baseToken));
    uint256 premiumSwap = _getMarketValue(strike, amount, true, swapPrice);
    premium_ = premiumSwap > premiumOrac ? premiumSwap : premiumOrac;
```


*[Content truncated...]*

---

### Example 23: M-3: JalaPair potential permanent DoS due to overflow

**Source**: Sherlock
**Protocol**: Jala Swap
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-02-jala-swap-judging/issues/186 

The protocol has acknowledged this issue.

## Found by 
0k, 0xMojito, 0xRstStn, 0xloscar01, Stoicov, ZanyBonzy, den\_sosnovskyi, deth, fibonacci, giraffe, mahmud, n1punp, santiellena, sunill\_eth, tank
## Summary

In the `JalaPair::_update` function, overflow is intentionally desired in the calculations for `timeElapsed` and `priceCumulative`. This is forked from the UniswapV2 source code, and its meant and known to overflow. UniswapV2 was developed using Solidity 0.6.6, where arithmetic operations overflow and underflow by default. However, Jala utilizes Solidity >=0.8.0, where such operations will automatically revert.

## Vulnerability Detail

```solidity
uint32 timeElapsed = blockTimestamp - blockTimestampLast; // overflow is desired
if (timeElapsed > 0 && _reserve0 != 0 && _reserve1 != 0) {
    // * never overflows, and + overflow is desired
    price0CumulativeLast += uint256(UQ112x112.encode(_reserve1).uqdiv(_reserve0)) * timeElapsed;
    price1CumulativeLast += uint256(UQ112x112.encode(_reserve0).uqdiv(_reserve1)) * timeElapsed;
}
```

## Impact

This issue could potentially lead to permanent denial of service for a pool. All the core functionalities such as `mint`, `burn`, or `swap` would be broken. Consequently, all funds would be locked within the contract.

I think issue with High impact and a Low probability (merely due to the extended timeframe for the event's occurrence, it's impo

*[Content truncated...]*

---

### Example 24: M-7: Users are unable to collect their yield if tranche is paused

**Source**: Sherlock
**Protocol**: Napier
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-01-napier-judging/issues/97 

The protocol has acknowledged this issue.

## Found by 
xiaoming90
## Summary

Users are unable to collect their yield if Tranche is paused, resulting in a loss of assets for the victims.

## Vulnerability Detail

Per the contest's README page, it stated that the admin/owner is "RESTRICTED". Thus, any finding showing that the owner/admin can steal a user's funds, cause loss of funds or harm to the users, or cause the user's fund to be struck is valid in this audit contest.

> Q: Is the admin/owner of the protocol/contracts TRUSTED or RESTRICTED?
>
> RESTRICTED

The admin of the protocol has the ability to pause the Tranche contract, and no one except for the admin can unpause it. If a malicious admin paused the Tranche contract, the users will not be able to collect their yield earned, leading to a loss of assets for them.

https://github.com/sherlock-audit/2024-01-napier/blob/main/napier-v1/src/Tranche.sol#L605

```solidity
File: Tranche.sol
603:     /// @notice Pause issue, collect and updateUnclaimedYield
604:     /// @dev only callable by management
605:     function pause() external onlyManagement {
606:         _pause();
607:     }
608: 
609:     /// @notice Unpause issue, collect and updateUnclaimedYield
610:     /// @dev only callable by management
611:     function unpause() external onlyManagement {
612:         _unpause();
613:     }
```

The following shows that the `collect` function can

*[Content truncated...]*

---

### Example 25: M-1: Nobody can cast for any proposal

**Source**: Sherlock
**Protocol**: Olympus On-Chain Governance
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance-judging/issues/37 

## Found by 
Bauer, Breeje, alexzoid, blutorque, cawfree, cocacola, emrekocak, fibonacci, hals, nobody2018, pontifex, s1ce
## Summary

[[castVote](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L369)](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L369)/[[castVoteWithReason](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L385)](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L385)/[[castVoteBySig](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L403)](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L403) are used to vote for the specified proposal. These functions internally call [[castVoteInternal](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/external/governance/GovernorBravoDelegate.sol#L433-L437)](https://github.com/sherlock-audit/2024-01-olympus-on-chain-governance/blob/main/bophades/src/ex

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 36
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## gas-limit-patterns.md
# Gas Limit Security Patterns

## Overview

**Frequency**: 18 occurrences (0.04% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 6 | 11 | 1 | 0 |

**Common Sources**: Sherlock, Code4rena, Pashov Audit Group, Spearbit, Cyfrin

---

## Detection Checklist

- [ ] Check for gas limit vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-08] Gas limit check is inaccurate, leading to an operator being able to fail a job intentionally

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: HIGH

**Details**:

[HolographOperator.sol#L316](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/src/HolographOperator.sol#L316)<br>

There's a check at line 316 that verifies that there's enough gas left to execute the `HolographBridge.bridgeInRequest()` with the `gasLimit` set by the user, however the actual amount of gas left during the call is less than that (mainly due to the `1/64` rule, see below).<br>
An attacker can use that gap to fail the job while still having the `executeJob()` function complete.

### Impact

The owner of the bridged token would loose access to the token since the job failed.

### Proof of Concept

Besides using a few units of gas between the check and the actual call, there's also a rule that only 63/64 of the remaining gas would be dedicated to an (external) function call. Since there are 2 external function calls done (`nonRevertingBridgeCall()` and the actual call to the bridge) `~2/64` of the gas isn't sent to the bridge call and can be used after the bridge call runs out of gas.

The following PoC shows that if the amount of gas left before the call is at least 1 million then the execution can continue after the bridge call fails:

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract ContractTest is Test {
    event FailedOperatorJob(bytes32 jobHash);
    uint256 private _inboundMessageCounter;
    mapping(bytes32 => bool) private _failedJobs;
    constr

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 2: [H-01] An attacker can lock operator out of the pod by setting gas limit that's higher than the block gas limit of dest chain

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: HIGH

**Details**:

[HolographOperator.sol#L415](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/HolographOperator.sol#L415)<br>

When a beaming job is executed, there's a requirement that the gas left would be at least as the `gasLimit` set by the user.
Given that there's no limit on the `gasLimit` the user can set, a user can set the `gasLimit` to amount that's higher than the block gas limit on the dest chain, causing the operator to fail to execute the job.

### Impact

Operators would be locked out of the pod, unable to execute any more jobs and not being able to get back the bond they paid.

The attacker would have to pay a value equivalent to the gas fee if that amount was realistic (i.e. `gasPrice` &ast; `gasLimit` in dest chain native token), but this can be a relative low amount for Polygon and Avalanche chain (for Polygon that's 20M gas limit and `200 Gwei gas = 4 Matic`, for Avalanche the block gas limit seems to be 8M and the price `~30 nAVAX = 0.24 AVAX`). Plus, the operator isn't going to receive that amount.

### Proof of Concept

The following test demonstrates this scenario:

```diff
diff --git a/test/06_cross-chain_minting_tests_l1_l2.ts b/test/06_cross-chain_minting_tests_l1_l2.ts
index 1f2b959..a1a23b7 100644
--- a/test/06_cross-chain_minting_tests_l1_l2.ts
+++ b/test/06_cross-chain_minting_tests_l1_l2.ts
@@ -276,6 +276,7 @@ describe('Testing cross-chain minting (L1 & L2)', async function () {
             gasLimit: TES

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 3: [H-03]  LayerZeroModule miscalculates gas, risking loss of assets

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: HIGH

**Details**:

[LayerZeroModule.sol#L431-L445](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/module/LayerZeroModule.sol#L431-L445)<br>

Holograph gets its cross chain messaging primitives through Layer Zero. To get pricing estimate, it uses the DstConfig price struct exposed in LZ's [RelayerV2](https://github.com/LayerZero-Labs/LayerZero/blob/main/contracts/RelayerV2.sol#L133).

The issue is that the important baseGas and gasPerByte configuration parameters, which are used to calculate a custom amount of gas for the destination LZ message, use the values that come from the *source* chain. This is in contrast to LZ which handles DstConfigs in a mapping keyed by chainID.  The encoded gas amount is described [here](https://layerzero.gitbook.io/docs/guides/advanced/relayer-adapter-parameters).

### Impact

The impact is that when those fields are different between chains, one of two things may happen:

1.  Less severe - we waste excess gas, which is refunded to the lzReceive() caller (Layer Zero)
2.  More severe - we underprice the delivery cost, causing lzReceive() to revert and the NFT stuck in limbo forever.

The code does not handle a failed lzReceive (differently to a failed executeJob). Therefore, no failure event is emitted and the NFT is screwed.

### Recommended Mitigation Steps

Firstly, make sure to use the target gas costs.<br>
Secondly, re-engineer lzReceive to be fault-proof, i.e. save some gas to emit result event.

**[gze

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

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

### Example 5: TRST-M-10 MozBridge underestimates gas for sending of Moz messages

**Source**: Trust Security
**Protocol**: Mozaic Archimedes
**Impact**: MEDIUM

**Details**:

**Description:**
The bridge calculates LayerZero fees for sending Mozaic messages using the function below:
```solidity
        function quoteLayerZeroFee(uint16 _chainId, uint16 _msgType, LzTxObj memory _lzTxParams) public view returns (uint256 _nativeFee, uint256 _zroFee) { 
             bytes memory payload = "";
        if (_msgType == TYPE_REPORT_SNAPSHOT) {
                payload = abi.encode(TYPE_REPORT_SNAPSHOT);
        }
        else if (_msgType == TYPE_REQUEST_SNAPSHOT) {
                     payload = abi.encode(TYPE_REQUEST_SNAPSHOT);
        }
        else if (_msgType == TYPE_SWAP_REMOTE) {
                        payload = abi.encode(TYPE_SWAP_REMOTE);
        }
        else if (_msgType == TYPE_STAKE_ASSETS) {
                          payload = abi.encode(TYPE_STAKE_ASSETS);
        }   
        else if (_msgType == TYPE_UNSTAKE_ASSETS) {
                                 payload = abi.encode(TYPE_UNSTAKE_ASSETS);
        }
        else if (_msgType == TYPE_REPORT_SETTLE) {
                                 payload = abi.encode(TYPE_REPORT_SETTLE);
        }
        else if (_msgType == TYPE_REQUEST_SETTLE) {
                            payload = abi.encode(TYPE_REQUEST_SETTLE);
        }
        else {
                         revert("MozBridge: unsupported function type");
        }
        
                     bytes memory _adapterParams = _txParamBuilder(_chainId, _msgType, _lzTxParams);
              return layerZeroEndpoint.estimateFees(_chainId, addr

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Trust Security/2023-05-23-Mozaic Archimedes.md)

---

### Example 6: [H-03] DoS: `claimForAllWindows()` May Be Made Unusable By An Attacker

**Source**: Code4rena
**Protocol**: Joyn
**Impact**: HIGH

**Details**:

_Submitted by kirk-baird, also found by hyh and Ruhum_

When the value of `currentWindow` is raised sufficiently high `Splitter.claimForAllWindows()` will not be able to be called due to the block gas limit.

`currentWindow` can only ever be incremented and thus will always increase. This value will naturally increase as royalties are paid into the contract.

Furthermore, an attacker can continually increment `currentWindow` by calling `incrementWindow()`. An attacker can impersonate a `IRoyaltyVault` and send 1 WEI worth of WETH to pass the required checks.

### Proof of Concept

Excerpt from `Splitter.claimForAllWindows()` demonstrating the for loop over `currentWindow` that will grow indefinitely.

            for (uint256 i = 0; i < currentWindow; i++) {
                if (!isClaimed(msg.sender, i)) {
                    setClaimed(msg.sender, i);

                    amount += scaleAmountByPercentage(
                        balanceForWindow[i],
                        percentageAllocation
                    );
                }
            }

`Splitter.incrementWindow()` may be called by an attacker increasing `currentWindow`.

        function incrementWindow(uint256 royaltyAmount) public returns (bool) {
            uint256 wethBalance;

            require(
                IRoyaltyVault(msg.sender).supportsInterface(IID_IROYALTY),
                "Royalty Vault not supported"
            );
            require(
                IRoyaltyVault(msg.sender).getSplitter(

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-03-joyn)

---

### Example 7: M-14: BondAggregator.liveMarketsBy eventually will revert because of block gas limit

**Source**: Sherlock
**Protocol**: Bond Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-bond-judging/issues/10 

## Found by 
rvierdiiev

## Summary
BondAggregator.liveMarketsBy eventually will revert because of block gas limit
## Vulnerability Detail
https://github.com/sherlock-audit/2022-11-bond/blob/main/src/BondAggregator.sol#L259-L280
```solidity
    function liveMarketsBy(address owner_) external view returns (uint256[] memory) {
        uint256 count;
        IBondAuctioneer auctioneer;
        for (uint256 i; i < marketCounter; ++i) {
            auctioneer = marketsToAuctioneers[i];
            if (auctioneer.isLive(i) && auctioneer.ownerOf(i) == owner_) {
                ++count;
            }
        }


        uint256[] memory ids = new uint256[](count);
        count = 0;
        for (uint256 i; i < marketCounter; ++i) {
            auctioneer = marketsToAuctioneers[i];
            if (auctioneer.isLive(i) && auctioneer.ownerOf(i) == owner_) {
                ids[count] = i;
                ++count;
            }
        }


        return ids;
    }
```
BondAggregator.liveMarketsBy function is looping through all markets and does at least `marketCounter` amount of external calls(when all markets are not live) and at most 4 * `marketCounter` external calls(when all markets are live and owner matches. This  all consumes a lot of gas, even that is called from view function. And each new market increases loop size.

That means that after some time `marketsToAuctioneers` mapping will be big enough that 

*[Content truncated...]*

---

### Example 8: [M-08] OOG error in `clearLoop()`

**Source**: Pashov Audit Group
**Protocol**: Primodium_2024-10-02
**Impact**: MEDIUM

**Details**:

## Severity

**Impact:** High

**Likelihood:** Low

## Description

Function `ResetClearLoopSubsystem.clearLoop()` calls `PointsMap.clear(empire)` to clear all utilities associated with an empire. The issue is that this function loops through all players of the empire and clears their data and if the player's count is very big then the execution can encounter OOG.

```solidity
  function clear(EEmpire empire) internal {
    bytes32[] memory players = keys(empire);
    for (uint256 i = 0; i < players.length; i++) {
      Value_PointsMap.deleteRecord(empire, players[i]);
      Meta_PointsMap.deleteRecord(empire, players[i]);
    }
    Keys_PointsMap.deleteRecord(empire);
    Empire.setPointsIssued(empire, 0);
  }
```

## Recommendations

Add restriction to the number of players or avoid looping through all of them in one transaction.

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/Primodium-security-review_2024-10-02.md)

---

### Example 9: [M-03] Risk of DoS when stoping large rental orders due to block gas limit

**Source**: Code4rena
**Protocol**: reNFT
**Impact**: MEDIUM

**Details**:

When an order is created on Opensea the `Create::validateOrder()` policy method is used to ensure the order is configured correctly. Currently there is no maximum limit to the number of `offers` in the input `ZoneParameters`, which allows orders to contain an arbitrary amount of ERC-721 and ERC-1155 items to a rental order.

If a large enough rental order is successfully created, there is a risk that it won't be able to be stopped by calling the `Stop::stopRent()` due to the amount of gas required exceeding the block gas limit. This would prevent the escrow from settling the order and leave the order permantanly in a rental state. This also means any ERC-721 and ERC-1155 tokens in the order would not be able to be reclaimed.

This situation arises under the following conditions:

*   The call to stop a rental order uses more gas than the call to create a rental order
*   The call to create the rental order is successful
*   The call to stop a rental order uses more gas than the block gas limit

### Proof of Concept

Below I have written 2 proof of concepts to show the above conditions are possible. Each of these can be added to `StopRent.t.sol` to run.

<Details>

```solidity
    // Update the `setup` in AccountCreator to 2000+ tokens on deployToken
    function testFuzz_StopRent_PayOrder_More_Expensive_To_Stop_Than_Start(uint numOf721, uint numof1155) public {
        numOf721 = bound(numOf721, 400, erc721s.length);
        numof1155 = bound(numof1155, 400, erc1155s.length);

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-renft)

---

### Example 10: Arithemetic underflow leading to unexpected revert and loss of funds in Receiver contract.

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
- **Files:** `Receiver.sol#L254`, `Receiver.sol#L282`

## Description
The Receiver contract is designed to gracefully return the funds to users. It reserves the gas for recovering gas before doing swaps via `executor.swapAndCompleteBridgeTokens`. The logic of reserving gas for recovering funds is implemented at `Receiver.sol#L236-L258`.

```solidity
contract Receiver is ILiFi, ReentrancyGuard, TransferrableOwnership {
    // ...
    if (reserveRecoverGas && gasleft() < _recoverGas) {
        // case 1a: not enough gas left to execute calls
        receiver.call{ value: amount }("");
        // ...
    }
    // case 1b: enough gas left to execute calls
    try
        executor.swapAndCompleteBridgeTokens{
            value: amount,
            gas: gasleft() - _recoverGas
        }(_transactionId, _swapData, assetId, receiver) 
    {} catch {
        receiver.call{ value: amount }("");
    }
    // ...
}
```

The `gasleft()` function returns the remaining gas of a call. It is continuously decreasing. The second query of `gasleft()` is smaller than the first query. Hence, if the attacker tries to relay the transaction with a carefully crafted gas where `gasleft() >= _recoverGas` at the first query and `gasleft() - _recoverGas` reverts, this results in the token loss in the Receiver contract.

## Recommendation
Recommend to cache the `gasleft()`:
```solidity
if (LibAsset.isNativeAsset(assetId)) {
    // case 1: native asset
    + uint256 cach

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-retainer1-Spearbit-Security-Review.pdf)

---

### Example 11: Controller Can Indefinitely Lock Users Tokens

**Source**: SigmaPrime
**Protocol**: Status
**Impact**: MEDIUM

**Details**:

## Description

The `release()` function is affected by a denial of service (DoS) vulnerability, which allows the controller (or an attacker who owns the controller account) to permanently prevent users from withdrawing their deposited tokens.

This vulnerability relates to the way the external call on line [143] is executed. A malicious controller can create an attack contract, which implements a false assert (as shown in DOSAttack Contract) that consumes all the gas of the called transaction, causing the global transaction to fail. To execute this attack, the controller would migrate the `UsernameRegistrar` contract to the malicious contract, preventing all users from withdrawing their tokens.

**Note:** In practice, gas allowance of the CALL opcode varies and is dependent on the total transaction gas allowance. For transactions with > 3.5M gas, the residue gas after the call is sufficient to complete the `release()` function. See the test: `test_attack_dos_all_users` that accompanies this report for a demonstration.

## Recommendations

This type of vulnerability can be prevented by specifying a gas stipend to the external call, which prevents the external call from consuming the entire gas of the transaction. Such a solution will limit the functionality of `dropUsername(bytes32)` to the stipend gas specified in the call. An example of the correct syntax is:

```solidity
1 ! newOwner.call.gas(gasAmount)(
2 abi.encodeWithSignature(
3 "dropUsername(bytes32)",
4 _label
5 )
6 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/sigp/public-audits/blob/master/reports/status/review.pdf)

---

### Example 12: H-2: Malicious user can use an excessively large _toAddress in OFTCore#sendFrom to break layerZero communication

**Source**: Sherlock
**Protocol**: UXD Protocol
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-uxd-judging/issues/270 

## Found by 
0x52

## Summary

By default layerZero implements a blocking behavior, that is, that each message must be processed and succeed in the order that it was sent. In order to circumvent this behavior the receiver must implement their own try-catch pattern. If the try-catch pattern in the receiving app ever fails then it will revert to its blocking behavior. The _toAddress input to OFTCore#sendFrom is calldata of any arbitrary length. An attacker can abuse this and submit a send request with an excessively large _toAddress to break communication between network with different gas limits.

## Vulnerability Detail

    function sendFrom(address _from, uint16 _dstChainId, bytes calldata _toAddress, uint _amount, address payable _refundAddress, address _zroPaymentAddress, bytes calldata _adapterParams) public payable virtual override {
        _send(_from, _dstChainId, _toAddress, _amount, _refundAddress, _zroPaymentAddress, _adapterParams);
    }

The _toAddress input to OFTCore#sendFrom is a bytes calldata of any arbitrary size. This can be used as follows to break communication between chains that have different block gas limits.

Example:
Let's say that an attacker wishes to permanently block the channel Arbitrum -> Optimism. Arbitrum has a massive gas block limit, much higher than Optimism's 20M block gas limit. The attacker would call sendFrom on the Arbitrum chain with the Optimism chain as 

*[Content truncated...]*

---

### Example 13: M-5: Users buying too many tickets will DoS them and the protocol if they are the winner due to OOG

**Source**: Sherlock
**Protocol**: Winnables Raffles
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-08-winnables-raffles-judging/issues/398 

## Found by 
0x73696d616f, Oblivionis, S3v3ru5, TessKimy, kuprum, neko\_nyaa
### Summary

`WinnablesTicket` stores `nft` ownership by setting the first minted nft id ownership to the user minting and all the next minted nfts remain as `0`. This means it always costs the same to mint, but the `ownerOf()` function becomes much more expensive, to the point where it may cause OOG errors. In this case, the user is able to buy tickets via [WinnablesTicketManager::buyTickets()](https://github.com/sherlock-audit/2024-08-winnables-raffles/blob/main/public-contracts/contracts/WinnablesTicketManager.sol#L182), the draw is made in [WinnablesTicketManager::drawWinner()](https://github.com/sherlock-audit/2024-08-winnables-raffles/blob/main/public-contracts/contracts/WinnablesTicketManager.sol#L310) and the chainlink request is fulfilled with the winner in [WinnablesTicketManager::fulfillRandomWords()](https://github.com/sherlock-audit/2024-08-winnables-raffles/blob/main/public-contracts/contracts/WinnablesTicketManager.sol#L350). However, in [WinnablesTicketManager::propagateWinner()](https://github.com/sherlock-audit/2024-08-winnables-raffles/blob/main/public-contracts/contracts/WinnablesTicketManager.sol#L334), it reverts due to OOG when calling [WinnablesTicket::ownerOf()](https://github.com/sherlock-audit/2024-08-winnables-raffles/blob/main/public-contracts/contracts/WinnablesTicket.sol#L97-L99).



*[Content truncated...]*

---

### Example 14: M-8: Settlement of batch auction can exceed the gas limit

**Source**: Sherlock
**Protocol**: Axis Finance
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-03-axis-finance-judging/issues/237 

## Found by 
0xR360, Kose, MrjoryStewartBaxter, flacko, shaka
## Summary

Settlement of batch auction can exceed the gas limit, making it impossible to settle the auction.

## Vulnerability Detail

When a batch auction (EMPAM) is settled, to calculate the lot marginal price, the contract [iterates over all bids](https://github.com/sherlock-audit/2024-03-axis-finance/blob/main/moonraker/src/modules/auctions/EMPAM.sol#L611-L651) until the capacity is reached or a bid below the minimum price is found. 

As some of the operations performed in the loop are gas-intensive, the contract may run out of gas if the number of bids is too high.

Note that additionally, there is [another loop](https://github.com/sherlock-audit/2024-03-axis-finance/blob/main/moonraker/src/modules/auctions/EMPAM.sol#L772-L781) in the `_settle` function that iterates over all the remaining bids to delete them from the queue. While this loop consumes much less gas per iteration and would require the number of bids to be much higher to run out of gas, it adds to the problem.

## Impact

Settlement of batch auction will revert, causing sellers and bidders to lose their funds.

## Code Snippet

https://github.com/sherlock-audit/2024-03-axis-finance/blob/main/moonraker/src/modules/auctions/EMPAM.sol#L611-L651

## Proof of concept

Change the minimum bid percent to 0.1% in the `EmpaModuleTest` contract in `EMPAModuleTest.sol`.

```d

*[Content truncated...]*

---

### Example 15: Low/high MaxGas values could make match/unmatch supplier/borrower functions always fail or revert

**Source**: Spearbit
**Protocol**: Morpho
**Impact**: MEDIUM

**Details**:

## Vulnerability Report

## Severity
**Medium Risk**

## Context
- PositionsManagerForAaveGettersSetters.sol#L47-L50
- PositionsManagerForAaveLogic.sol#L34

## Description
The `maxGas` variable is used to determine how much gas the `matchSuppliers`, `unmatchSuppliers`, `matchBorrowers`, and `unmatchBorrowers` functions can consume while trying to match/unmatch suppliers/borrowers and also updating their position if matched.

- `maxGas = 0` will make the process skip the loop entirely.
- A low `maxGas` will make the loop run at least one time, but the smaller the `maxGas`, the higher the possibility that not all available suppliers/borrowers are matched/unmatched.
- A very high `maxGas` could cause the loop to consume all the block gas, leading to a transaction revert.

*Note:* `maxGas` can be overridden by the user when calling the `supply` or `borrow` functions.

## Recommendation
Conduct thorough testing to determine a safe minimum and maximum value for `maxGas`.

## Morpho
These parameters will be decided by governance in the future. We will implement a time-lock of seven days to ensure everyone can review the relevance of these parameters. Additionally, the governance has no incentives to implement incorrect parameters that could harm Morpho and its users.

## Spearbit
Acknowledged.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Morpho-Spearbit-Security-Review.pdf)

---

### Example 16: A malicious user can grief a `StakePet` contract by creating massive number of pets

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

### Example 17: [L-04] Frontrunnable Initialization

**Source**: Pashov Audit Group
**Protocol**: Enclave_2025-10-25
**Impact**: LOW

**Details**:

_Acknowledged_

The `initialize` instruction creates the global `fund_pool` PDA (`seed = b"fund_pool"`) and sets `initial_admin` to an arbitrary public key supplied by the caller. There is no access control restricting who may invoke this first-use initializer. An attacker can front-run deployment, initialize the pool, and seize control over all admin- and signer-gated operations for the lifetime of the program (until redeploy).

**Recommendations**

Implement a robust access control mechanism that ensures only a trusted entity, such as the program's deployer or a predefined address, can call the `initialize` function. This restriction can be enforced by verifying the caller's identity or using a specific signature during initialization.

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/Enclave-security-review_2025-10-25.md)

---

### Example 18: M-1: Determining how many votes to buy may run OOG.

**Source**: Sherlock
**Protocol**: Ethos Reputation Market Fix Review Contest
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-12-ethos-update-judging/issues/43 

## Found by 
bughuntoor

### Summary
The current way buying votes works is that a user sends a certain `msg.value` and a minimum and maximum amount they wish to buy, and the contract loops through the values to find the maximum amount the user can actually buy.

```solidity
    (, , , uint256 total) = _calculateBuy(markets[profileId], isPositive, minVotesToBuy);
    if (total > msg.value) revert InsufficientFunds();

    (
      uint256 purchaseCostBeforeFees,
      uint256 protocolFee,
      uint256 donation,
      uint256 totalCostIncludingFees
    ) = _calculateBuy(markets[profileId], isPositive, maxVotesToBuy);
    uint256 currentVotesToBuy = maxVotesToBuy;
    // if the cost is greater than the maximum votes to buy,
    // decrement vote count and recalculate until we identify the max number of votes they can afford
    while (totalCostIncludingFees > msg.value) {
      currentVotesToBuy--;
      (purchaseCostBeforeFees, protocolFee, donation, totalCostIncludingFees) = _calculateBuy(
        markets[profileId],
        isPositive,
        currentVotesToBuy
      );
    }
```

The problem is that this way is highly gas inefficient. And even though protocol is to be deployed on Base where gas costs are low, it would still be possible to reach significant gas costs.

Looping to check a certain buy's gas costs, costs around ~33k gas (PoC attached below). Considering

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 18
- Examples shown: 18
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## gas-price-patterns.md
# Gas Price Security Patterns

## Overview

**Frequency**: 5 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 3 | 2 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock

---

## Detection Checklist

- [ ] Check for gas price vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-06] Gas price spikes cause the selected operator to be vulnerable to frontrunning and be slashed

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: HIGH

**Details**:

[HolographOperator.sol#L354](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/HolographOperator.sol#L354)<br>

```solidity
require(gasPrice >= tx.gasprice, "HOLOGRAPH: gas spike detected");
```

```solidity
        /**
         * @dev select operator that failed to do the job, is slashed the pod base fee
         */
        _bondedAmounts[job.operator] -= amount;
        /**
         * @dev the slashed amount is sent to current operator
         */
        _bondedAmounts[msg.sender] += amount;
```

Since you have designed a mechanism to prevent other operators to slash the operator due to "the selected missed the time slot due to a gas spike". It can induce that operators won't perform their job if a gas price spike happens due to negative profit.

But your designed mechanism has a vulnerability. Other operators can submit their transaction to the mempool and queue it using `gasPrice in bridgeInRequestPayload`. It may get executed before the selected operator as the selected operator is waiting for the gas price to drop but doesn't submit any transaction yet. If it doesn't, these operators lose a little gas fee. But a slashed reward may be greater than the risk of losing a little gas fee.

```solidity
require(timeDifference > 0, "HOLOGRAPH: operator has time");
```

Once 1 epoch has passed, selected operator is vulnerable to slashing and frontrunning.

### Recommended Mitigation Steps

Modify your operator node software t

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 2: [H-05] MEV: Operator can bribe miner and steal honest operator's bond amount if gas price went high

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: HIGH

**Details**:

[HolographOperator.sol#L354](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/HolographOperator.sol#L354)<br>

Operators in Holograph do their job by calling executeJob() with the bridged in bytes from source chain.<br>
If the primary job operator did not execute the job during his allocated block slot, he is punished by taking a single bond amount and transfer it to the operator doing it instead.<br>
The docs and code state that if there was a gas spike in the operator's slot, he shall not be punished. The way a gas spike is checked is with this code in executeJob:

    require(gasPrice >= tx.gasprice, "HOLOGRAPH: gas spike detected");

However, there is still a way for operator to claim primary operator's bond amount although gas price is high. Attacker can submit a flashbots bundle including the executeJob() transaction, and one additional "bribe" transaction. The bribe transaction will transfer some incentive amount to coinbase address (miner), while the executeJob is submitted with a low gasprice. Miner will accept this bundle as it is overall rewarding enough for them, and attacker will receive the base bond amount from victim operator. This threat is not theoretical because every block we see MEV bots squeezing value from such opportunities.

info about coinbase [transfer](https://docs.flashbots.net/flashbots-auction/searchers/advanced/coinbase-payment)<br>
info about bundle [selection](https://docs.flashbots.net/f

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 3: [H-02] If user sets a low `gasPrice` the operator would have to choose between being locked out of the pod or executing the job anyway

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: HIGH

**Details**:

[HolographOperator.sol#L202-L340](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/src/HolographOperator.sol#L202-L340)<br>
[HolographOperator.sol#L593-L596](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/HolographOperator.sol#L593-L596)<br>
[LayerZeroModule.sol#L277-L294](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/module/LayerZeroModule.sol#L277-L294)<br>

During the beaming process the user compensates the operator for the gas he has to pay by sending some source-chain-native-tokens via `hToken`.<br>
The amount he has to pay is determined according to the `gasPrice` set by the user, which is supposed to be the maximum gas price to be used on dest chain (therefore predicting the max gas fee the operator would pay and paying him the same value in src chain native tokens).<br>
However, in case the user sets a low price (as low as 1 wei) the operator can't skip the job because he's locked out of the pod till he executes the job.<br>
The operator would have to choose between loosing money by paying a higher gas fee than he's compensated for or being locked out of the pod - not able to execute additional jobs or get back his bonded amount.<br>

### Impact

Operator would be losing money by having to pay gas fee that's higher than the compensation (gas fee can be a few dozens of USD for heavy txs).<br>
This could also be

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 4: [M-03] Beaming job might freeze on dest chain under some conditions, leading to owner losing (temporarily) access to token

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: MEDIUM

**Details**:

[HolographOperator.sol#L255](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/src/HolographOperator.sol#L255)<br>

If the following conditions have been met:

*   The selected operator doesn't complete the job, either intentionally (they're sacrificing their bonded amount to harm the token owner) or innocently (hardware failure that caused a loss of access to the wallet)
*   Gas price has spiked, and isn't going down than the `gasPrice` set by the user in the bridge out request

Then the bridging request wouldn't complete and the token owner would loos access to the token till the gas price goes back down again.

### Proof of Concept

The fact that no one but the selected operator can execute the job in case of a gas spike has been proven by the test ['Should fail if there has been a gas spike'](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/test/14\_holograph_operator_tests.ts#L834-L844) provided by the sponsor.

An example of a price spike can be in the recent month in the Ethereum Mainnet where the min gas price was 3 at Oct 8, but jumped to 14 the day after and didn't go down since then (the min on Oct 9 was lower than the avg of Oct8, but users might witness a momentarily low gas price and try to hope on it). See the [gas price chat on Etherscan](https://etherscan.io/chart/gasprice) for more details.

### Recommended Mitigation Steps

In case of a gas price spike, instead of refus

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 5: M-1: Determining how many votes to buy may run OOG.

**Source**: Sherlock
**Protocol**: Ethos Reputation Market Fix Review Contest
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-12-ethos-update-judging/issues/43 

## Found by 
bughuntoor

### Summary
The current way buying votes works is that a user sends a certain `msg.value` and a minimum and maximum amount they wish to buy, and the contract loops through the values to find the maximum amount the user can actually buy.

```solidity
    (, , , uint256 total) = _calculateBuy(markets[profileId], isPositive, minVotesToBuy);
    if (total > msg.value) revert InsufficientFunds();

    (
      uint256 purchaseCostBeforeFees,
      uint256 protocolFee,
      uint256 donation,
      uint256 totalCostIncludingFees
    ) = _calculateBuy(markets[profileId], isPositive, maxVotesToBuy);
    uint256 currentVotesToBuy = maxVotesToBuy;
    // if the cost is greater than the maximum votes to buy,
    // decrement vote count and recalculate until we identify the max number of votes they can afford
    while (totalCostIncludingFees > msg.value) {
      currentVotesToBuy--;
      (purchaseCostBeforeFees, protocolFee, donation, totalCostIncludingFees) = _calculateBuy(
        markets[profileId],
        isPositive,
        currentVotesToBuy
      );
    }
```

The problem is that this way is highly gas inefficient. And even though protocol is to be deployed on Base where gas costs are low, it would still be possible to reach significant gas costs.

Looping to check a certain buy's gas costs, costs around ~33k gas (PoC attached below). Considering

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 5
- Examples shown: 5
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## broken-loop-patterns.md
# Broken Loop Security Patterns

## Overview

**Frequency**: 7 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 4 | 3 | 0 | 0 |

**Common Sources**: Code4rena, Spearbit, Sherlock

---

## Detection Checklist

- [ ] Check for broken loop vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: _removeStackPosition() always reverts

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Security Report

## Severity
**High Risk**

## Context
`LienToken.sol#L823-L828`

## Description
The function `removeStackPosition()` always reverts since it calls the stack array for an index beyond its length:

```solidity
for (i; i < length; ) {
unchecked {
newStack[i] = stack[i + 1];
++i;
}
}
```

Notice that for `i == length - 1`, `stack[length]` is called. This reverts since length is the length of the stack array.

Additionally, the intention is to delete the element from the stack at `indexPosition` and shift left the elements appearing after this index. However, an additional increment to the loop index `i` results in `newStack[position]` being empty, and the shift of other elements doesn't happen.

## Recommendation
Apply the following diff to `LienToken.sol#L823-L831`:

```diff
- unchecked {
- ++i;
- }
- for (i; i < length; ) {
+ for (i; i < length - 1; ) {
unchecked {
newStack[i] = stack[i + 1];
++i;
}
}
```

## Note
This issue has to be considered in conjunction with the following issue:
- `makePayment` doesn't properly update stack, so most payments don't pay off debt.

### Astaria
Fixed in PRs 202 and 265.

### Spearbit
Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 2: [H-04] Unbounded loop in _removeNft could lead to a griefing/DOS attack

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

### Example 3: Large number of inbound roots can DOS the RootManager

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
RootManager.sol#L154-L163

## Description
It is possible to perform a DOS against the RootManager by exploiting the `dequeueVerified` function or `insert` function of the RootManager.sol. The following describes the possible attack path:

1. Assume that a malicious user calls the permissionless `GnosisSpokeConnector.send` function 1000 times (or any number of times that will cause an Out-of-Gas error later) within a single transaction/block on Gnosis, causing a large number of Gnosis's outboundRoots to be forwarded to `GnosisHubConnector` on Ethereum.
2. Since the 1000 outboundRoots were sent at the same transaction/block earlier, all of them should arrive at the `GnosisHubConnector` within the same block/transaction on Ethereum.
3. For each of the 1000 outboundRoots received, the `GnosisHubConnector.processMessage` function will be triggered to process it, which will in turn call the `RootManager.aggregate` function to add the received outboundRoot into the pendingInboundRoots queue. As a result, 1000 outboundRoots with the same commit block will be added to the pendingInboundRoots queue.
4. After the delay period, the `RootManager.propagate` function will be triggered. The function will call the `dequeueVerified` function to dequeue 1000 verified outboundRoots from the pendingInboundRoots queue by looping through the queue. This might result in an Out-of-Gas error and cause a revert.
5. If the above `dequeueVerified` function does not reve

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 4: [H-03] Denial of Service by wrong `BatchRequests.removeAddress` logic

**Source**: Code4rena
**Protocol**: Yieldy
**Impact**: HIGH

**Details**:

_Submitted by 0x1f8b, also found by rfa, berndartmueller, BowTiedWardens, csanuragjain, Lambda, neumo, and StErMi_

**Note: issues #[283](https://github.com/code-423n4/2022-06-yieldy-findings/issues/283), [115](https://github.com/code-423n4/2022-06-yieldy-findings/issues/115), [82](https://github.com/code-423n4/2022-06-yieldy-findings/issues/82), [89](https://github.com/code-423n4/2022-06-yieldy-findings/issues/89), [61](https://github.com/code-423n4/2022-06-yieldy-findings/issues/61), and [241](https://github.com/code-423n4/2022-06-yieldy-findings/issues/241) were originally broken out as a separate medium issue. Approximately 1 week after judging and awarding were finalized, the judging team re-assessed that these should have all been grouped under H-03. Accordingly, the 6 warden names have been added as submitters above.**

<https://github.com/code-423n4/2022-06-yieldy/blob/34774d3f5e9275978621fd20af4fe466d195a88b/src/contracts/BatchRequests.sol#L93>

<https://github.com/code-423n4/2022-06-yieldy/blob/34774d3f5e9275978621fd20af4fe466d195a88b/src/contracts/BatchRequests.sol#L57>

<https://github.com/code-423n4/2022-06-yieldy/blob/34774d3f5e9275978621fd20af4fe466d195a88b/src/contracts/BatchRequests.sol#L37>

### Impact

The `BatchRequests.removeAddress` logic is wrong and it will produce a denial of service.

### Proof of Concept

Removing the element from the array is done using the `delete` statement, but this is not the proper way to remove an entry from an array, it will

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-yieldy)

---

### Example 5: M-10: `BondAggregator.findMarketFor` Function Will Break In Certain Conditions

**Source**: Sherlock
**Protocol**: Bond Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-bond-judging/issues/14 

## Found by 
xiaoming90

## Summary

`BondAggregator.findMarketFor` function will break when the `BondBaseSDA.payoutFor` function within the for-loop reverts under certain conditions.

## Vulnerability Detail

The `BondBaseSDA.payoutFor` function will revert if the computed payout is larger than the market's max payout. Refer to Line 711 below.

https://github.com/sherlock-audit/2022-11-bond/blob/main/src/bases/BondBaseSDA.sol#L699

```solidity
File: BondBaseSDA.sol
699:     function payoutFor(
700:         uint256 amount_,
701:         uint256 id_,
702:         address referrer_
703:     ) public view override returns (uint256) {
704:         // Calculate the payout for the given amount of tokens
705:         uint256 fee = amount_.mulDiv(_teller.getFee(referrer_), 1e5);
706:         uint256 payout = (amount_ - fee).mulDiv(markets[id_].scale, marketPrice(id_));
707: 
708:         // Check that the payout is less than or equal to the maximum payout,
709:         // Revert if not, otherwise return the payout
710:         if (payout > markets[id_].maxPayout) {
711:             revert Auctioneer_MaxPayoutExceeded();
712:         } else {
713:             return payout;
714:         }
715:     }
```

The `BondAggregator.findMarketFor` function will call the `BondBaseSDA.payoutFor` function at Line 245. The `BondBaseSDA.payoutFor` function will revert if the final computed payout is larger than the `markets[

*[Content truncated...]*

---

### Example 6: [M-04] Iterations over all tiers in recordMintBestAvailableTier can render system unusable

**Source**: Code4rena
**Protocol**: Juicebox
**Impact**: MEDIUM

**Details**:

`JBTiered721DelegateStore.recordMintBestAvailableTier` potentially iterates over all tiers to find the one with the highest contribution floor that is lower than `_amount`. When there are many tiers, this loop can always run out of gas, which will cause some transactions (the ones that have a high `_leftoverAmount` within `_processPayment`) to always revert. The (implicit) limit for the number of tiers is 2^16 - 1, so it is possible that this happens in practice.

### Proof Of Concept

Let's say that 1,000 tiers are registered for a project. Small payments without a leftover amount or a small amount will be succesfully processed by `_processPayment`, because `_mintBestAvailableTier` is either not called or it is called with a small amount, meaning that `recordMintBestAvailableTier` will exit the loop early (when it is called with a small amount). However, if a payment with a large leftover amount (let's say greater than the highest contribution floor) is processed, it is necessary to iterate over all tiers, which will use too much gas and cause the processing to revert.

### Recommended Mitigation Steps

Use a binary search (which requires some architectural changes) for determining the best available tier. Then, the gas usage grows logarithmically (instead of linear with the current design) with the number of tiers, meaning that it would only be \~16 times higher for 65535 tiers as for 2 tiers.


**[drgorillamd (Juicebox DAO) commented on duplicate issue #226](https://github

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-juicebox)

---

### Example 7: [M-07] processFees() may fail due to exceed gas limit

**Source**: Code4rena
**Protocol**: Juicebox
**Impact**: MEDIUM

**Details**:

_Submitted by oyc&#95;109, also found by 0x52, IllIllI, and pashov_

<https://github.com/jbx-protocol/juice-contracts-v2-code4rena/blob/828bf2f3e719873daa08081cfa0d0a6deaa5ace5/contracts/abstract/JBPayoutRedemptionPaymentTerminal.sol#L594>

### Impact

The function `processFees()` in `JBPayoutRedemptionPaymentTerminal.sol` may fail due to unbounded loop over `_heldFeesOf[_projectId]`

`_heldFeesOf[_projectId]` can get very large due to the function `_takeFeeFrom()` where it pushes fees that should be paid to a specific beneficiary onto the array

<https://github.com/jbx-protocol/juice-contracts-v2-code4rena/blob/828bf2f3e719873daa08081cfa0d0a6deaa5ace5/contracts/abstract/JBPayoutRedemptionPaymentTerminal.sol#L1199>

`_heldFeesOf[_projectId]` could get large and cause a DOS condition where no fees can be distributed due to exceed of gas limit

### Proof of Concept

        for (uint256 _i = 0; _i < _heldFeeLength; ) {
          // Get the fee amount.
          uint256 _amount = _feeAmount(
            _heldFees[_i].amount,
            _heldFees[_i].fee,
            _heldFees[_i].feeDiscount
          );

**[mejango (Juicebox) acknowledged](https://github.com/code-423n4/2022-07-juicebox-findings/issues/8)** 


***

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-juicebox)

---

## Statistics

- Total findings analyzed: 7
- Examples shown: 7
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## array-patterns.md
# Array Security Patterns

## Overview

**Frequency**: 6 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 3 | 3 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock

---

## Detection Checklist

- [ ] Check for array vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-01] User can steal tokens by using duplicated ERC20 tokens as parameter in `NounsDAOLogicV1Fork.quit`

**Source**: Code4rena
**Protocol**: Nouns DAO
**Impact**: HIGH

**Details**:

Calling [NounsDAOLogicV1Fork.quit](https://github.com/nounsDAO/nouns-monorepo/blob/718211e063d511eeda1084710f6a682955e80dcb/packages/nouns-contracts/contracts/governance/fork/newdao/governance/NounsDAOLogicV1Fork.sol#L206-L216) by using dupliated ERC20 tokens, malicious user can gain more ERC20 tokens than he/she is supposed to, even drain all ERC20 tokens.

### Proof of Concept

In function, [NounsDAOLogicV1Fork.quit](https://github.com/nounsDAO/nouns-monorepo/blob/718211e063d511eeda1084710f6a682955e80dcb/packages/nouns-contracts/contracts/governance/fork/newdao/governance/NounsDAOLogicV1Fork.sol#L206-L216), `erc20TokensToInclude` is used to specified tokens a user wants to get, but since the function doesn't verify if `erc20TokensToInclude` contains dupliated tokens, it's possible that a malicious user calls the function by specify the ERC20 more than once to get more share tokens.

```solidity
    function quit(uint256[] calldata tokenIds, address[] memory erc20TokensToInclude) external nonReentrant {
        // check that erc20TokensToInclude is a subset of `erc20TokensToIncludeInQuit`
        address[] memory erc20TokensToIncludeInQuit_ = erc20TokensToIncludeInQuit;
        for (uint256 i = 0; i < erc20TokensToInclude.length; i++) {
            if (!isAddressIn(erc20TokensToInclude[i], erc20TokensToIncludeInQuit_)) {
                revert TokensMustBeASubsetOfWhitelistedTokens();
            }
        }

        quitInternal(tokenIds, erc20TokensToInclude);
    }

    f

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-07-nounsdao)

---

### Example 2: H-4: Wrong implementation of orderbook can make user can't get their fund back

**Source**: Sherlock
**Protocol**: Knox Finance
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-09-knox-judging/issues/66 

## Found by 
Trumpero

## Lines of code 
https://github.com/sherlock-audit/2022-09-knox/blob/main/knox-contracts/contracts/auction/OrderBook.sol#L240
https://github.com/sherlock-audit/2022-09-knox/blob/main/knox-contracts/contracts/auction/OrderBook.sol#L182-L190

## Summary
When a user remove an order, next user call `addLimitOrder` can override the latest order with his/her order. It will make one who is owner of that latest order lose their fund. 

## Vulnerability Detail
Function `_remove` will decrease value of `index.length` by 1 when an order is removed
```solidity=
// url = https://github.com/sherlock-audit/2022-09-knox/blob/main/knox-contracts/contracts/auction/OrderBook.sol#L240
function _remove(Index storage index, uint256 id) internal returns (bool) {
    index.length = index.length > 0 ? index.length - 1 : 1;
    ...
}
```
Instead of reserving `id` of removed order to reuse for next created order, function `_insert` use the id of new order is `index.length + 1`
```solidity=
// url = https://github.com/sherlock-audit/2022-09-knox/blob/main/knox-contracts/contracts/auction/OrderBook.sol#L165-L172
function _insert(
    Index storage index,
    int128 price64x64,
    uint256 size,
    address buyer
) internal returns (uint256) {
    index.length = index.length > 0 ? index.length + 1 : 1;
    uint256 id = index.length;
    ...
}
```
It will override the latest order with new order's data.

For 

*[Content truncated...]*

---

### Example 3: H-12: Pending CRV rewards are not accounted for and can cause unfair liquidations

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/136 

## Found by 
0x52
## Summary

pendingRewards are factored into the health of a position so that the position collateral is fairly assessed. However WCurveGauge#pendingRewards doesn't return the proper reward tokens/amounts meaning that positions aren't valued correctly and users can be unfairly liquidated.

## Vulnerability Detail

[BlueBerryBank.sol#L408-L413](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/BlueBerryBank.sol#L408-L413)

            (address[] memory tokens, uint256[] memory rewards) = IERC20Wrapper(
                pos.collToken
            ).pendingRewards(pos.collId, pos.collateralSize);
            for (uint256 i; i < tokens.length; i++) {
                rewardsValue += oracle.getTokenValue(tokens[i], rewards[i]);
            }

When BlueBerryBank is valuing a position it also values the pending rewards since they also have value. 

[WCurveGauge.sol#L106-L114](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/wrapper/WCurveGauge.sol#L106-L114)

    function pendingRewards(
        uint256 tokenId,
        uint256 amount
    )
        public
        view
        override
        returns (address[] memory tokens, uint256[] memory rewards)
    {}

Above we see that WCurveGauge#pendingRewards returns empty arrays when called. This means that pending rewards are not factored in correctly and users can be 

*[Content truncated...]*

---

### Example 4: M-9: Bad debt may persist even after complete liquidation in Velo Vault due to truncation

**Source**: Sherlock
**Protocol**: Isomorph
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-isomorph-judging/issues/174 

## Found by 
0x52

## Summary

When liquidating a user, if all their collateral is taken but it is not valuable enough to repay the entire loan they would be left with remaining debt. This is what is known as bad debt because there is no collateral left to take and the user has no obligation to pay it back. When this occurs, the vault will forgive the user's debts, clearing the bad debt. The problem is that the valuations are calculated in two different ways which can lead to truncation issue that completely liquidates a user but doesn't clear their bad debt.

## Vulnerability Detail

            uint256 totalUserCollateral = totalCollateralValue(_collateralAddress, _loanHolder);
            uint256 proposedLiquidationAmount;
            { //scope block for liquidationAmount due to stack too deep
                uint256 liquidationAmount = viewLiquidatableAmount(totalUserCollateral, 1 ether, isoUSDBorrowed, liquidatableMargin);
                require(liquidationAmount > 0 , "Loan not liquidatable");
                proposedLiquidationAmount = _calculateProposedReturnedCapital(_collateralAddress, _loanNFTs, _partialPercentage);
                require(proposedLiquidationAmount <= liquidationAmount, "excessive liquidation suggested");
            }
            uint256 isoUSDreturning = proposedLiquidationAmount*LIQUIDATION_RETURN/LOAN_SCALE;
            if(proposedLiquidationAmount >= totalUserColl

*[Content truncated...]*

---

### Example 5: [M-07] User may get less tokens than expected when collateral list order changes

**Source**: Code4rena
**Protocol**: Angle Protocol
**Impact**: MEDIUM

**Details**:

<https://github.com/AngleProtocol/angle-transmuter/blob/8a2c3aaf4bd054581b06d33049370a6f01b56d44/contracts/transmuter/libraries/LibSetters.sol#L123> <br><https://github.com/AngleProtocol/angle-transmuter/blob/8a2c3aaf4bd054581b06d33049370a6f01b56d44/contracts/transmuter/facets/Redeemer.sol#L64>

The order of `ts.collateralList` is not stable: Whenever `LibSetters.revokeCollateral` is used to revoke a collateral, it may change because of the swap that is performed. However, the function `Redeemer.redeem` relies on this order, as the user has to provide the `minAmountsOut` in the order of `ts.collateralList`. This can lead to situations where the user has crafted the `minAmountsOut` array when the order was still different, leading to unintended results (and potentially redemptions that the user did not want to accept). It also means that revoking a collateral can be challenging for the team / governance because it should never be done when a user has already prepared a redemption (either via the frontend which he had open or some other way to interact with the contract). But there is of course no way to know this.

### Proof of Concept

Let's say the system contains the collateral \[tokenA, tokenB, tokenC]. `normalizedStables` for tokenA is 0. The user therefore does not want to receive tokenA (and will not receive anything for it). However, it is extremely important to him that he receives 100,000 of tokenC. He therefore crafts a `minAmountsOut` of \[0, 10000, 100000]. Just b

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-dev-test-repo)

---

## Statistics

- Total findings analyzed: 6
- Examples shown: 5
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## array-reorder-patterns.md
# Array Reorder Security Patterns

## Overview

**Frequency**: 4 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 3 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock

---

## Detection Checklist

- [ ] Check for array reorder vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: H-4: Wrong implementation of orderbook can make user can't get their fund back

**Source**: Sherlock
**Protocol**: Knox Finance
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-09-knox-judging/issues/66 

## Found by 
Trumpero

## Lines of code 
https://github.com/sherlock-audit/2022-09-knox/blob/main/knox-contracts/contracts/auction/OrderBook.sol#L240
https://github.com/sherlock-audit/2022-09-knox/blob/main/knox-contracts/contracts/auction/OrderBook.sol#L182-L190

## Summary
When a user remove an order, next user call `addLimitOrder` can override the latest order with his/her order. It will make one who is owner of that latest order lose their fund. 

## Vulnerability Detail
Function `_remove` will decrease value of `index.length` by 1 when an order is removed
```solidity=
// url = https://github.com/sherlock-audit/2022-09-knox/blob/main/knox-contracts/contracts/auction/OrderBook.sol#L240
function _remove(Index storage index, uint256 id) internal returns (bool) {
    index.length = index.length > 0 ? index.length - 1 : 1;
    ...
}
```
Instead of reserving `id` of removed order to reuse for next created order, function `_insert` use the id of new order is `index.length + 1`
```solidity=
// url = https://github.com/sherlock-audit/2022-09-knox/blob/main/knox-contracts/contracts/auction/OrderBook.sol#L165-L172
function _insert(
    Index storage index,
    int128 price64x64,
    uint256 size,
    address buyer
) internal returns (uint256) {
    index.length = index.length > 0 ? index.length + 1 : 1;
    uint256 id = index.length;
    ...
}
```
It will override the latest order with new order's data.

For 

*[Content truncated...]*

---

### Example 2: M-1: `claimFromIndividualPlugin()` may endup claiming the reward from a different plugin with wrong `auxData` when the index as changed due to `removePlugin()`

**Source**: Sherlock
**Protocol**: Telcoin
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-telcoin-judging/issues/86 

## Found by 
WATCHPUG

## Summary

When `removePlugin()` happens between the user sends the `claimFromIndividualPlugin()` transaction and before it gets minted, it may lead to lesser rewards as the `auxData` prepared for another plugin will now be used.

## Vulnerability Detail

When a user calls `claimFromIndividualPlugin()`, a `pluginIndex` is used to refer to a plugin.

However, if the `PLUGIN_EDITOR` removed a plugin before the transaction gets minted, the plugin referred by the `pluginIndex` can be changed to another plugin.

As a result, the `auxData` supposed to be supplied to the original plugin is now supplied to another plugin.

## Impact

The user may end up with lesser rewards as a wrong `auxData` is supplied to the wrong plugin.

## Code Snippet

https://github.com/sherlock-audit/2022-11-telcoin/blob/main/contracts/StakingModule.sol#L420-L429

https://github.com/sherlock-audit/2022-11-telcoin/blob/main/contracts/StakingModule.sol#L178-L185

## Tool used

Manual Review

## Recommendation

Consider using `pluginAddress` instead.

## Discussion

**amshirif**

https://github.com/telcoin/telcoin-staking/pull/8

---

### Example 3: [M-07] User may get less tokens than expected when collateral list order changes

**Source**: Code4rena
**Protocol**: Angle Protocol
**Impact**: MEDIUM

**Details**:

<https://github.com/AngleProtocol/angle-transmuter/blob/8a2c3aaf4bd054581b06d33049370a6f01b56d44/contracts/transmuter/libraries/LibSetters.sol#L123> <br><https://github.com/AngleProtocol/angle-transmuter/blob/8a2c3aaf4bd054581b06d33049370a6f01b56d44/contracts/transmuter/facets/Redeemer.sol#L64>

The order of `ts.collateralList` is not stable: Whenever `LibSetters.revokeCollateral` is used to revoke a collateral, it may change because of the swap that is performed. However, the function `Redeemer.redeem` relies on this order, as the user has to provide the `minAmountsOut` in the order of `ts.collateralList`. This can lead to situations where the user has crafted the `minAmountsOut` array when the order was still different, leading to unintended results (and potentially redemptions that the user did not want to accept). It also means that revoking a collateral can be challenging for the team / governance because it should never be done when a user has already prepared a redemption (either via the frontend which he had open or some other way to interact with the contract). But there is of course no way to know this.

### Proof of Concept

Let's say the system contains the collateral \[tokenA, tokenB, tokenC]. `normalizedStables` for tokenA is 0. The user therefore does not want to receive tokenA (and will not receive anything for it). However, it is extremely important to him that he receives 100,000 of tokenC. He therefore crafts a `minAmountsOut` of \[0, 10000, 100000]. Just b

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-dev-test-repo)

---

## Statistics

- Total findings analyzed: 4
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## dust-patterns.md
# Dust Security Patterns

## Overview

**Frequency**: 5 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 5 | 0 | 0 |

**Common Sources**: Sherlock, Code4rena, Spearbit

---

## Detection Checklist

- [ ] Check for dust vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Dust might be trapped in WlsETH when burning one's balance.

**Source**: Spearbit
**Protocol**: Liquid Collective
**Impact**: MEDIUM

**Details**:

## Security Analysis Report

## Severity
**Medium Risk**

## Context
*WLSETH.1.sol#L140*

## Description
It is not possible to burn the exact amount of minted/deposited lsETH back because the _value provided to burn is in ETH. 

Assume we've called `mint(r,v)` with our address `r`, then to get the `v` lsETH back to our address, we need to find an `x` where:

\[ v = \frac{b \cdot x \cdot S}{B} \]

and call `burn(r, x)` (Here `S` represents the total share of lsETH and `B` the total underlying value.). 

It's not always possible to find the exact `x`, so there will always be an amount locked in this contract:

\[ v \neq \frac{b \cdot x \cdot S}{B} \]

These dust amounts can accumulate from different users and turn into a significant number. To get the full amount back, the user needs to mint more wlsETH tokens so that we can find an exact solution to:

\[ v = \frac{b \cdot x \cdot S}{B} \]

The extra amount to get the locked-up fees back can be engineered. The same problem exists for `transfer` and `transferFrom`. 

Also note, if you have minted `x` amount of shares, the `balanceOf` would tell you that you own:

\[ b = \frac{b \cdot x \cdot B}{S \cdot wlsETH} \]

Internally, wlsETH keeps track of the shares `x`. So users think they can only burn `b` amount, plug that in for the _value, and in this case, the number of shares burnt would be:

\[
\frac{b \cdot x \cdot B}{S \cdot C \cdot B\%}
\]

which has even more rounding errors. wlsETH could internally track the underlying but 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LiquidCollective-Spearbit-Security-Review.pdf)

---

### Example 2: [M-18] DoS: Attacker may significantly increase the cost of withdrawExcessRewards() by creating a significant number of excess receipts

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

### Example 3: M-4: Dust amounts can cause payments to fail, leading to default

**Source**: Sherlock
**Protocol**: Cooler
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-cooler-judging/issues/218 

## Found by 
kiki\_dev, HollaDieWaldfee, IllIllI, ak1

## Summary

Dust amounts can cause payments to fail, leading to default


## Vulnerability Detail

In order for a loan to close, the exact right number of wei of the debt token must be sent to match the remaining loan amount. If more is sent, the balance underflows, reverting the transaction.


## Impact

An attacker can send dust amounts right before a loan is due, front-running any payments also destined for the final block before default. If the attacker's transaction goes in first, the borrower will be unable to pay back the loan before default, and will lose thier remaining collateral. This may be the whole loan amount.


## Code Snippet

If the repayment amount isn't exactly the remaining loan amount, and instead is more (due to the dust payment), the subtraction marked below will underflow, reverting the payment:
```solidity
// File: src/Cooler.sol : Cooler.repay()   #1

108        function repay (uint256 loanID, uint256 repaid) external {
109            Loan storage loan = loans[loanID];
110    
111            if (block.timestamp > loan.expiry) 
112                revert Default();
113            
114            uint256 decollateralized = loan.collateral * repaid / loan.amount;
115    
116           if (repaid == loan.amount) delete loans[loanID];
117           else {
118 @>             loan.amount -= repaid;
119                loan.coll

*[Content truncated...]*

---

### Example 4: [M-08] Rebases can be frontrun with very little token downtime even when warmUpPeriod  0

**Source**: Code4rena
**Protocol**: Yieldy
**Impact**: MEDIUM

**Details**:

_Submitted by 0x52, also found by elprofesor_

Rebases can be frontrun with very little token downtime even when `warmUpPeriod > 0`.

### Proof of Concept

<https://github.com/code-423n4/2022-06-yieldy/blob/524f3b83522125fb7d4677fa7a7e5ba5a2c0fe67/src/contracts/Staking.sol#L415-L417>

<https://github.com/code-423n4/2022-06-yieldy/blob/524f3b83522125fb7d4677fa7a7e5ba5a2c0fe67/src/contracts/Staking.sol#L703>

A user can call stake the block before epoch.endTime <= block.timestamp, allowing the user to bypass the forced rebase called in L416 of the the stake function. If warmUpPeriod > 0 then the user will receive a "warmUpInfo" with the value of their deposit. The very next block, the user can then call instantUnstakeCurve.

<https://github.com/code-423n4/2022-06-yieldy/blob/524f3b83522125fb7d4677fa7a7e5ba5a2c0fe67/src/contracts/Staking.sol#L600-L627>

This will call rebase again in L633 and this time epoch.endTime <= block.timestamp will be true and it will trigger an actual rebase, distributing the pending rewards. \_retrieveBalanceFromUser (L617) will then allows the user to unstake all the funds locked in warm up. The issue is that when unstaking it uses userWarmInfo.credits meaning that any rebalance rewards are kept. This allows the user to get in, collect the rebase, then immediately get out.

### Recommended Mitigation Steps

Being able to unstake tokens even when in the warm up period is a useful feature but tokens unstaked during that period should not be allowed to a

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-yieldy)

---

### Example 5: M-2: Rounding error when call function `dodoMultiswap()` can lead to revert of transaction or fund of user

**Source**: Sherlock
**Protocol**: DODO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-dodo-judging/issues/45 

## Found by 
TrungOre

## Summary
The calculation of the proportion when do the split swap in function `_multiSwap` doesn't care about the rounding error 

## Vulnerability Detail
The amount of `midToken` will be transfered to the each adapter can be calculated by formula `curAmount = curTotalAmount * weight / totalWeight`
```solidity=
if (assetFrom[i - 1] == address(this)) {
    uint256 curAmount = curTotalAmount * curPoolInfo.weight / curTotalWeight;


    if (curPoolInfo.poolEdition == 1) {
        //For using transferFrom pool (like dodoV1, Curve), pool call transferFrom function to get tokens from adapter
        IERC20(midToken[i]).transfer(curPoolInfo.adapter, curAmount);
    } else {
        //For using transfer pool (like dodoV2), pool determine swapAmount through balanceOf(Token) - reserve
        IERC20(midToken[i]).transfer(curPoolInfo.pool, curAmount);
    }
}
```
It will lead to some scenarios when `curTotalAmount * curPoolInfo.weight` is not divisible by `curTotalWeight`, there will be some token left after the swap.

For some tx, if user set a `minReturnAmount` strictly, it may incur the reversion. 
For some token with small decimal and high value, it can make a big loss for the sender. 

## Impact
* Revert the transaction because not enough amount of `toToken`
* Sender can lose a small amount of tokens 

## Code Snippet
https://github.com/sherlock-audit/2022-11-dodo/blob/main/contracts

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 5
- Examples shown: 5
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## revert-by-sending-dust-patterns.md
# Revert By Sending Dust Security Patterns

## Overview

**Frequency**: 7 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 5 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Spearbit

---

## Detection Checklist

- [ ] Check for revert by sending dust vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: An attacker can freeze all incoming deposits and brick the oracle members' reporting system with only 1 wei

**Source**: Spearbit
**Protocol**: Liquid Collective
**Impact**: HIGH

**Details**:

## Severity: Critical Risk

**Context:** SharesManager.1.sol#L195-L206

**Description:** An attacker can brick or lock all deposited user funds and also prevent oracle members from reaching a quorum when there are earnings to be distributed as rewards. Consider the following scenario:

1. The attacker forcefully sends 1 wei to the River contract using, e.g., `selfdestruct`. The attacker must ensure this transaction occurs before any other users deposit their funds in the contract. The attacker can observe the mempool and front-run the initial user deposit. Now, `b = _assetBalance() > 0` is at least 1 wei.
   
2. An allowed user tries to deposit funds into the River protocol. The call eventually ends up in `_mintShares(o, x)` and in the first line, `oldTotalAssetBalance = _assetBalance() - x`. Here, `_assetBalance()` represents the updated River balance after accounting for the user deposit `x`. So, `_assetBalance()` is now `b + x + ...` and `oldTotalAssetBalance = b + ...` where the `...` includes the beacon balance sum, deposited amounts for validators in the queue, etc. (which is probably 0 by this point). Therefore, `oldTotalAssetBalance > 0` means that the following if block is skipped:

   ```javascript
   if (oldTotalAssetBalance == 0) {
       _mintRawShares(_owner, _underlyingAssetValue);
       return _underlyingAssetValue;
   }
   ```

   It goes directly to the else block for the first allowed user deposit:

   ```javascript
   else {
       uint256 sharesToMint = 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LiquidCollective-Spearbit-Security-Review.pdf)

---

### Example 2: A malicious user could DOS a vesting schedule by sending only 1 wei ofTLCto the vesting escrow address

**Source**: Spearbit
**Protocol**: Liquid Collective
**Impact**: HIGH

**Details**:

## Severity: Critical Risk

## Context:
- `ERC20VestableVotesUpgradeable.1.sol#L132-L134`
- `ERC20VestableVotesUpgradeable.1.sol#L137-L139`
- `ERC20VestableVotesUpgradeable.1.sol#L86-L97`
- `ERC20VestableVotesUpgradeable.1.sol#L353`

## Description:
An external user who owns some TLC tokens could DOS the vesting schedule of any user by sending just 1 wei of TLC to the escrow address related to the vesting schedule. By doing that:
- The creator of the vesting schedule will not be able to revoke the vesting schedule.
- The beneficiary of the vesting schedule will not be able to release any vested tokens until the end of the vesting schedule.
- Any external contracts or dApps will not be able to call `computeVestingReleasableAmount`.

In practice, all the functions that internally call `_computeVestingReleasableAmount` will revert because of an underflow error when called before the vesting schedule ends. The underflow error is thrown because, when called before the schedule ends, `_computeVestingReleasableAmount` will enter the `if (_time < _vestingSchedule.end)` branch and will try to compute:

```solidity
uint256 releasedAmount = _computeVestedAmount(_vestingSchedule, _vestingSchedule.end) - balanceOf(_escrow);
```

In this case, `_computeVestedAmount(_vestingSchedule, _vestingSchedule.end)` will always be lower than `balanceOf(_escrow)` and the contract will revert with an underflow error. When the vesting period ends, the contract will not enter the `if (_time < _vestingSch

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LiquidCollective2-Spearbit-Security-Review.pdf)

---

### Example 3: [M-01] `PirexGmx.initiateMigration` can be blocked

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: MEDIUM

**Details**:

`PirexGmx.initiateMigration` can be blocked so contract will not be able to migrate his funds to another contract using gmx.

### Proof of Concept

PirexGmx was designed with the thought that the current contract can be changed with another during migration.

`PirexGmx.initiateMigration` is the first point in this long process.

<https://github.com/code-423n4/2022-11-redactedcartel/blob/main/src/PirexGmx.sol#L921-L935>

```solidity
    function initiateMigration(address newContract)
        external
        whenPaused
        onlyOwner
    {
        if (newContract == address(0)) revert ZeroAddress();


        // Notify the reward router that the current/old contract is going to perform
        // full account transfer to the specified new contract
        gmxRewardRouterV2.signalTransfer(newContract);


        migratedTo = newContract;


        emit InitiateMigration(newContract);
    }
```

As you can see `gmxRewardRouterV2.signalTransfer(newContract);` is called to start migration.

This is the code of signalTransfer function
<https://arbiscan.io/address/0xA906F338CB21815cBc4Bc87ace9e68c87eF8d8F1#code#F1#L282>

```solidity
    function signalTransfer(address _receiver) external nonReentrant {
        require(IERC20(gmxVester).balanceOf(msg.sender) == 0, "RewardRouter: sender has vested tokens");
        require(IERC20(glpVester).balanceOf(msg.sender) == 0, "RewardRouter: sender has vested tokens");

        _validateReceiver(_receiver);
        pendingReceivers[msg.send

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-redactedcartel)

---

### Example 4: [M-05] repay function can be DOSed

**Source**: Code4rena
**Protocol**: Inverse Finance
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L531


## Vulnerability details

## Impact
In `repay()` users can repay their debt.
```
function repay(address user, uint amount) public {
        uint debt = debts[user];
        require(debt >= amount, "Insufficient debt");
        debts[user] -= amount;
        totalDebt -= amount;
        dbr.onRepay(user, amount);
        dola.transferFrom(msg.sender, address(this), amount);
        emit Repay(user, msg.sender, amount);
    }
```

There is a `require` condition, that checks if the amount provided, is greater than the debt of the user. If it is, then the function reverts. This is where the vulnerability arises.

`repay` function can be frontrun by an attacker. Say an attacker pay a small amount of debt for the victim user, by frontrunning his repay transaction. Now when the victim's transaction gets executed, the `require` condition will fail, as the amount of debt is less than the amount of DOLA provided. Hence the attacker can repeat the process to DOS the victim from calling the repay function.


## Proof of Concept

1. Victim calls repay() function to pay his debt of 500 DOLA , by providing the amount as 500
2. Now attacker saw this transaction on mempool
3. Attacker frontruns the transaction, by calling repay() with amount provided as 1 DOLA
4. Attacker's transaction get's executed first due to frontrunning, which reduces the debt of the victim user to 499 DOLA
5. Now when the vi

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-inverse)

---

### Example 5: [M-13] Market::forceReplenish can be DoSed

**Source**: Code4rena
**Protocol**: Inverse Finance
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L562


## Vulnerability details

## Impact
If a user wants to completely forceReplenish a borrower with deficit, the borrower or any other malicious party can front run this with a dust amount to prevent the replenish.

## Proof of Concept
```javascript
    function testForceReplenishFrontRun() public {
        gibWeth(user, wethTestAmount);
        gibDBR(user, wethTestAmount / 14);
        uint initialReplenisherDola = DOLA.balanceOf(replenisher);

        vm.startPrank(user);
        deposit(wethTestAmount);
        uint borrowAmount = getMaxBorrowAmount(wethTestAmount);
        market.borrow(borrowAmount);
        uint initialUserDebt = market.debts(user);
        uint initialMarketDola = DOLA.balanceOf(address(market));
        vm.stopPrank();

        vm.warp(block.timestamp + 5 days);
        uint deficitBefore = dbr.deficitOf(user);
        vm.startPrank(replenisher);

        market.forceReplenish(user,1); // front run DoS

        vm.expectRevert("Amount > deficit");
        market.forceReplenish(user, deficitBefore); // fails due to amount being larger than deficit
        
        assertEq(DOLA.balanceOf(replenisher), initialReplenisherDola, "DOLA balance of replenisher changed");
        assertEq(DOLA.balanceOf(address(market)), initialMarketDola, "DOLA balance of market changed");
        assertEq(DOLA.balanceOf(replenisher) - initialReplenisherDola, initialMarketDola - DOLA

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-inverse)

---

### Example 6: M-9: [M] Incorrect Validation in `Pool.sol#transferLPs` lead to a DOS attack

**Source**: Sherlock
**Protocol**: Ajna
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-ajna-judging/issues/116 

## Found by 
oxcm

## Summary

The code in the transferLPs function has an incorrect validation check, where it requires `allowances_` to be strictly equal to `lenderLpBalance`, instead of just `allowances_` being greater than `transferAmount`.

## Vulnerability Detail

In the `transferLPs()` function, `transferAmount` is being compared to `allowances_[owner_][newOwner_][index]` and `lenderLpBalance`. If the values are not strictly equal, the function will revert with a `NoAllowance` error. 

Due to the requirement of `transferLPs()` that `allowances_` must equal `lenderLpBalance`, the user can only enter `lpsAmountToApprove_` as the current `lenderLpBalance` when using `approveLpOwnership()`.

This results in `transferLPs()` reverting with `NoAllowance` if `lenderLpBalance` undergoes any change, allowing attackers to design a DOS attack.

However, this validation is not necessary as it should only require `allowances_` to be greater than `transferAmount`.

## Impact

An attacker could exploit this vulnerability by transferring a small amount of LP tokens to the owner before the transfer to the new owner is initiated. This would cause the `allowances_` value to be less than `lenderLpBalance`, causing the transfer to revert and the tokens to remain in the original owner's account.

## Code Snippet

Relevant code snippet from transferLPs function:
 
https://github.com/sherlock-audit/2023-01-ajna/blob/ma

*[Content truncated...]*

---

### Example 7: M-4: Dust amounts can cause payments to fail, leading to default

**Source**: Sherlock
**Protocol**: Cooler
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-cooler-judging/issues/218 

## Found by 
kiki\_dev, HollaDieWaldfee, IllIllI, ak1

## Summary

Dust amounts can cause payments to fail, leading to default


## Vulnerability Detail

In order for a loan to close, the exact right number of wei of the debt token must be sent to match the remaining loan amount. If more is sent, the balance underflows, reverting the transaction.


## Impact

An attacker can send dust amounts right before a loan is due, front-running any payments also destined for the final block before default. If the attacker's transaction goes in first, the borrower will be unable to pay back the loan before default, and will lose thier remaining collateral. This may be the whole loan amount.


## Code Snippet

If the repayment amount isn't exactly the remaining loan amount, and instead is more (due to the dust payment), the subtraction marked below will underflow, reverting the payment:
```solidity
// File: src/Cooler.sol : Cooler.repay()   #1

108        function repay (uint256 loanID, uint256 repaid) external {
109            Loan storage loan = loans[loanID];
110    
111            if (block.timestamp > loan.expiry) 
112                revert Default();
113            
114            uint256 decollateralized = loan.collateral * repaid / loan.amount;
115    
116           if (repaid == loan.amount) delete loans[loanID];
117           else {
118 @>             loan.amount -= repaid;
119                loan.coll

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 7
- Examples shown: 7
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## grief-attack-patterns.md
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

Inside LoanVault.sols liquidate() it is checked if the debtAmount (initial debt amount when loan was created) is now equal to the balance of debt token in the vault , if not revert (L163)

An attacker can see a liquidation() call in the mempool and ->

a.) Frontruns this call to send the lowest amount of debt token to the vault , say 1
b.) Now when the liquidator tries to liquidate he sends out debtAmount of tokens to the vault , lets say they were 100
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


---
## fund-lock-patterns.md
# Fund Lock Security Patterns

## Overview

**Frequency**: 22 occurrences (0.04% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 9 | 13 | 0 | 0 |

**Common Sources**: Spearbit, Sherlock, Code4rena, Cyfrin, Pashov Audit Group

---

## Detection Checklist

- [ ] Check for fund lock vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Tokens can get stuck in Executor contract if the destination doesnt claim them all

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Vulnerability Report

## Severity
**High Risk**

## Context
**Executor.sol#L142-L243**

## Description
The function `execute()` increases allowance and then calls the recipient (`_args.to`). When the recipient does not use all tokens, these could remain stuck inside the Executor contract. 

**Notes:**
- The executor can have excess tokens, see: kovan executor.
- See issue: "Malicious call data can DOS execute or steal unclaimed tokens in the Executor contract".

```solidity
function execute(...) ... {
    ...
    if (!isNative && hasValue) {
        SafeERC20.safeIncreaseAllowance(IERC20(_args.assetId), _args.to, _args.amount);
    }
    ...
    (success, returnData) = ExcessivelySafeCall.excessivelySafeCall(_args.to, ...);
    ...
}
```

## Recommendation
Determine what should happen with unclaimed tokens. Consider one or more of the following suggestions:
- Send the unclaimed tokens to the recovery address via `_sendToRecovery()` (although this further complicates the contract).
- Set the allowance to `0` (before `safeIncreaseAllowance()` or after the call to `excessivelySafeCall()`).
- Allow the retrieval of unclaimed tokens from the executor contract by an owner.

**Connext:** New policy: "any funds left in the Executor following a transfer are claimable by anyone". This forces implementers to think carefully about the calldata. Thus, leave the issues as is.

**Spearbit:** Acknowledged.

**Note:** As it requires some deliberate action to retrieve the tokens, in practic

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 2: Tokens transferred with Axelar can get lost if the destination transaction cant be executed

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: HIGH

**Details**:

## Security Report

## Severity
**High Risk**

## Context
`Executor.sol#L293-L316`

## Description
If `executeWithToken()` reverts, then the transaction can be retried, possibly with additional gas.  
See Axelar recovery. However, there is no option to return the tokens or send them elsewhere. This means that tokens would be lost if the call cannot be made to work.

```solidity
contract Executor is IAxelarExecutable, Ownable, ReentrancyGuard, ILiFi {
    function _executeWithToken(...) ... {
        ...
        (bool success, ) = callTo.call(callData);
        if (!success) revert ExecutionFailed();
    }
}
```

## Recommendation
Consider sending the tokens to a recovery address in case the transaction fails.  
For comparison: The Connext executor has logic to do this.

## Status
**LiFi:** Fixed with PR #44  
**Spearbit:** Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 3: Tokens are left in the protocol when the swap at the destination chain fails

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: HIGH

**Details**:

## Security Report

## Severity
**High Risk**

## Context
- AmarokFacet.sol#L55-L94
- StargateFacet.sol#L149-L187
- NXTPFacet.sol#L86-L117
- Executor.sol#L125-L221
- XChainExecFacet.sol#L17-L51

## Description
LiFi protocol finds the best bridge route for users. In some cases, it helps users do a swap at the destination chain. With the help of the bridge protocols, the LiFi protocol assists users in triggering `swapAndComplete-BridgeTokensVia{Services}` or `CompleteBridgeTokensVia{Services}` at the destination chain to perform the swap.

Some bridge services will send the tokens directly to the receiver address when the execution fails. For example, Stargate, Amarok, and NXTP conduct the external call in a try-catch clause and send the tokens directly to the receiver when it fails. The tokens will remain in the LiFi protocol in this scenario. If the receiver is the Executor contract, users can freely pull the tokens. 

**Note:** Exploiters can pull the tokens from the LiFi protocol. Please refer to the issue **"Remaining tokens can be swept from the LiFi Diamond or the Executor," Issue #82**. Exploiters can take a more aggressive strategy and force the victim's swap to revert. A possible exploit scenario:

- A victim wants to swap 10K optimisms BTC into Ethereum mainnet USDC.
- Since DEXs on the mainnet have the best liquidity, the LiFi protocol helps users swap on the mainnet.
- The transaction on the source chain (optimism) succeeds, and the bridge services try to call `Co

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 4: Upon failing to back unbacked debt _reconcileProcessPortal() will leave the converted asset in the contract

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Security Report

## Severity
**High Risk**

## Context
`NomadFacet.sol#L225-L242`

## Description
When routers front liquidity for the protocols users, they are later reconciled once the bridge has optimistically verified transfers from the source chain. Upon being reconciled, the `_reconcileProcessPortal()` attempts to first pay back Aave debt before distributing the rest back to the router. However, `_reconcileProcessPortal()` will not convert the adopted asset back to the local asset in the case where the call to the Aave pool fails.

Instead, the function will set `amountIn = 0` and continue to distribute the local asset to the router.

```solidity
if (success) {
    emit AavePortalRepayment(_transferId, adopted, backUnbackedAmount, portalFee);
} else {
    // Reset values
    s.portalDebt[_transferId] += backUnbackedAmount;
    s.portalFeeDebt[_transferId] += portalFee;
    // Decrease the allowance
    SafeERC20.safeDecreaseAllowance(IERC20(adopted), s.aavePool, totalRepayAmount);
    // Update the amount repaid to 0, so the amount is credited to the router
    amountIn = 0;
    emit AavePortalRepaymentDebt(_transferId, adopted, s.portalDebt[_transferId],
                                 s.portalFeeDebt[_transferId]);
}
```

## Recommendation
It might be useful to convert the adopted asset amount back to the local asset such that subsequent swaps do not fail due to an insufficient amount of local asset. Alternatively, if the attempt to back unbacked debt fails, cons

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 5: H-8: Interest component of underlying amount is not withdrawable using the `withdrawLend` function. Such amount is permanently locked in the BlueBerryBank contract

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/109 

## Found by 
berndartmueller, carrot, minhtrng, 0Kage, Jeiwan, chaduke, koxuan, Ruhum, cergyk, rbserver, stent, saian, XKET, GimelSec

## Summary
Soft vault shares are issued against interest bearing tokens issued by `Compound` protocol in exchange for underlying deposits. However, `withdrawLend` function caps the withdrawable amount to initial underlying deposited by user (`pos.underlyingAmount`). Capping underlying amount to initial underlying deposited would mean that a user can burn all his vault shares in `withdrawLend` function and only receive original underlying deposited.

Interest accrued component received from Soft vault (that rightfully belongs to the user) is no longer retrievable because the underlying vault shares are already burnt. Loss to the users is permanent as such interest amount sits permanently locked in Blueberry bank.

## Vulnerability Detail

[`withdrawLend` function in `BlueBerryBank`](https://github.com/sherlock-audit/2023-02-blueberry/blob/main/contracts/BlueBerryBank.sol#L669) allows users to withdraw underlying amount from `Hard` or `Soft` vaults. `Soft` vault shares are backed by interest bearing `cTokens` issued by Compound Protocol

User can request underlying by specifying `shareAmount`. When user tries to send the maximum `shareAmount` to withdraw all the lent amount, notice that the amount withdrawable is limited to the `pos.underlyingAmount` (original depos

*[Content truncated...]*

---

### Example 6: Dust might be trapped in WlsETH when burning one's balance.

**Source**: Spearbit
**Protocol**: Liquid Collective
**Impact**: MEDIUM

**Details**:

## Security Analysis Report

## Severity
**Medium Risk**

## Context
*WLSETH.1.sol#L140*

## Description
It is not possible to burn the exact amount of minted/deposited lsETH back because the _value provided to burn is in ETH. 

Assume we've called `mint(r,v)` with our address `r`, then to get the `v` lsETH back to our address, we need to find an `x` where:

\[ v = \frac{b \cdot x \cdot S}{B} \]

and call `burn(r, x)` (Here `S` represents the total share of lsETH and `B` the total underlying value.). 

It's not always possible to find the exact `x`, so there will always be an amount locked in this contract:

\[ v \neq \frac{b \cdot x \cdot S}{B} \]

These dust amounts can accumulate from different users and turn into a significant number. To get the full amount back, the user needs to mint more wlsETH tokens so that we can find an exact solution to:

\[ v = \frac{b \cdot x \cdot S}{B} \]

The extra amount to get the locked-up fees back can be engineered. The same problem exists for `transfer` and `transferFrom`. 

Also note, if you have minted `x` amount of shares, the `balanceOf` would tell you that you own:

\[ b = \frac{b \cdot x \cdot B}{S \cdot wlsETH} \]

Internally, wlsETH keeps track of the shares `x`. So users think they can only burn `b` amount, plug that in for the _value, and in this case, the number of shares burnt would be:

\[
\frac{b \cdot x \cdot B}{S \cdot C \cdot B\%}
\]

which has even more rounding errors. wlsETH could internally track the underlying but 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LiquidCollective-Spearbit-Security-Review.pdf)

---

### Example 7: What if the receiver of Axelar _executeWithToken() doesnt claim all tokens

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Security Assessment Report

## Severity
**Medium Risk**

## Context
`Executor.sol#L293-L316`

## Description
The function `_executeWithToken()` approves tokens and then calls `callTo`. If that contract doesnt retrieve the tokens, then the tokens stay within the Executor and are lost. 

Also see: "Remaining tokens can be swept from the LiFi Diamond or the Executor."

```solidity
contract Executor is IAxelarExecutable, Ownable, ReentrancyGuard, ILiFi {
    function _executeWithToken(...) ... {
        ...
        // transfer received tokens to the recipient
        IERC20(tokenAddress).approve(callTo, amount);
        (bool success, ) = callTo.call(callData);
        ...
    }
}
```

## Recommendation
Consider sending the remaining tokens to a recovery address. Document the token handling in `AxelarFacet.md`.

## References
- **LiFi**: Fixed with PR #62.
- **Spearbit**: Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 8: Funds can be locked during the recovery stage

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Security Report

## Severity
**Low Risk**

## Context
`AmarokFacet.sol#L133`

## Description
The recovery address is intended to receive funds if the execution fails on the destination domain. This approach ensures that funds are never lost due to failed calls. However, in the `AmarokFacet`, it is hardcoded as `msg.sender`. Several unexpected behaviors can be observed with this implementation:

- If the `msg.sender` is a smart contract, it might not be available on the destination chain.
- If the `msg.sender` is a smart contract deployed on another chain, the contract may not have a function to withdraw the native token.

As a result of this implementation, funds can be locked when an execution fails.

```solidity
contract AmarokFacet is ILiFi, SwapperV2, ReentrancyGuard {
...
IConnextHandler.XCallArgs memory xcallArgs = IConnextHandler.XCallArgs({
    params: IConnextHandler.CallParams({
        to: _bridgeData.receiver,
        callData: _bridgeData.callData,
        originDomain: _bridgeData.srcChainDomain,
        destinationDomain: _bridgeData.dstChainDomain,
        agent: _bridgeData.receiver,
        recovery: msg.sender,
        forceSlow: false,
        receiveLocal: false,
        callback: address(0),
        callbackFee: 0,
        relayerFee: 0,
        slippageTol: _bridgeData.slippageTol
    }),
    transactingAssetId: _bridgeData.assetId,
    amount: _amount
});
...
}
```

## Recommendation
Consider taking the recovery parameter as an argument.

## LiFi
Fi

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 9: Underpaying Optimism l2gas may lead to loss of funds

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Security Report

## Severity: Medium Risk

### Context
- **File:** OptimismBridgeFacet.sol
- **Lines:** 97-113

### Description
The `OptimismBridgeFacet` uses Optimisms bridge with user-provided `l2Gas`.

```solidity
function _startBridge(
    LiFiData calldata _lifiData,
    BridgeData calldata _bridgeData,
    uint256 _amount,
    bool _hasSourceSwap
) private {
    ...
    if (LibAsset.isNativeAsset(_bridgeData.assetId)) {
        bridge.depositETHTo{ value: _amount }(_bridgeData.receiver, _bridgeData.l2Gas, "");
    } else {
        ...
        bridge.depositERC20To(
            _bridgeData.assetId,
            _bridgeData.assetIdOnL2,
            _bridgeData.receiver,
            _amount,
            _bridgeData.l2Gas,
            ""
        );
    }
}
```

Optimisms standard token bridge makes the cross-chain deposit by sending a cross-chain message to `L2Bridge`.

- **File:** L1StandardBridge.sol
- **Lines:** 114-123

```solidity
// Construct calldata for finalizeDeposit call
bytes memory message = abi.encodeWithSelector(
    IL2ERC20Bridge.finalizeDeposit.selector,
    address(0),
    Lib_PredeployAddresses.OVM_ETH,
    _from,
    _to,
    msg.value,
    _data
);

// Send calldata into L2
// slither-disable-next-line reentrancy-events
sendCrossDomainMessage(l2TokenBridge, _l2Gas, message);
```

If the `l2Gas` is underpaid, `finalizeDeposit` will fail and user funds will be lost.

### Recommendation
Given the potential risks of losing users funds, it is recommend

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 10: WormholeFacet doesnt send native token

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
`WormholeFacet.sol#L36-L103`

## Description
The functions of `WormholeFacet` allow sending the native token; however, they dont actually send it across the bridge, causing the native token to stay stuck in the LiFi Diamond and get lost for the sender.

```solidity
contract WormholeFacet is ILiFi, ReentrancyGuard, Swapper {
    function startBridgeTokensViaWormhole(... ) ... payable ... { // is payable
        LibAsset.depositAsset(_wormholeData.token, _wormholeData.amount); // allows native token
        _startBridge(_wormholeData);
        ...
    }

    function _startBridge(WormholeData memory _wormholeData) private {
        ...
        LibAsset.maxApproveERC20(...); // geared towards ERC20, also works when `msg.value `is set
        IWormholeRouter(_wormholeData.wormholeRouter).transferTokens(...); // no { value : .... }
    }
}
```

## Recommendation
Remove the `payable` keyword and/or check `msg.value == 0`. Alternatively, support sending the native token. This can be done via `wrapAndTransferETH()` of the wormhole bridge.

**Note:** also see issue "Consider using wrapped native token"

## LiFi
Fixed with PR #76.

## Spearbit
Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 11: Implement a function to claim liquidity mining rewards

**Source**: Spearbit
**Protocol**: Gauntlet
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
AeraVaultV1.sol

## Description
Balancer offers a liquidity mining rewards distribution for liquidity providers. 

Liquidity Mining distributions are available to claim weekly through the `MerkleOrchard` contract. Liquidity Providers can claim tokens from this contract by submitting claims to the tokens. These claims are checked against a Merkle root of the accrued token balances which are stored in a Merkle tree. Claiming through the `MerkleOrchard` is much more gas-efficient than the previous generation of claiming contracts, especially when claiming multiple weeks of rewards, and when claiming multiple tokens.

The AeraVault is itself the only liquidity provider of the Balancer pool deployed, so each week its entitled to claim those rewards. Currently, those rewards cannot be claimed because the AeraVault is missing an implementation to interact with the `MerkleOrchard` contract, causing all rewards (BAL + other tokens) to remain in the `MerkleOrchard` forever.

## Recommendation
Add a function to allow the vault owner (the Treasury) to claim those rewards. More information on how to claim rewards and interact with the contract can be found directly in the Balancer Documentation website.

Rewards claimed by the AeraVault can be later distributed to the Treasury via the sweep function.

## Gauntlet
Recommendation implemented in PR #146.

## Spearbit
Acknowledged.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Gauntlet-Spearbit-Security-Review.pdf)

---

### Example 12: TRST-M-9 Vault does not have a way to withdraw native tokens

**Source**: Trust Security
**Protocol**: Mozaic Archimedes
**Impact**: MEDIUM

**Details**:

**Description:**
The Vault sets the LayerZero fee refund address to itself:
```solidity
        /// @notice Report snapshot of the vault to the controller.
        function reportSnapshot() public onlyBridge {
                 MozBridge.Snapshot memory _snapshot = _takeSnapshot();
             MozBridge(mozBridge).reportSnapshot(_snapshot, 
          payable(address(this)));
        }
```
However, there is no function to withdraw those funds, making them forever stuck in the vault 
only available for paying for future transactions.

**Recommended mitigation:**
Add a native token withdrawal function.

**Team response:**
Fixed.

**Mitigation review:**
The fix includes a new `withdraw()` function. Its intention is to vacate any ETH stored in the 
controller and vaults.

```solidity
        function withdraw() public {
        // get the amount of Ether stored in this contract
            uint amount = address(this).balance;
        // send all Ether to owner
        // Owner can receive Ether since the address of owner is payable
            (bool success, ) = treasury.call{value: amount}("");
                 require(success, "Controller: Failed to send Ether");
         }
```
In fact, attackers can simply call `withdraw()` to make messaging fail due to lack of native
tokens. This could be repeated in every block to make the system unusable.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Trust Security/2023-05-23-Mozaic Archimedes.md)

---

### Example 13: User's funds are locked temporarily in the PriorityPool contract

**Source**: Cyfrin
**Protocol**: Stake Link
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Description:** The protocol intended to utilize the deposit queue for withdrawal to minimize the stake/unstake interaction with the staking pool.
When a user wants to withdraw, they are supposed to call the function `PriorityPool::withdraw()` with the desired amount as a parameter.
```solidity
function withdraw(uint256 _amount) external {//@audit-info LSD token
    if (_amount == 0) revert InvalidAmount();
    IERC20Upgradeable(address(stakingPool)).safeTransferFrom(msg.sender, address(this), _amount);//@audit-info get LSD token from the user
    _withdraw(msg.sender, _amount);
}
```
As we can see in the implementation, the protocol pulls the `_amount` of LSD tokens from the user first and then calls `_withdraw()` where the actual withdrawal utilizing the queue is processed.
```solidity
function _withdraw(address _account, uint256 _amount) internal {
    if (poolStatus == PoolStatus.CLOSED) revert WithdrawalsDisabled();

    uint256 toWithdrawFromQueue = _amount <= totalQueued ? _amount : totalQueued;//@audit-info if the queue is not empty, we use that first
    uint256 toWithdrawFromPool = _amount - toWithdrawFromQueue;

    if (toWithdrawFromQueue != 0) {
        totalQueued -= toWithdrawFromQueue;
        depositsSinceLastUpdate += toWithdrawFromQueue;//@audit-info regard this as a deposit via the queue
    }

    if (toWithdrawFromPool != 0) {
        stakingPool.withdraw(address(this), address(this), toWithdrawFromPool);//@audit-info withdraw from

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-08-25-cyfrin-stake-link.md)

---

### Example 14: [M-02] If DAO updates `forkEscrow` before `forkThreshold` is reached, the user's escrowed Nouns will be lost

**Source**: Code4rena
**Protocol**: Nouns DAO
**Impact**: MEDIUM

**Details**:

During the escrow period, users can escrow to or withdraw from forkEscrow their Nouns.

During the escrow period, proposals can be executed.

```solidity
    function withdrawFromForkEscrow(NounsDAOStorageV3.StorageV3 storage ds, uint256[] calldata tokenIds) external {
        if (isForkPeriodActive(ds)) revert ForkPeriodActive();

        INounsDAOForkEscrow forkEscrow = ds.forkEscrow;
        forkEscrow.returnTokensToOwner(msg.sender, tokenIds);

        emit WithdrawFromForkEscrow(forkEscrow.forkId(), msg.sender, tokenIds);
    }
```

Since withdrawFromForkEscrow will only call the returnTokensToOwner function of ds.forkEscrow, and returnTokensToOwner is only allowed to be called by DAO.

If, during the escrow period, ds.forkEscrow is changed by the proposal's call to \_setForkEscrow, then the user's escrowed Nouns will not be withdrawn by withdrawFromForkEscrow.

```solidity
    function returnTokensToOwner(address owner, uint256[] calldata tokenIds) external onlyDAO {
        for (uint256 i = 0; i < tokenIds.length; i++) {
            if (currentOwnerOf(tokenIds[i]) != owner) revert NotOwner();

            nounsToken.transferFrom(address(this), owner, tokenIds[i]);
            escrowedTokensByForkId[forkId][tokenIds[i]] = address(0);
        }

        numTokensInEscrow -= tokenIds.length;
    }
```

Consider that some Nouners is voting on a proposal that would change ds.forkEscrow.<br>
There are some escrowed Nouns in forkEscrow (some Nouners may choose to always escro

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-07-nounsdao)

---

### Example 15: M-6: Claiming rewards from a future not yet existing epoch prevents claiming rewards for those epochs later on

**Source**: Sherlock
**Protocol**: Ajna
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-ajna-judging/issues/122 

## Found by 
berndartmueller, Blockian

## Summary

If a user claims rewards for a future epoch, all epochs are marked as claimed up until that future epoch. This prevents the user from claiming rewards for those epochs later, leading to a loss of rewards.

## Vulnerability Detail

Already claimed rewards are tracked in the `isEpochClaimed` mapping and checked in the `RewardsManager.claimRewards` function to prevent claiming rewards multiple times. However, the current implementation does not prevent a user from accidentally claiming rewards for a future epoch. This would iterate through all epochs up until the future epoch and mark them all as claimed. This prevents the user from claiming rewards for those epochs later on, leading to a loss of rewards.

## Impact

If a user accidentally claims rewards for a future epoch, the rewards are lost and unclaimable.

## Code Snippet

[contracts/src/RewardsManager.sol#L112](https://github.com/sherlock-audit/2023-01-ajna/blob/main/contracts/src/RewardsManager.sol#L112)

```solidity
106: function claimRewards(
107:     uint256 tokenId_,
108:     uint256 epochToClaim_
109: ) external override {
110:     if (msg.sender != stakes[tokenId_].owner) revert NotOwnerOfDeposit();
111:
112:     if (isEpochClaimed[tokenId_][epochToClaim_]) revert AlreadyClaimed();
113:
114:     _claimRewards(tokenId_, epochToClaim_);
115: }
```

[contracts/src/RewardsManager.sol#L298](htt

*[Content truncated...]*

---

### Example 16: H-4: PerpDepository has no way to withdraw profits depriving stakers of profits owed

**Source**: Sherlock
**Protocol**: UXD Protocol
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-uxd-judging/issues/251 

## Found by 
0x52

## Summary

PerpDepository has no way to calculate or withdraw any profits made by the vault. By [design](https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/rage-trade/RageDnDepository.sol#L99-L115) stakes are entitled to a portion of the profits generated by the delta-neutral strategy. The issue is that the vault never implements a way to withdraw profits to stakers, resulting in loss of revenue for them.

## Vulnerability Detail

See summary.

## Impact

Profits owed stakers will be trapped in the contract and they will lose that portion of their revenue

## Code Snippet

https://github.com/sherlock-audit/2023-01-uxd/blob/main/contracts/integrations/perp/PerpDepository.sol#L25

## Tool used

Manual Review

## Recommendation

Create a function to calculate and withdraw protocol profit to be awarded to stakers

## Discussion

**WarTech9**

Profits on `PerpDepository` are currently locked in the depository and can be unlocked in future updates through positive PnL rebalancing.
`RageDepository` profits are locked in that contract and can be withdrawn by the contract owner (governance) through the `withdrawProfits()` function

**rvierdiyev**

Escalate for 11 USDC.

This is not a vulnerability.
As @WarTech9 said, 
>`RageDepository` profits are locked in that contract and can be withdrawn by the contract owner (governance) through the `withdrawProfits()` functi

*[Content truncated...]*

---

### Example 17: H-2: ShortLongSpell#openPosition uses the wrong balanceOf when determining how much collateral to put

**Source**: Sherlock
**Protocol**: Blueberry Update #2
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-05-blueberry-judging/issues/31 

## Found by 
0x52
## Summary

The _doPutCollateral subcall in ShortLongSpell#openPosition uses the balance of the uToken rather than the vault resulting in the vault tokens being left in the contract which will be stolen.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-05-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L144-L150

        address vault = strategies[param.strategyId].vault;
        _doPutCollateral(
            vault,
            IERC20Upgradeable(ISoftVault(vault).uToken()).balanceOf(
                address(this)
            )
        );

When putting the collateral the contract is putting vault but it uses the balance of the uToken instead of the balance of the vault.

## Impact

Vault tokens will be left in contract and stolen

## Code Snippet

https://github.com/sherlock-audit/2023-05-blueberry/blob/main/blueberry-core/contracts/spell/ShortLongSpell.sol#L111-L151

## Tool used

Manual Review

## Recommendation

Use the balanceOf vault rather than vault.uToken



## Discussion

**sleepriverfish**

Escalate for 10 USDC

In #Blueberry Update, despite the successful escalation of the issue, no reward was granted for the heightened severity and impact of the vulnerability. However, in #Blueberry Update2, a reward was offered specifically for the detection and reporting of a similar vulnerability.
https://github.com/sherlock-audit/2023-04-bluebe

*[Content truncated...]*

---

### Example 18: H-1: AuraSpell#openPositionFarm fails to return all rewards to user

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

### Example 19: M-4: Users can fail to closePositionFarm and lose their funds

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/64 

## Found by 
Bauer
## Summary
If self.is_killed in the curve pool contract  becomes true, user may be unable to call the `CurveSpell.closePositionFarm()` function to  repay his debt, resulting in his assets being liquidated.


## Vulnerability Detail
The `CurveSpell.closePositionFarm()` function is used to unwind a position on a strategy that involves farming CRV rewards through staking LP tokens in a Curve pool. Inside the function, the protocol swaps the harvested CRV tokens to the debt token, and calculates the actual amount of LP tokens to remove from the Curve pool. It then removes the LP tokens using the remove_liquidity_one_coin function of the Curve pool. 
```solidity
   int128 tokenIndex;
            for (uint256 i = 0; i < tokens.length; i++) {
                if (tokens[i] == pos.debtToken) {
                    tokenIndex = int128(uint128(i));
                    break;
                }
            }

            ICurvePool(pool).remove_liquidity_one_coin(
                amountPosRemove,
                int128(tokenIndex),
                0
            );
        }

        // 5. Withdraw isolated collateral from Bank
        _doWithdraw(param.collToken, param.amountShareWithdraw);

        // 6. Repay
        {
            // Compute repay amount if MAX_INT is supplied (max debt)
            uint256 amountRepay = param.amountRepay;
            if (amountRepay == type(uint256).max) {

*[Content truncated...]*

---

### Example 20: [M-18] Fees from delisted pool still in reward handler will become stuck after delisting

**Source**: Code4rena
**Protocol**: Backd
**Impact**: MEDIUM

**Details**:

_Submitted by 0x52_

Unclaimed fees from pool will be stuck.

### Proof of Concept

When delisting a pool the pool's reference is removed from address provider:

<https://github.com/code-423n4/2022-05-backd/blob/2a5664d35cde5b036074edef3c1369b984d10010/protocol/contracts/Controller.sol#L63>

Burning fees calls a dynamic list of all pools which no longer contains the delisted pool:

<https://github.com/code-423n4/2022-05-backd/blob/2a5664d35cde5b036074edef3c1369b984d10010/protocol/contracts/RewardHandler.sol#L39>

Since the list no longer contains the pool those fees will not be processed and will remain stuck in the contract

### Recommended Mitigation Steps

Call burnFees() before delisting a pool.

**[danhper (Backd) confirmed](https://github.com/code-423n4/2022-05-backd-findings/issues/135)** 

**[Alex the Entreprenerd (judge) commented](https://github.com/code-423n4/2022-05-backd-findings/issues/135#issuecomment-1163376879):**
 > The warden has shown how, by removing a pool before calling `burnFees`, the removed pool will not receive the portion of fees that it should.
> 
> Because this finding related to loss of yield, I believe Medium Severity to be appropriate.



***

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-backd)

---

### Example 21: [M-02] Contract `HibernationDen` can receive ETH but it can't be withdrawn

**Source**: Pashov Audit Group
**Protocol**: Bearcave
**Impact**: MEDIUM

**Details**:

**Impact:**
Medium, as it will result in stuck funds, but they will just have the value of gas refunded

**Likelihood:**
Medium, as it will happen when there is a refund from a cross-chain call

**Description**

The `HibernationDen` contract has a `receive` method. This is mostly expected to be used for `LayerZero` refunds as the comment above the method says. The problem is that this gas refunds ETH won't be withdrawable as there is no method for ETH withdraw in the contract. Another issue is that anyone can mistakenly send ETH to `HibernationDen` and it will be stuck there.

**Recommendations**

Add a method that can withdraw ETH from the `HibernationDen` contract.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Pashov/2023-06-01-BearCave.md)

---

### Example 22: Funds held in ETHAdapter can be drained by anyone

**Source**: OpenZeppelin
**Protocol**: Pods Finance Ethereum Volatility Vault Audit #1
**Impact**: MEDIUM

**Details**:

The[`ETHAdapter`](https://github.com/pods-finance/yield-contracts/blob/9389ab46e9ecdd1ea1fd7228c9d9c6821c00f057/contracts/proxy/ETHAdapter.sol)contract is used as a proxy to allow users to interact with the vault through sending and receiving ETH instead of stETH. The adapter achieves this by converting ETH and stETH through a curve pool and then forwarding interactions to and from the vault. In the course of a normal[withdrawal](https://github.com/pods-finance/yield-contracts/blob/9389ab46e9ecdd1ea1fd7228c9d9c6821c00f057/contracts/proxy/ETHAdapter.sol#L71)or[redemption](https://github.com/pods-finance/yield-contracts/blob/9389ab46e9ecdd1ea1fd7228c9d9c6821c00f057/contracts/proxy/ETHAdapter.sol#L46)transaction, the`ETHAdapter`will pull the funds out of the vault before passing them on to the designated receiver. During the moment the`ETHAdapter`is holding the funds, it first[converts](https://github.com/pods-finance/yield-contracts/blob/9389ab46e9ecdd1ea1fd7228c9d9c6821c00f057/contracts/proxy/ETHAdapter.sol#L110-L112)all of its stETH to ETH, and then sends its entire ETH balance to the receiving address.


The issue is that the`ETHAdapter`sends its full balance to the receiver each time, meaning any ETH or stETH that is mistakenly sent to it can be drained by any user who performs a withdrawal or redemption on the`ETHAdapter`. This is exacerbated by the fact that the vault is passed in as a[parameter](https://github.com/pods-finance/yield-contracts/blob/9389ab4

*[Content truncated...]*

**Reference**: [View Original Finding](https://blog.openzeppelin.com/pods-finance-ethereum-volatility-vault-audit-1/)

---

## Statistics

- Total findings analyzed: 22
- Examples shown: 22
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## withdraw-0-patterns.md
# Withdraw 0 Security Patterns

## Overview

**Frequency**: 3 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 1 | 0 | 0 |

**Common Sources**: Codehawks, Sherlock, Code4rena

---

## Detection Checklist

- [ ] Check for withdraw 0 vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Token withdrawal fails until someone manually approves spending

**Source**: Codehawks
**Protocol**: Tadle
**Impact**: HIGH

**Details**:

## Summary

The protocol uses a contract called TokenManager to control a capital pool that stores tokens.

When a user wants to withdraw, the TokenManager needs spender allowance on the capital pool, but this is not checked for, so the withdrawal fails.

## Vulnerability Details

We simulate a user creating an offer, closing it and then trying to withdraw. The withdrawal fails because of zero allowance for the TokenManager as a spender of the capital pool.

```Solidity
function test_token_withdrawal_fails() public {
    // Data for creating an offer, not relevant.
    uint256 points = 1000;
    uint256 amountToken = 1000000 * 1e18;
    uint256 collateralRate = 12000;
    uint256 eachTradeTax = 300;

    vm.startPrank(user);
    preMarktes.createOffer(
        CreateOfferParams(
            marketPlace,
            address(mockUSDCToken),
            points,
            amountToken,
            collateralRate,
            eachTradeTax,
            OfferType.Ask,
            OfferSettleType.Turbo
        )
    );

    // Close the offer.
    address offerAddr = GenerateAddress.generateOfferAddress(0);
    address stockAddr = GenerateAddress.generateStockAddress(0);

    preMarktes.closeOffer(stockAddr, offerAddr);

    tokenManager.withdraw(address(mockUSDCToken), TokenBalanceType.MakerRefund);
    vm.stopPrank();
}
```

> ```Solidity
>  [8858] UpgradeableProxy::withdraw(MockERC20Token: [0xF62849F9A0B5Bf2913b396098F7c7019b51A820a], 4)
>     [8339] TokenManager::withdraw(M

*[Content truncated...]*

---

### Example 2: [H-02] denial of service

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

### Example 3: M-3: `_withdrawFromPlugin()` will revert when `_withdrawalValues[i] == 0`

**Source**: Sherlock
**Protocol**: Mycelium
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-10-mycelium-judging/tree/main/013-M 

## Found by 
ctf\_sec, hansfriese, WATCHPUG

## Summary

## Vulnerability Detail

When `_withdrawalValues[i] == 0` in `rebalancePlugins()`, it means NOT to rebalance this plugin.

However, the current implementation still tries to withdraw 0 from the plugin.

This will revert in AaveV2Plugin as Aave V2's `validateWithdraw()` does not allow `0` withdrawals:

https://github.com/aave/protocol-v2/blob/554a2ed7ca4b3565e2ceaea0c454e5a70b3a2b41/contracts/protocol/libraries/logic/ValidationLogic.sol#L60-L70

```solidity
  function validateWithdraw(
    address reserveAddress,
    uint256 amount,
    uint256 userBalance,
    mapping(address => DataTypes.ReserveData) storage reservesData,
    DataTypes.UserConfigurationMap storage userConfig,
    mapping(uint256 => address) storage reserves,
    uint256 reservesCount,
    address oracle
  ) external view {
    require(amount != 0, Errors.VL_INVALID_AMOUNT);
```

`removePlugin()` will also always `_withdrawFromPlugin()` even if the plugin's balance is 0, as it will also tries to withdraw 0 in that case (balance is 0).

## Impact

For AaveV2Plugin (and any future plugins that dont allow withdraw 0):

1. In every rebalance call, it must at least withdraw 1 wei from the plugin for the rebalance to work.
2. The plugin can not be removed or rebalanced when there is no balance in it. 

If such a plugin can not deposit for some reason (paused by gov, AaveV2Plu

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 3
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## withdraw-pattern-patterns.md
# Withdraw Pattern Security Patterns

## Overview

**Frequency**: 6 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 3 | 3 | 0 | 0 |

**Common Sources**: Sherlock, Code4rena, Cyfrin

---

## Detection Checklist

- [ ] Check for withdraw pattern vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: H-8: Interest component of underlying amount is not withdrawable using the `withdrawLend` function. Such amount is permanently locked in the BlueBerryBank contract

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/109 

## Found by 
berndartmueller, carrot, minhtrng, 0Kage, Jeiwan, chaduke, koxuan, Ruhum, cergyk, rbserver, stent, saian, XKET, GimelSec

## Summary
Soft vault shares are issued against interest bearing tokens issued by `Compound` protocol in exchange for underlying deposits. However, `withdrawLend` function caps the withdrawable amount to initial underlying deposited by user (`pos.underlyingAmount`). Capping underlying amount to initial underlying deposited would mean that a user can burn all his vault shares in `withdrawLend` function and only receive original underlying deposited.

Interest accrued component received from Soft vault (that rightfully belongs to the user) is no longer retrievable because the underlying vault shares are already burnt. Loss to the users is permanent as such interest amount sits permanently locked in Blueberry bank.

## Vulnerability Detail

[`withdrawLend` function in `BlueBerryBank`](https://github.com/sherlock-audit/2023-02-blueberry/blob/main/contracts/BlueBerryBank.sol#L669) allows users to withdraw underlying amount from `Hard` or `Soft` vaults. `Soft` vault shares are backed by interest bearing `cTokens` issued by Compound Protocol

User can request underlying by specifying `shareAmount`. When user tries to send the maximum `shareAmount` to withdraw all the lent amount, notice that the amount withdrawable is limited to the `pos.underlyingAmount` (original depos

*[Content truncated...]*

---

### Example 2: H-4: Lender force Loan become default

**Source**: Sherlock
**Protocol**: Cooler
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-cooler-judging/issues/23 

## Found by 
hansfriese, 0x52, wagmi, IllIllI, bin2chen, Zarf, dipp, libratus, simon135, Trumpero, zaskoh, TrungOre, cccz

## Summary
in ```repay()``` directly transfer the debt token to Lender, but did not consider that Lender can not accept the token (in contract blacklist), resulting in repay() always revert, and finally the Loan can only expire, Loan be default

## Vulnerability Detail
The only way for the borrower to get the collateral token back is to repay the amount owed via repay(). Currently in the repay() method transfers the debt token directly to the Lender.
This has a problem:
 if the Lender is blacklisted by the debt token now, the debtToken.transferFrom() method will fail and the repay() method will always fail and finally the Loan will default.
Example:
Assume collateral token = ETH,debt token = USDC, owner = alice
1.alice call request() to loan 2000 usdc , duration = 1 mon
2.bob call clear(): loanID =1
3.bob transfer loan[1].lender = jack by Cooler.approve/transfer  
  Note: jack has been in USDC's blacklist for some reason before
or bob in USDC's blacklist for some reason now, it doesn't need transfer 'lender')
4.Sometime before the expiration date, alice call repay(id=1) , it will always revert, Because usdc.transfer(jack) will revert
5.after 1 mon, loan[1] default, jack call defaulted() get collateral token

```solidity
    function repay (uint256 loanID, uint256 repaid) external

*[Content truncated...]*

---

### Example 3: [M-06] [Denial-of-Service] Contract Owner Could Block Users From Withdrawing Their Strike

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

### Example 4: [M-15] Malicious Stakers can grief Keepers

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

### Example 5: User's funds are locked temporarily in the PriorityPool contract

**Source**: Cyfrin
**Protocol**: Stake Link
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Description:** The protocol intended to utilize the deposit queue for withdrawal to minimize the stake/unstake interaction with the staking pool.
When a user wants to withdraw, they are supposed to call the function `PriorityPool::withdraw()` with the desired amount as a parameter.
```solidity
function withdraw(uint256 _amount) external {//@audit-info LSD token
    if (_amount == 0) revert InvalidAmount();
    IERC20Upgradeable(address(stakingPool)).safeTransferFrom(msg.sender, address(this), _amount);//@audit-info get LSD token from the user
    _withdraw(msg.sender, _amount);
}
```
As we can see in the implementation, the protocol pulls the `_amount` of LSD tokens from the user first and then calls `_withdraw()` where the actual withdrawal utilizing the queue is processed.
```solidity
function _withdraw(address _account, uint256 _amount) internal {
    if (poolStatus == PoolStatus.CLOSED) revert WithdrawalsDisabled();

    uint256 toWithdrawFromQueue = _amount <= totalQueued ? _amount : totalQueued;//@audit-info if the queue is not empty, we use that first
    uint256 toWithdrawFromPool = _amount - toWithdrawFromQueue;

    if (toWithdrawFromQueue != 0) {
        totalQueued -= toWithdrawFromQueue;
        depositsSinceLastUpdate += toWithdrawFromQueue;//@audit-info regard this as a deposit via the queue
    }

    if (toWithdrawFromPool != 0) {
        stakingPool.withdraw(address(this), address(this), toWithdrawFromPool);//@audit-info withdraw from

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-08-25-cyfrin-stake-link.md)

---

### Example 6: H-9: BlueBerryBank#withdrawLend will cause underlying token accounting error if soft/hard vault has withdraw fee

**Source**: Sherlock
**Protocol**: Blueberry
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/33 

## Found by 
y1cunhui, rvierdiiev, csanuragjain, Ruhum, evan, 0x52

## Summary

Soft/hard vaults can have a withdraw fee. This takes a certain percentage from the user when they withdraw. The way that the token accounting works in BlueBerryBank#withdrawLend, it will only remove the amount returned by the hard/soft vault from pos.underlying amount. If there is a withdraw fee, underlying amount will not be decrease properly and the user will be left with phantom collateral that they can still use.

## Vulnerability Detail

        // Cut withdraw fee if it is in withdrawVaultFee Window (2 months)
        if (
            block.timestamp <
            config.withdrawVaultFeeWindowStartTime() +
                config.withdrawVaultFeeWindow()
        ) {
            uint256 fee = (withdrawAmount * config.withdrawVaultFee()) /
                DENOMINATOR;
            uToken.safeTransfer(config.treasury(), fee);
            withdrawAmount -= fee;
        }

Both SoftVault and HardVault implement a withdraw fee. Here we see that withdrawAmount (the return value) is decreased by the fee amount.

        uint256 wAmount;
        if (address(ISoftVault(bank.softVault).uToken()) == token) {
            ISoftVault(bank.softVault).approve(
                bank.softVault,
                type(uint256).max
            );
            wAmount = ISoftVault(bank.softVault).withdraw(shareAmount);
        } else {
    

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 6
- Examples shown: 6
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## revert-on-0-transfer-patterns.md
# Revert On 0 Transfer Security Patterns

## Overview

**Frequency**: 5 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 0 | 5 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock

---

## Detection Checklist

- [ ] Check for revert on 0 transfer vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: M-1: `Cooler.roll()` wouldn't work as expected when `newCollateral = 0`.

**Source**: Sherlock
**Protocol**: Cooler
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-cooler-judging/issues/320 

## Found by 
hansfriese, cccz, Allarious, csanuragjain



## Summary
`Cooler.roll()` is used to increase the loan duration by transferring the additional collateral.

But there will be some problems when `newCollateral = 0`.

## Vulnerability Detail
```solidity
    function roll (uint256 loanID) external {
        Loan storage loan = loans[loanID];
        Request memory req = loan.request;

        if (block.timestamp > loan.expiry) 
            revert Default();

        if (!loan.rollable)
            revert NotRollable();

        uint256 newCollateral = collateralFor(loan.amount, req.loanToCollateral) - loan.collateral;
        uint256 newDebt = interestFor(loan.amount, req.interest, req.duration);

        loan.amount += newDebt;
        loan.expiry += req.duration;
        loan.collateral += newCollateral;
        
        collateral.transferFrom(msg.sender, address(this), newCollateral); //@audit 0 amount
    }
```

In `roll()`, it transfers the `newCollateral` amount of collateral to the contract.

After the borrower repaid most of the debts, `loan.amount` might be very small and `newCollateral` for the original interest might be 0 because of the rounding issue.

Then as we can see from this [one](https://github.com/d-xo/weird-erc20#revert-on-zero-value-transfers), some tokens might revert for 0 amount and `roll()` wouldn't work as expected.

## Impact
There will be 2 impacts.

1. When the 

*[Content truncated...]*

---

### Example 2: [M-01] Zero amount token transfers may cause a denial of service during liquidations

**Source**: Code4rena
**Protocol**: Particle Protocol
**Impact**: MEDIUM

**Details**:

Some ERC20 implementations revert on zero value transfers. Since liquidation rewards are based on a fraction of the available position's premiums, this may cause an accidental denial of service that prevents the successful execution of liquidations.

### Impact

Liquidations in the LAMM protocol are incentivized by a reward that is calculated as a fraction of the premiums available in the position.

<https://github.com/code-423n4/2023-12-particle/blob/a3af40839b24aa13f5764d4f84933dbfa8bc8134/contracts/protocol/ParticlePositionManager.sol#L348-L354>

```solidity
348:         // calculate liquidation reward
349:         liquidateCache.liquidationRewardFrom =
350:             ((closeCache.tokenFromPremium) * LIQUIDATION_REWARD_FACTOR) /
351:             uint128(Base.BASIS_POINT);
352:         liquidateCache.liquidationRewardTo =
353:             ((closeCache.tokenToPremium) * LIQUIDATION_REWARD_FACTOR) /
354:             uint128(Base.BASIS_POINT);
```

These amounts are later transferred to the caller, the liquidator, at the end of the `liquidatePosition()` function.

<https://github.com/code-423n4/2023-12-particle/blob/a3af40839b24aa13f5764d4f84933dbfa8bc8134/contracts/protocol/ParticlePositionManager.sol#L376-L378>

```solidity
376:         // reward liquidator
377:         TransferHelper.safeTransfer(closeCache.tokenFrom, msg.sender, liquidateCache.liquidationRewardFrom);
378:         TransferHelper.safeTransfer(closeCache.tokenTo, msg.sender, liquidateCache.liquidationReward

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-12-particle)

---

### Example 3: [M-13] Transaction revert if the baseToken does not support 0 value transfer when charging changeFee

**Source**: Code4rena
**Protocol**: Caviar
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2023-04-caviar/blob/cd8a92667bcb6657f70657183769c244d04c015c/src/PrivatePool.sol#L423
https://github.com/code-423n4/2023-04-caviar/blob/cd8a92667bcb6657f70657183769c244d04c015c/src/PrivatePool.sol#L651


## Vulnerability details

## Impact

Transaction revert if the baseToken does not support 0 value transfer when charging changeFee

## Proof of Concept

When call change via the PrivatePool.sol, the caller needs to the pay the change fee,

```solidity
	// calculate the fee amount
	(feeAmount, protocolFeeAmount) = changeFeeQuote(inputWeightSum);
}

// ~~~ Interactions ~~~ //

if (baseToken != address(0)) {
	// transfer the fee amount of base tokens from the caller
	ERC20(baseToken).safeTransferFrom(
		msg.sender,
		address(this),
		feeAmount
	);
```

calling changeFeeQuote(inputWeightSum)

```solidity
function changeFeeQuote(
	uint256 inputAmount
) public view returns (uint256 feeAmount, uint256 protocolFeeAmount) {
	// multiply the changeFee to get the fee per NFT (4 decimals of accuracy)
	uint256 exponent = baseToken == address(0)
		? 18 - 4
		: ERC20(baseToken).decimals() - 4;
	uint256 feePerNft = changeFee * 10 ** exponent;

	feeAmount = (inputAmount * feePerNft) / 1e18;
	protocolFeeAmount =
		(feeAmount * Factory(factory).protocolFeeRate()) /
		10_000;
}
```

if the feeAmount is 0,

the code below woud revert if the ERC20 token does not support 0 value transfer

```solidity
ERC20(baseToken).safeTransferFrom(
	msg.sender,
	ad

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-04-caviar)

---

### Example 4: [M-29] `ConvexStakingWrapper` deposits and withdraws will frequently be disabled if a token that doesn't allow zero value transfers will be added as a reward one

**Source**: Code4rena
**Protocol**: Concur Finance
**Impact**: MEDIUM

**Details**:

_Submitted by hyh_

If deposits and withdraws are done frequently enough, the reward update operation they invoke will deal mostly with the case when there is nothing to add yet, i.e. `reward.remaining` match the reward token balance.

If reward token doesn't allow for zero value transfers, the reward update function will fail on an empty incremental reward transfer, which is now done unconditionally, reverting the caller deposit/withdrawal functionality

### Proof of Concept

When ConvexStakingWrapper isn't paused, every deposit and withdraw update current rewards via `_checkpoint` function before proceeding:

[ConvexStakingWrapper.sol#L233](https://github.com/code-423n4/2022-02-concur/blob/main/contracts/ConvexStakingWrapper.sol#L233)<br>

[ConvexStakingWrapper.sol#L260](https://github.com/code-423n4/2022-02-concur/blob/main/contracts/ConvexStakingWrapper.sol#L260)<br>

`_checkpoint` calls `_calcRewardIntegral` for each of the reward tokens of the pid:

[ConvexStakingWrapper.sol#L220](https://github.com/code-423n4/2022-02-concur/blob/main/contracts/ConvexStakingWrapper.sol#L220)<br>

`_calcRewardIntegral` updates the incremental reward for the token, running the logic even if reward is zero, which is frequently the case:

[ConvexStakingWrapper.sol#L182](https://github.com/code-423n4/2022-02-concur/blob/main/contracts/ConvexStakingWrapper.sol#L182)<br>

If the reward token doesn't allow zero value transfers, this transfer will fail, reverting the corresponding deposit or wit

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-02-concur)

---

### Example 5: M-6: Tokens that revert of zero value transfers can cause reverts on liquidation

**Source**: Sherlock
**Protocol**: Teller Lender Groups Update Audit
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-11-teller-finance-update-judging/issues/51 

## Found by 
hash
### Summary

Tokens that revert of zero value transfers can cause reverts on liquidation

### Root Cause

In the [readme the team has mentioned](https://github.com/sherlock-audit/2024-11-teller-finance-update/tree/main?tab=readme-ov-file#q-if-you-are-integrating-tokens-are-you-allowing-only-whitelisted-tokens-to-work-with-the-codebase-or-any-complying-with-the-standard-are-they-assumed-to-have-certain-properties-eg-be-non-reentrant-are-there-any-types-of-weird-tokens-you-want-to-integrate) that they would like to know if any wierd token breaks their contract pools

In multiple places token amount which can become zero is transferred without checking the value is zero. This will cause these transactions to revert
https://github.com/sherlock-audit/2024-11-teller-finance-update/blob/0c8535728f97d37a4052d2a25909d28db886a422/teller-protocol-v2-audit-2024/packages/contracts/contracts/LenderCommitmentForwarder/extensions/LenderCommitmentGroup/LenderCommitmentGroup_Smart.sol#L699-L727
```solidity
            IERC20(principalToken).safeTransferFrom(
                msg.sender,
                address(this),
                amountDue + tokensToTakeFromSender - liquidationProtocolFee
            ); 
             
            address protocolFeeRecipient = ITellerV2(address(TELLER_V2)).getProtocolFeeRecipient();


              IERC20(principalToken).safeT

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 5
- Examples shown: 5
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29


---
## evm-gas-dos.md
# EVM, Gas & DoS Vulnerability Patterns

> **AI Skill**: This file contains EVM-specific, gas-related, and denial-of-service vulnerability patterns extracted from real audit reports.

## Quick Reference Index

| Category | Pattern | Severity |
|----------|---------|----------|
| [Gas](#1-gas-vulnerabilities) | Transaction Costs, L1L2 Gas | Medium-High |
| [DoS](#2-dos-vulnerabilities) | Replay Attacks, Block Gas Limit | Medium-High |
| [Context](#3-context-vulnerabilities) | msg.value, msg.sender | Medium-High |
| [Cross-Layer](#4-cross-layer-vulnerabilities) | L1L2 Sync, Upgrade Failures | High |
| [Data Location](#5-data-location-vulnerabilities) | Storage vs Memory, Calldata | Medium |

---

## 1. Gas Vulnerabilities

### 1.1 L1L2 Transaction Gas Miscalculation

**Vulnerability**: Incorrect gas check allows L1L2 transaction without sufficient gas for both overhead AND intrinsic costs.

**Context**: zkSync, Arbitrum, Optimism L1L2 bridging

**Formula**:
```
totalGasLimit = overhead + actualGasLimit
actualGasLimit = intrinsicCosts + executionCosts
```

**Pattern to Look For**:
```solidity
// VULNERABLE: Only checks minimal priority gas, not total required
require(
    getMinimalPriorityTransactionGasLimit(encodedLength, factoryDeps, gasPerPubdata)
    <= transaction.gasLimit,  // Only checks gasLimit, not total
    "Insufficient gas"
);

// Later: Transaction fails because overhead wasn't accounted
function processL1Tx() {
    let gasLimitForTx = _totalGasLimit - overhead;  // May underflow or leave nothing for execution
}
```

**Secure Pattern**:
```solidity
require(
    transaction.gasLimit >= getOverhead() + getIntrinsicCosts() + MIN_EXECUTION_GAS,
    "Insufficient total gas"
);
```

**Audit Checklist**:
- [ ] Does L1L2 gas calculation include overhead?
- [ ] Does it include intrinsic costs?
- [ ] Does it include minimum execution gas?
- [ ] Can underflow occur when subtracting overhead?

---

### 1.2 Unit Mismatch in Transaction Encoding

**Vulnerability**: Using different units (bytes vs words) in gas calculations causes 32x overcharge.

**Pattern to Look For**:
```solidity
// In Solidity: uses BOOTLOADER_TX_ENCODING_SPACE (bytes)
uint256 overheadForLength = Math.ceilDiv(
    _encodingLength * batchOverheadGas,
    BOOTLOADER_TX_ENCODING_SPACE  // e.g., 1_000_000 bytes
);

// In bootloader: uses BOOTLOADER_MEMORY_FOR_TXS (words = bytes/32)
let overheadForLength := ceilDiv(
    safeMul(txEncodeLen, totalBatchOverhead),
    BOOTLOADER_MEMORY_FOR_TXS()  // e.g., 31_250 words (1M/32)
);
// Result: overhead is 32x larger than expected!
```

**Audit Checklist**:
- [ ] Are units consistent across L1 and L2 calculations?
- [ ] Are bytes vs words clearly documented?
- [ ] Is there unit conversion where needed?

---

### 1.3 L1L2 Revert Consumes All Gas

**Vulnerability**: Near call opcode (zkSync) doesn't return unspent gas on REVERT, unlike EVM's 63/64 rule.

**Pattern to Look For**:
```yul
// zkSync near call - no gas refund on revert
// If L2 transaction reverts, ALL gas is consumed (like deprecated THROW)

function executeL1Tx() {
    // Uses near call - exempt from 63/64 rule
    // On REVERT: gas NOT returned to caller
    nearCallPanic()  // Consumes all remaining gas
}
```

**Impact**: Users lose entire gas payment even for simple reverts.

**Audit Checklist**:
- [ ] Does L1L2 path use near call?
- [ ] Is gas refunded on revert?
- [ ] Is this behavior documented for users?

---

## 2. DoS Vulnerabilities

### 2.1 EIP-155 Replay Attack

**Vulnerability**: Not enforcing EIP-155 chain ID signature allows transaction replay from other networks.

**Pattern to Look For**:
```rust
// VULNERABLE: Only checks chain ID if present in legacy tx
let should_check_chain_id = if matches!(
    transaction_type, TransactionType::LegacyTransaction
) && common_data.extract_chain_id().is_some()  // Only if chain_id exists!
{
    U256([1, 0, 0, 0])
} else {
    U256::zero()  // No chain ID check for EIP-155 unprotected txs
};
```

**Attack Scenario**:
1. User signs tx on network without EIP-155
2. Attacker replays tx on your network
3. Transaction executes, attacker profits from gas/value

**Secure Pattern**:
```rust
// ALWAYS require chain ID in signature
require(
    transaction.chain_id == EXPECTED_CHAIN_ID,
    "Invalid chain ID"
);
```

---

### 2.2 Wrong ProfitManager Causes Revert

**Vulnerability**: Single ProfitManager in constructor breaks multi-market systems.

**Pattern to Look For**:
```solidity
contract GuildToken {
    ProfitManager public profitManager;  // Set once in constructor
    
    constructor(address _profitManager) {
        profitManager = ProfitManager(_profitManager);  // Fixed forever!
    }
    
    // When called from different market's term:
    function notifyGaugeLoss(address gauge) external {
        require(msg.sender == address(profitManager), "UNAUTHORIZED");  // Reverts!
        // Different market uses different ProfitManager
    }
}
```

**Impact**: Cross-market operations fail, bad debt cannot be processed.

**Secure Pattern**:
```solidity
// Dynamic ProfitManager per gauge/market
mapping(address => address) public gaugeProfitManagers;

function notifyGaugeLoss(address gauge) external {
    require(msg.sender == gaugeProfitManagers[gauge], "UNAUTHORIZED");
}
```

---

### 2.3 Same-Block Stake/Unstake Exploit

**Vulnerability**: Flash loan stake  claim rewards  unstake in same block dilutes long-term staker rewards.

**Pattern to Look For**:
```solidity
// VULNERABLE: No cooldown between stake and claim/unstake
function stake(uint256 amount) external {
    stakes[msg.sender] += amount;
    // No timestamp recorded
}

function claimRewards() external {
    uint256 reward = calculateReward(msg.sender);
    _transfer(msg.sender, reward);
    // Attacker stakes 1M, claims, unstakes in same tx
}
```

**Attack Flow**:
1. Flash loan large amount
2. Stake into protocol
3. Trigger reward distribution (e.g., repay loan with interest)
4. Claim share of rewards
5. Unstake
6. Repay flash loan

**Secure Patterns**:
```solidity
// Option 1: Block same-block unstake
mapping(address => uint256) public stakeTimestamp;

function stake(uint256 amount) external {
    stakeTimestamp[msg.sender] = block.timestamp;
    stakes[msg.sender] += amount;
}

function unstake(uint256 amount) external {
    require(block.timestamp > stakeTimestamp[msg.sender], "Same block");
    // ...
}

// Option 2: Warm-up period for reward eligibility
function claimRewards() external {
    require(
        block.timestamp >= stakeTimestamp[msg.sender] + WARMUP_PERIOD,
        "Warmup not complete"
    );
}
```

---

## 3. Context Vulnerabilities

### 3.1 L2 ETH Inaccessible via L1 Transactions

**Vulnerability**: L1L2 transactions use msg.value from L1, ignoring user's L2 balance.

**Pattern to Look For**:
```solidity
// L1 -> L2 transaction
function requestL2Transaction(
    address _contractL2,
    uint256 _l2Value,
    bytes calldata _calldata
) external payable {
    // msg.value comes from L1 payment
    // User cannot use their existing L2 ETH balance
    require(msg.value >= _l2Value + baseCost, "Insufficient ETH");
}
```

**Impact**: User with ETH on L2 cannot use it for L1L2 transactions. Critical if malicious upgrade scheduled - users trapped.

**Audit Checklist**:
- [ ] Can users access L2 balances via L1 calls?
- [ ] Is there alternative withdrawal path?
- [ ] Can protocol freeze user L2 funds?

---

### 3.2 Deposit Limit Bypass via Failed Deposits

**Vulnerability**: Deposit limits not tracked until actually enforced; failed deposits can reset counters.

**Pattern to Look For**:
```solidity
// VULNERABLE: Only tracks if limit exists
function _verifyDepositLimit(address token, address depositor, uint256 amount, bool claiming) {
    if (_claiming) {
        totalDeposited[token][depositor] -= amount;  // Reduces counter
    } else {
        totalDeposited[token][depositor] += amount;
        // ONLY checks limit if already enforced
        if (limitData.depositLimitation) {
            require(totalDeposited[token][depositor] <= limitData.depositCap);
        }
    }
}
```

**Attack Scenario**:
1. Token has no limit initially
2. Attacker deposits large amount, intentionally fails
3. Later, token limit imposed
4. Attacker claims failed deposit  reduces counter
5. Attacker can now deposit more than cap

**Secure Pattern**:
```solidity
// Always track deposits, regardless of current limits
totalDeposited[token][depositor] += amount;  // Always track
if (limitData.depositLimitation) {
    require(totalDeposited <= cap);
}
```

---

### 3.3 EOA Repayers Affected by Changing Credit Multiplier

**Vulnerability**: EOA must mint CreditTokens before repaying; if bad debt generated between mint and repay, multiplier changes.

**Pattern to Look For**:
```solidity
function repay(bytes32 loanId) external {
    // User pre-calculated debt and minted exact CreditTokens
    uint256 loanDebt = getLoanDebt(loanId);  // Uses CURRENT creditMultiplier
    // If bad debt occurred since user calculated, this is now HIGHER
    
    CreditToken.transferFrom(msg.sender, address(this), loanDebt);
    // User doesn't have enough - reverts!
}

function getLoanDebt(bytes32 loanId) public view returns (uint256) {
    uint256 creditMultiplier = profitManager.creditMultiplier();
    // If creditMultiplier decreased, loanDebt increased
    return (borrowAmount * borrowCreditMultiplier) / creditMultiplier;
}
```

**Impact**: Honest repayers suddenly owe more due to others' bad debt.

**Secure Pattern**:
```solidity
// Allow atomic mint-and-repay
function repayWithPegToken(bytes32 loanId, uint256 pegTokenAmount) external {
    uint256 loanDebt = getLoanDebt(loanId);
    uint256 creditNeeded = _mintCredit(pegTokenAmount);  // Atomic
    require(creditNeeded >= loanDebt, "Insufficient");
    _repay(loanId, loanDebt);
}
```

---

## 4. Cross-Layer Vulnerabilities

### 4.1 L1/L2 Upgrade Synchronization Failure

**Vulnerability**: L2 upgrade fails but L1 protocol version advances anyway; state becomes inconsistent.

**Pattern to Look For**:
```solidity
// L1 executes batches without checking L2 upgrade outcome
function executeBatches(StoredBatchInfo[] calldata batches) external {
    // Process batches...
    
    if (batchWhenUpgradeHappened <= newTotalBatchesExecuted) {
        delete s.l2SystemContractsUpgradeTxHash;
        // Protocol version already advanced even if L2 upgrade failed!
    }
}
```

**Problem**: L2 upgrade tx has unique hash with nonce = protocol version. If L2 upgrade reverts, version is wrong.

**Secure Pattern**:
```solidity
function executeBatches(StoredBatchInfo[] calldata batches) external {
    // ...
    if (batchWhenUpgradeHappened <= newTotalBatchesExecuted) {
        // Check L2 upgrade success
        if (!proveL1ToL2TransactionStatus(upgradeHash, SUCCEEDED)) {
            s.protocolVersion = s.previousProtocolVersion;  // Rollback
        }
    }
}
```

---

### 4.2 Transaction Ordering in Cross-Layer Operations

**Vulnerability**: L1L2 message order assumptions can be violated by sequencer.

**Pattern to Look For**:
```solidity
// Assumes deposit processes before operation
function depositAndOperate() external {
    bridge.deposit(token, amount);  // L1  L2 message 1
    bridge.operate(data);            // L1  L2 message 2
    // Sequencer may reorder!
}
```

**Audit Checklist**:
- [ ] Are cross-layer operations atomic?
- [ ] Can sequencer reorder messages?
- [ ] Are nonces enforced for ordering?

---

## 5. Data Location Vulnerabilities

### 5.1 Storage vs Memory Pointer Confusion

**Vulnerability**: Using `memory` creates copy; changes don't persist.

**Pattern to Look For**:
```solidity
// VULNERABLE: Memory copy, changes lost
function updateBalance(address user) internal {
    UserData memory data = userData[user];  // Copy!
    data.balance += 100;
    // Changes NOT saved to storage
}

// CORRECT: Storage pointer, changes persist
function updateBalance(address user) internal {
    UserData storage data = userData[user];  // Pointer!
    data.balance += 100;
    // Changes saved
}
```

**Detection**: Look for `memory` keyword with subsequent modifications that seem intended to persist.

---

### 5.2 Calldata Modification Attempt

**Vulnerability**: Attempting to modify calldata parameter (read-only).

**Pattern to Look For**:
```solidity
// VULNERABLE: Calldata is immutable
function process(uint256[] calldata data) external {
    data[0] = 100;  // Compile error - good
    // But indirect modifications may not error
}
```

---

### 5.3 Log Sorter Queue Manipulation (zkSync)

**Vulnerability**: Sorted queue in log sorter can be manipulated to emit reverted logs.

**Technical Detail**:
```
Sorted queue pattern: wr rw wr rw
- Two adjacent logs with same timestamp
- Same written value
- All four logs are reverted
- But queue adds 2nd and 4th to result (wrong!)

Required constraint: First popped = write only (not consecutive rollbacks)
```

---

## 6. Finding Report Template

Based on Cyfrin's finding layout:

```markdown
### [S-#] TITLE (Root Cause + Impact)

**Description:** 
Clear explanation of the vulnerability mechanism.

**Impact:** 
- Severity: Critical/High/Medium/Low
- Who is affected
- Financial impact estimate

**Proof of Concept:**
```solidity
// Minimal reproduction code
function testVulnerability() public {
    // Setup
    // Attack
    // Assert impact
}
```

**Recommended Mitigation:** 
Specific code changes to fix the issue.
```

---

## Audit Integration Prompts

### For Gas Audits
```
Analyze this cross-layer transaction for:
1. Gas calculation completeness (overhead + intrinsic + execution)
2. Unit consistency (bytes vs words)
3. Gas refund behavior on revert
4. Potential gas griefing vectors
```

### For DoS Audits
```
Check this protocol for denial of service vectors:
1. EIP-155 replay protection
2. Flash loan stake/unstake in same block
3. Manager/registry single points of failure
4. Block gas limit issues in loops
```

### For L1L2 Audits
```
Review cross-layer synchronization for:
1. Message ordering guarantees
2. Upgrade failure handling
3. Protocol version consistency
4. User fund accessibility during failures
```

---

## Cross-Reference Sources

| Pattern | Source Report | Protocol |
|---------|--------------|----------|
| L1L2 Gas | Code4rena 2023-10 | zkSync |
| Unit Mismatch | Code4rena 2023-10 | zkSync |
| Revert Gas | Code4rena 2023-10 | zkSync |
| EIP-155 Replay | Code4rena 2023-10 | zkSync |
| Wrong Manager | Code4rena 2023-12 | ECG |
| Same-Block Stake | Code4rena 2023-12 | ECG |
| L2 ETH Access | Code4rena 2023-10 | zkSync |
| Deposit Limits | Code4rena 2023-10 | zkSync |
| Credit Multiplier | Code4rena 2023-12 | ECG |
| L1/L2 Sync | Code4rena 2023-10 | zkSync |

---

## Related Skills

- [vulnerability-patterns.md](vulnerability-patterns.md) - General patterns
- [l2-security.md](l2-security.md) - L2-specific patterns
- [defi-vulnerabilities.md](defi-vulnerabilities.md) - DeFi patterns


