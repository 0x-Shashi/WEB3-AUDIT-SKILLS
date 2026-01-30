# Front-Running Security Patterns

## Overview

**Frequency**: 106 occurrences (0.21% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 39 | 67 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Spearbit, MixBytes, Trust Security

---

## Detection Checklist

- [ ] Check for front-running vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Lack of transferId Verification Allows an Attacker to Front-Run Bridge Transfers

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Severity: Critical Risk  

## Context  
- `NomadFacet.sol#L99-L149`  
- `BridgeRouter.sol#L176-L199`  
- `BridgeRouter.sol#L347-L381`  

## Description  
The `onReceive()` function does not verify the integrity of `transferId` against all other parameters. Although the `onlyBridgeRouter` modifier checks that the call originates from another BridgeRouter (assuming a correct configuration of the whitelist) to the `onReceive()` function, it does not check that the call originates from another Connext Diamond.

This allows anyone to send arbitrary data to `BridgeRouter.sendToHook()`, which is later interpreted as the `transferId` on Connext’s `NomadFacet.sol` contract. This can be abused by a front-running attack as described in the following scenario:

- **Alice** is a bridge user and makes an honest call to transfer funds over to the destination chain.  
- **Bob** does not make a transfer but instead calls the `sendToHook()` function with the same `_extraData` but passes an `_amount` of `1 wei`.  
- Both Alice and Bob have their tokens debited on the source chain and must wait for the Nomad protocol to optimistically verify incoming `TransferToHook` messages.  
- Once the messages have been replicated onto the destination chain, Bob processes the message before Alice, causing `onReceive()` to be called on the same `transferId`.  
- However, because `_amount` is not verified against the `transferId`, Alice receives significantly fewer tokens, and the `s.reconciledTransfers` m

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 2: [H-01] Attacker can frontrun a victim's `mint`+`add` transaction to steal NFT

**Source**: Code4rena
**Protocol**: Canto Identity Protocol
**Impact**: HIGH

**Details**:

[CidNFT.sol#L147](https://github.com/code-423n4/2023-01-canto-identity/blob/main/src/CidNFT.sol#L147)<br>
[CidNFT.sol#L165](https://github.com/code-423n4/2023-01-canto-identity/blob/main/src/CidNFT.sol#L165)<br>
[CidNFT.sol#L237](https://github.com/code-423n4/2023-01-canto-identity/blob/main/src/CidNFT.sol#L237)

High - an attacker can steal deposited NFTs from victims using the `mint()` + `add()` functionality in `CidNFT.sol`

### Proof of Concept

One of the core features of CID Protocol is the ability for users to attach Subprotocol NFTs to their `CidNFT`. The `CidNFT` contract custodies these attached NFTs, and they are regarded as "traits" of the user.

The protocol currently includes functionality for a user to mint a `CidNFT` as their identity and then optionally add a subprotocol NFT to that `CidNFT` in the same transaction. This occurs in the `mint()` function of `CidNFT.sol`, which takes a byte array of `add()` parameters and includes a loop where `add()` can be repeatedly called with these parameters to attach subprotocol NFTs to the `CidNFT`.

```

function mint(bytes[] calldata _addList) external {
    _mint(msg.sender, ++numMinted); 
    bytes4 addSelector = this.add.selector;
    for (uint256 i = 0; i < _addList.length; ++i) {
        (bool success /*bytes memory result*/, ) = address(this)
            .delegatecall(abi.encodePacked(addSelector, _addList[i]));
        if (!success) revert AddCallAfterMintingFailed(i);
    }
}
```

One of the arguments for `add(

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-canto-identity)

---

### Example 3: [H-09] BathPair.sol#rebalancePair() can be front run to steal the pending rebalancing amount

**Source**: Code4rena
**Protocol**: Rubicon
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-05-rubicon/blob/8c312a63a91193c6a192a9aab44ff980fbfd7741/contracts/rubiconPools/BathToken.sol#L756-L759


## Vulnerability details

https://github.com/code-423n4/2022-05-rubicon/blob/8c312a63a91193c6a192a9aab44ff980fbfd7741/contracts/rubiconPools/BathToken.sol#L756-L759

```solidity
function underlyingBalance() public view returns (uint256) {
    uint256 _pool = IERC20(underlyingToken).balanceOf(address(this));
    return _pool.add(outstandingAmount);
}
```

https://github.com/code-423n4/2022-05-rubicon/blob/8c312a63a91193c6a192a9aab44ff980fbfd7741/contracts/rubiconPools/BathToken.sol#L294-L303

```solidity
function removeFilledTradeAmount(uint256 amt) external onlyPair {
    outstandingAmount = outstandingAmount.sub(amt);
    emit LogRemoveFilledTradeAmount(
        IERC20(underlyingToken),
        amt,
        underlyingBalance(),
        outstandingAmount,
        totalSupply
    );
}
```

For `BathToken`, there will be non-underlyingToken assets sitting on the contract that have filled to the contract and are awaiting rebalancing by strategists.

We assume the rebalance will happen periodically, between one rebalance to the next rebalance, `underlyingBalance()` will decrease over time as the orders get filled, so that the price per share will get lower while the actual equity remain relatively stable. This kind of price deviation will later be corrected by rebalancing.

Every time a `BathPair.sol#rebalancePair()` get ca

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-rubicon)

---

### Example 4: [H-06] Gas price spikes cause the selected operator to be vulnerable to frontrunning and be slashed

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

### Example 5: [H-03] `fillOrder` executor can be front-run by the order creator by changing order's `limitPrice_e36`, the executor's assets can be stolen

**Source**: Code4rena
**Protocol**: Init Capital
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2024-01-init-capital-invitational/blob/main/contracts/hook/MarginTradingHook.sol#L539-L563> 

<https://github.com/code-423n4/2024-01-init-capital-invitational/blob/main/contracts/hook/MarginTradingHook.sol#L387>

`limitPrice_e36` acts as slippage protection for the order creator, depending on the trade/order position (whether long or short). A higher or lower limit price impacts the `tokenOut` amount that needs to be transferred to the order's creator. However, when the executor executes `fillOrder`, it can be front-run by the order creator to update `limitPrice_e36` and steal tokens from the executor.

### Proof of Concept

When `fillOrder` is executed, it will calculate the `amtOut` that needs to be transferred to `order.recipient` by calling `_calculateFillOrderInfo`.

<https://github.com/code-423n4/2024-01-init-capital-invitational/blob/main/contracts/hook/MarginTradingHook.sol#L532-L564>

```solidity
    function _calculateFillOrderInfo(Order memory _order, MarginPos memory _marginPos, address _collToken)
        internal
        returns (uint amtOut, uint repayShares, uint repayAmt)
    {
        (repayShares, repayAmt) = _calculateRepaySize(_order, _marginPos);
        uint collTokenAmt = ILendingPool(_marginPos.collPool).toAmtCurrent(_order.collAmt);
        // NOTE: all roundings favor the order owner (amtOut)
        if (_collToken == _order.tokenOut) {
            if (_marginPos.isLongBaseAsset) {
                // long eth hold eth


*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-init-capital-invitational)

---

### Example 6: [H-04] Initial pool deposit can be stolen

**Source**: Code4rena
**Protocol**: InsureDAO
**Impact**: HIGH

**Details**:

_Submitted by cmichel, also found by WatchPug_

Note that the `PoolTemplate.initialize` function, called when creating a market with `Factory.createMarket`, calls a vault function to transfer an initial deposit amount (`conditions[1]`) *from* the initial depositor (`_references[4]`):

```solidity
// PoolTemplate
function initialize(
     string calldata _metaData,
     uint256[] calldata _conditions,
     address[] calldata _references
) external override {
     // ...

     if (_conditions[1] > 0) {
          // @audit vault calls asset.transferFrom(_references[4], vault, _conditions[1])
          _depositFrom(_conditions[1], _references[4]);
     }
}

function _depositFrom(uint256 _amount, address _from)
     internal
     returns (uint256 _mintAmount)
{
     require(
          marketStatus == MarketStatus.Trading && paused == false,
          "ERROR: DEPOSIT_DISABLED"
     );
     require(_amount > 0, "ERROR: DEPOSIT_ZERO");

     _mintAmount = worth(_amount);
     // @audit vault calls asset.transferFrom(_from, vault, _amount)
     vault.addValue(_amount, _from, address(this));

     emit Deposit(_from, _amount, _mintAmount);

     //mint iToken
     _mint(_from, _mintAmount);
}
```

The initial depositor needs to first approve the vault contract for the `transferFrom` to succeed.

An attacker can then frontrun the `Factory.createMarket` transaction with their own market creation (it does not have access restrictions) and create a market *with different parameters* but st

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-insure)

---

### Example 7: Owner of a bad ShortRecord can front-run flagShort calls AND liquidateSecondary and prevent liquidation

**Source**: Codehawks
**Protocol**: DittoETH
**Impact**: HIGH

**Details**:

### Relevant GitHub Links
<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-09-ditto/blob/main/contracts/facets/MarginCallPrimaryFacet.sol#L47">https://github.com/Cyfrin/2023-09-ditto/blob/main/contracts/facets/MarginCallPrimaryFacet.sol#L47</a>

<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-09-ditto/blob/a93b4276420a092913f43169a353a6198d3c21b9/contracts/libraries/AppStorage.sol#L101">https://github.com/Cyfrin/2023-09-ditto/blob/a93b4276420a092913f43169a353a6198d3c21b9/contracts/libraries/AppStorage.sol#L101</a>

<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-09-ditto/blob/a93b4276420a092913f43169a353a6198d3c21b9/contracts/facets/ERC721Facet.sol#L162C17-L162C17">https://github.com/Cyfrin/2023-09-ditto/blob/a93b4276420a092913f43169a353a6198d3c21b9/contracts/facets/ERC721Facet.sol#L162C17-L162C17</a>

<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-09-ditto/blob/a93b4276420a092913f43169a353a6198d3c21b9/contracts/libraries/LibShortRecord.sol#L132">https://github.com/Cyfrin/2023-09-ditto/blob/a93b4276420a092913f43169a353a6198d3c21b9/contracts/libraries/LibShortRecord.sol#L132</a>

<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-09-ditto/blob/a93b4276420a092913f43169a353a6198d3c21b9/contracts/libraries/LibShortRecord.sol#L224C10-L224C10">https://github.com/Cyfrin/2023-09-ditto/blob/a93b4276420a092913f43169a353a6198d3c21b9/contracts/libraries/LibShortR

*[Content truncated...]*

---

### Example 8: H-3: CryptoPunks NFTs may be stolen via deposit frontrunning

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

### Example 9: H-1: If a user approves junior vault tokens to WithdrawPeriphery, anyone can withdraw/redeem his/her token

**Source**: Sherlock
**Protocol**: Rage Trade
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-10-rage-trade-judging/issues/79 

## Found by 
simon135, cccz, Nyx, GimelSec, clems4ever

## Summary

If users want to withdraw/redeem tokens by WithdrawPeriphery, they should approve token approval to WithdrawPeriphery, then call `withdrawToken()` or `redeemToken()`.
But if users approve `dnGmxJuniorVault` to WithdrawPeriphery, anyone can withdraw/redeem his/her token.

## Vulnerability Detail

Users should approve `dnGmxJuniorVault` before calling `withdrawToken()` or `redeemToken()`:

```solidity
    function withdrawToken(
        address from,
        address token,
        address receiver,
        uint256 sGlpAmount
    ) external returns (uint256 amountOut) {
        // user has approved periphery to use junior vault shares
        dnGmxJuniorVault.withdraw(sGlpAmount, address(this), from);
...

    function redeemToken(
        address from,
        address token,
        address receiver,
        uint256 sharesAmount
    ) external returns (uint256 amountOut) {
        // user has approved periphery to use junior vault shares
        dnGmxJuniorVault.redeem(sharesAmount, address(this), from);
...
```

For better user experience, we always use `approve(WithdrawPeriphery, type(uint256).max)`. It means that if Alice approves the max amount, anyone can withdraw/redeem her tokens anytime.
Another scenario is that if Alice approves 30 amounts, she wants to call `withdrawToken` to withdraw 30 tokens. But in this case Alice sho

*[Content truncated...]*

---

### Example 10: H-2: Attacker will prevent any raffles by calling `WinnablesTicketManager::cancelRaffle` before admin starts raffle

**Source**: Sherlock
**Protocol**: Winnables Raffles
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-08-winnables-raffles-judging/issues/57 

## Found by 
0rpse, 0x0bserver, 0x73696d616f, 0xAadi, 0xShahilHussain, 0xarno, 0xbrivan, AllTooWell, BitcoinEason, Bluedragon, CatchEmAll, KaligoAudits, Oblivionis, Offensive021, PNS, PTolev, Paradox, S3v3ru5, Silvermist, TessKimy, Trident-Audits, ZC002, aman, araj, charles\_\_cheerful, denzi\_, dimi6oni, dimulski, dinkras\_, dobrevaleri, durov, eeshenggoh, frndz0ne, iamnmt, jennifer37, neko\_nyaa, ogKapten, p0wd3r, philmnds, phoenixv110, rsam\_eth, sakshamguruji, shaflow01, shikhar, shui, tjonair, utsav, vinica\_boy, y4y
### Summary

The [`WinnablesTicketManager::cancelRaffle`](https://github.com/sherlock-audit/2024-08-winnables-raffles/blob/main/public-contracts/contracts/WinnablesTicketManager.sol#L278) function is vulnerable to abuse because it is an external function that allows anyone to cancel a raffle if its status is set to PRIZE_LOCKED. An attacker could exploit this by repeatedly calling `cancelRaffle` whenever a new raffle is available to be started, effectively preventing any raffles from ever being initiated.

### Root Cause

The root cause of this issue lies in the design of the function:
1. The function is external, meaning it can be called by anyone.
2. When called, it checks the underlying function `WinnablesTicketManager::_checkShouldCancel`, which allows cancellation of a raffle if the [status is PRIZE_LOCKED](https://github.com/sherlock-audit/2024-08-winnables-raffles/

*[Content truncated...]*

---

### Example 11: DoS of an account using frontrun

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

### Example 12: [H-02] Order's creator can update `tokenOut` to arbitrary token

**Source**: Code4rena
**Protocol**: Init Capital
**Impact**: HIGH

**Details**:

When an order is created, it checks whether the `order.tokenOut` is equal to `marginPos.baseAsset` or `_tokenOut` is equal to `marginPos.quoteAsset`. However, when `tokenOut` is updated via `updateOrder`, it can be changed to an arbitrary token. This has the potential to be exploited by changing `tokenOut` to a high-value token right before the executor executes the `fillOrder`.

### Proof of Concept

It can be observed that order's creator can update `order.tokenOut` to arbitrary token.

<https://github.com/code-423n4/2024-01-init-capital-invitational/blob/main/contracts/hook/MarginTradingHook.sol#L504-L526>

```solidity
    function updateOrder(
        uint _posId,
        uint _orderId,
        uint _triggerPrice_e36,
        address _tokenOut,
        uint _limitPrice_e36,
        uint _collAmt
    ) external {
        _require(_collAmt != 0, Errors.ZERO_VALUE);
        Order storage order = __orders[_orderId];
        _require(order.status == OrderStatus.Active, Errors.INVALID_INPUT);
        uint initPosId = initPosIds[msg.sender][_posId];
        _require(initPosId != 0, Errors.POSITION_NOT_FOUND);
        MarginPos memory marginPos = __marginPositions[initPosId];
        uint collAmt = IPosManager(POS_MANAGER).getCollAmt(initPosId, marginPos.collPool);
        _require(_collAmt <= collAmt, Errors.INPUT_TOO_HIGH);

        order.triggerPrice_e36 = _triggerPrice_e36;
        order.limitPrice_e36 = _limitPrice_e36;
        order.collAmt = _collAmt;
        order.tokenOu

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-init-capital-invitational)

---

### Example 13: [H-02] The first disputer might lose funds although his dispute is valid

**Source**: Code4rena
**Protocol**: Angle Protocol
**Impact**: HIGH

**Details**:

Users can dispute the current tree using `disputeTree()` and the governor refunds the dispute funds if the dispute is valid in `resolveDispute()`.

```solidity
    function disputeTree(string memory reason) external {
        if (block.timestamp >= endOfDisputePeriod) revert InvalidDispute();
        IERC20(disputeToken).safeTransferFrom(msg.sender, address(this), disputeAmount);
        disputer = msg.sender;
        emit Disputed(reason);
    }

    /// @notice Resolve the ongoing dispute, if any
    /// @param valid Whether the dispute was valid
    function resolveDispute(bool valid) external onlyGovernorOrGuardian {
        if (disputer == address(0)) revert NoDispute();
        if (valid) {
            IERC20(disputeToken).safeTransfer(disputer, disputeAmount);
            // If a dispute is valid, the contract falls back to the last tree that was updated
            _revokeTree();
        } else {
            IERC20(disputeToken).safeTransfer(msg.sender, disputeAmount);
            endOfDisputePeriod = _endOfDisputePeriod(uint48(block.timestamp));
        }
        disputer = address(0);
        emit DisputeResolved(valid);
    }
```

But `disputeTree()` can be called again by another disputer although there is an active disputer and `resolveDispute()` refunds to the last disputer only.

In the worst case, a valid disputer might lose the dispute funds by malicious frontrunners.

1.  A valid disputer creates a dispute using `disputeTree()`.
2.  As it's valid, the govern

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-dev-test-repo)

---

### Example 14: TRST-H-4 First depositor can steal asset tokens of others

**Source**: Trust Security
**Protocol**: Stella
**Impact**: HIGH

**Details**:

**Description:**
The first depositor can be front run by an attacker and as a result will lose a considerable 
part of the assets provided.
When the pool has no share supply, in `_mintInternal()`, the amount of shares to be minted is 
equal to the assets provided. An attacker can abuse of this situation and profit of the 
rounding down operation when calculating the amount of shares if the supply is non-zero. 
```solidity
        function _mintInternal(address _receiver, uint _balanceIncreased, uint _totalAsset
             ) internal returns (uint mintShares) {
                unfreezeTime[_receiver] = block.timestamp + mintFreezeInterval;
        if (freezeBuckets.interval > 0) {
             FreezeBuckets.addToFreezeBuckets(freezeBuckets, _balanceIncreased.toUint96());
        }
                 uint _totalSupply = totalSupply();
                    if (_totalAsset == 0 || _totalSupply == 0) {
                     mintShares = _balanceIncreased + _totalAsset;
                 } else {
             mintShares = (_balanceIncreased * _totalSupply) / _totalAsset;
             }
            if (mintShares == 0) {
        revert ZeroAmount();
        }
        _mint(_receiver, mintShares);
        }
``` 
Consider the following scenario.
1. Alice wants to deposit 2M * 1e6 USDC to a pool.
2. Bob observes Alice's transaction, frontruns to deposit 1 wei USDC to mint 1 wei share, and 
transfers 1 M * 1e6 USDC to the pool.
3. Alice's transaction is executed, since **_totalAsset = 1M *

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Trust Security/2023-05-29-Stella.md)

---

### Example 15: TRST-H-3 The liquidated person can make the liquidator lose premium by adding collateral in advance

**Source**: Trust Security
**Protocol**: Stella
**Impact**: HIGH

**Details**:

**Description:**
When the position with **debtRatioE18 >= 1e18** or **startLiqTimestamp ! = 0**, the position can 
be liquidated. On liquidation, the liquidator needs to pay premium, but the profit is related 
to the position's health factor and **deltaTime**, and when **discount == 0**, the liquidator loses 
premium.
```solidity
            uint deltaTime;
            // 1.1 check the amount of time since position is marked
            if (pos.startLiqTimestamp > 0) {
                 deltaTime = Math.max(deltaTime, block.timestamp - pos.startLiqTimestamp);
            }
            // 1.2 check the amount of time since position is past the deadline
             if (block.timestamp > pos.positionDeadline) {
                    deltaTime = Math.max(deltaTime, block.timestamp - pos.positionDeadline);
            }
            // 1.3 cap time-based discount, as configured
              uint timeDiscountMultiplierE18 = Math.max(
                IConfig(config).minLiquidateTimeDiscountMultiplierE18(),
                     ONE_E18 - deltaTime * IConfig(config).liquidateTimeDiscountGrowthRateE18()
            );
            // 2. calculate health-based discount factor
            uint curHealthFactorE18 = (ONE_E18 * ONE_E18) /
             getPositionDebtRatioE18(_positionManager, _user, _posId);
                 uint minDesiredHealthFactorE18 = IConfig(config).minDesiredHealthFactorE18s(strategy);
            // 2.1 interpolate linear health discount factor (according to the diagr

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Trust Security/2023-05-29-Stella.md)

---

### Example 16: [H-01] Challenges can be frontrun with de-leveraging to cause lossses for challengers

**Source**: Code4rena
**Protocol**: Frankencoin
**Impact**: HIGH

**Details**:

Challenges, once created, cannot be closed. Thus once a challenge is created, the challenger has already transferred in a collateral amount and is thus open for losing their collateral to a bidding war which will most likely close below market price, since otherwise buying from the market would be cheaper for bidders.

Position owners can take advantage of this fact and frontrun a `launchChallenge` transaction with an `adjustPrice` transaction. The `adjustPrice` function lets the user lower the price of the position, and can pass the collateral check by sending collateral tokens externally.

As a worst case scenario, consider a case where a position is open with 1 ETH collateral and 1500 ZCHF minted. A challenger challenges the position and the owner frontruns the challenger by sending the contract 1500 ZCHF and calling `repay()` and then calling `adjustPrice` with value 0, all in one transaction with a contract. Now, the price in the contract is set to 0, and the collateral check passes since the outstanding minted amount is 0. The challenger's transaction gets included next, and they are now bidding away their collateral, since any amount of bid will pass the avert collateral check.

The position owner themselves can backrun the same transaction with a bid of 1 wei and take all the challenger's collateral, since every bid checks for the `tryAvertChallenge` condition.

```solidity
if (_bidAmountZCHF * ONE_DEC18 >= price * _collateralAmount)
```

Since price is set to 0, any 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-04-frankencoin)

---

### Example 17: [H-01] Anyone can frontrun fixed price signature mints to waste claim ticket

**Source**: ZachObront
**Protocol**: Sound.Xyz
**Impact**: HIGH

**Details**:

When NFTs are minted using the `FixedPriceSignatureMinterV2.sol` contract, the user is able to input any quantity to mint. As long as this amount is less than the quantity that has been signed for, the transaction will succeed and the claim ticket will be used up.

The signed ticket includes the following details:

- Buyer
- Mint ID
- Claim Ticket
- Signed Quantity
- Affiliate

When `mintTo()` is called, these values are all filled in entirely from the arguments passed to the function, as we can see here:

```solidity
bytes32 digest = keccak256(
abi.encodePacked(
"\x19\x01",
DOMAIN_SEPARATOR(),
keccak256(abi.encode(MINT_TYPEHASH, to, mintId, claimTicket, signedQuantity, affiliate))
)
);
```

This leaves us with two facts:

1. The signature used by Alice to claim her NFTs could equally have been used by Bob to send NFTs to Alice, because there is no reference to who the `msg.sender` is when checking the signature.

2. The signature used to claim `signedQuantity` NFTs could also have been used to claim any amount `x` (where 0 < `x` <= `signedQuantity`), because there is no reference to the quantity claimed in the signature.

As a result, any user who is claiming a large number of NFTs is vulnerable to being frontrun. Bob can watch the mempool for Alice's transaction, copy the signature, and replay his own version of the transaction, sending just 1 NFT to Alice instead of the full `signedQuantity`.

Once this action has been taken, Alice's ticket will be claimed, and she will be

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/ZachObront/2023-04-12-Sound.xyz.md)

---

### Example 18: [H-10] First vault depositor can steal other's assets

**Source**: Code4rena
**Protocol**: Popcorn
**Impact**: HIGH

**Details**:

The first depositor can be front run by an attacker and as a result will lose a considerable part of the assets provided.

The vault calculates the amount of shares to be minted upon deposit to every user via the `convertToShares()` function:

```solidity
function deposit(uint256 assets, address receiver)
    public
    nonReentrant
    whenNotPaused
    syncFeeCheckpoint
    returns (uint256 shares)
{
    if (receiver == address(0)) revert InvalidReceiver();

    uint256 feeShares = convertToShares(
        assets.mulDiv(uint256(fees.deposit), 1e18, Math.Rounding.Down)
    );

    shares = convertToShares(assets) - feeShares;

    if (feeShares > 0) _mint(feeRecipient, feeShares);

    _mint(receiver, shares);

    asset.safeTransferFrom(msg.sender, address(this), assets);

    adapter.deposit(assets, address(this));

    emit Deposit(msg.sender, receiver, assets, shares);
}

function convertToShares(uint256 assets) public view returns (uint256) {
    uint256 supply = totalSupply(); // Saves an extra SLOAD if totalSupply is non-zero.

    return
        supply == 0
            ? assets
            : assets.mulDiv(supply, totalAssets(), Math.Rounding.Down);
}

```

When the pool has no share supply, the amount of shares to be minted is equal to the assets provided. An attacker can abuse this situation and profit off the rounding down operation when calculating the amount of shares if the supply is non-zero. This attack is enabled by the following components: frontrunning, rou

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-popcorn)

---

### Example 19: Initialization functions can be front-run

**Source**: TrailOfBits
**Protocol**: Advanced Blockchain
**Impact**: HIGH

**Details**:

## Type: Timing

## Difficulty: Medium

### Target: Throughout the contracts

### Description
The `CrosslayerPortal` contracts have initializer functions that can be front-run, allowing an attacker to incorrectly initialize the contracts. Due to the use of the `delegatecall` proxy pattern, these contracts cannot be initialized with their own constructors, and they have initializer functions:

```solidity
function initialize() public initializer {
    __Ownable_init();
    __Pausable_init();
    __ReentrancyGuard_init();
}
```

*Figure 1.1: The `initialize` function in `MsgSender:126-130`*

An attacker could front-run these functions and initialize the contracts with malicious values. This issue affects the following system contracts:

- `contracts/core/BridgeAggregator`
- `contracts/core/InvestmentStrategyBase`
- `contracts/core/MosaicHolding`
- `contracts/core/MosaicVault`
- `contracts/core/MosaicVaultConfig`
- `contracts/core/functionCalls/MsgReceiverFactory`
- `contracts/core/functionCalls/MsgSender`
- `contracts/nfts/Summoner`
- `contracts/protocols/aave/AaveInvestmentStrategy`
- `contracts/protocols/balancer/BalancerV1Wrapper`
- `contracts/protocols/balancer/BalancerVaultV2Wrapper`
- `contracts/protocols/bancor/BancorWrapper`
- `contracts/protocols/compound/CompoundInvestmentStrategy`
- `contracts/protocols/curve/CurveWrapper`
- `contracts/protocols/gmx/GmxWrapper`
- `contracts/protocols/sushiswap/SushiswapLiquidityProvider`
- `contracts/protocols/synapse/ISynapseSwap`
-

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/trailofbits/publications/blob/master/reviews/AdvancedBlockchain.pdf)

---

### Example 20: Winning pods can be frontrun with large deposits

**Source**: ConsenSys
**Protocol**: PoolTogether - Pods
**Impact**: HIGH

**Details**:

#### Description


`Pod.depositTo()` grants users shares of the pod pool in exchange for `tokenAmount` of `token`.


**code/pods-v3-contracts/contracts/Pod.sol:L266-L288**



```
function depositTo(address to, uint256 tokenAmount)
    external
    override
    returns (uint256)
{
    require(tokenAmount > 0, "Pod:invalid-amount");

    // Allocate Shares from Deposit To Amount
    uint256 shares = \_deposit(to, tokenAmount);

    // Transfer Token Transfer Message Sender
    IERC20Upgradeable(token).transferFrom(
        msg.sender,
        address(this),
        tokenAmount
    );

    // Emit Deposited
    emit Deposited(to, tokenAmount, shares);

    // Return Shares Minted
    return shares;
}

```
The winner of a prize pool is typically determined by an off-chain random number generator, which requires a request to first be made on-chain. The result of this RNG request can be seen in the mempool and frontrun. In this case, an attacker could identify a winning `Pod` contract and make a large deposit, diluting existing user shares and claiming the entire prize.


#### Recommendation


The modifier `pauseDepositsDuringAwarding` is included in the `Pod` contract but is unused.


**code/pods-v3-contracts/contracts/Pod.sol:L142-L148**



```
modifier pauseDepositsDuringAwarding() {
    require(
        !IPrizeStrategyMinimal(\_prizePool.prizeStrategy()).isRngRequested(),
        "Cannot deposit while prize is being awarded"
    );
    \_;
}

```
Add this modifier to the `depos

*[Content truncated...]*

**Reference**: [View Original Finding](https://consensys.net/diligence/audits/2021/03/pooltogether-pods/)

---

### Example 21: [M-05] BkdLocker#depositFees() can be front run to steal the newly added rewardToken

**Source**: Code4rena
**Protocol**: Backd
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-05-backd/blob/2a5664d35cde5b036074edef3c1369b984d10010/protocol/contracts/BkdLocker.sol#L90-L100


## Vulnerability details

Every time the `BkdLocker#depositFees()` gets called, there will be a surge of rewards per locked token for the existing stakeholders.

This enables a well-known attack vector, in which the attacker will take a large portion of the shares before the surge, then claim the rewards and exit immediately.

While the `_WITHDRAW_DELAY` can be set longer to mitigate this issue in the current implementation, it is possible for the admin to configure it to a very short period of time or even `0`.

In which case, the attack will be very practical and effectively steal the major part of the newly added rewards.

https://github.com/code-423n4/2022-05-backd/blob/2a5664d35cde5b036074edef3c1369b984d10010/protocol/contracts/BkdLocker.sol#L90-L100

```solidity
function depositFees(uint256 amount) external override {
    require(amount > 0, Error.INVALID_AMOUNT);
    require(totalLockedBoosted > 0, Error.NOT_ENOUGH_FUNDS);
    IERC20(rewardToken).safeTransferFrom(msg.sender, address(this), amount);

    RewardTokenData storage curRewardTokenData = rewardTokenData[rewardToken];

    curRewardTokenData.feeIntegral += amount.scaledDiv(totalLockedBoosted);
    curRewardTokenData.feeBalance += amount;
    emit FeesDeposited(amount);
}
```

### PoC

Given:

- Current `totalLockedBoosted()` is `100,000 govToken`;
- Pending dis

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-backd)

---

### Example 22: Decrementing the quorum in Oracle in some scenarios can open up a frontrunning/backrunning opportunity for some oracle members

**Source**: Spearbit
**Protocol**: Liquid Collective
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
- Oracle.1.sol#L338-L370
- Oracle.1.sol#L260
- Oracle.1.sol#L156 @ 030b52feb5af2dd2ad23da0d512c5b0e55eb8259

## Description
Assume there are 2 groups of oracle members A and B where they have voted for report variants \(V_a\) and \(V_b\) respectively. Let's also assume the count for these variants \(C_a\) and \(C_b\) are equal and are the highest variant vote counts among all possible variants. If the Oracle admin changes the quorum to a number less than or equal to \(C_a + 1 = C_b + 1\), any oracle member can backrun this transaction by the admin to decide which report variant \(V_a\) or \(V_b\) gets pushed to the River. This is because when a lower quorum is submitted by the admin and there exist two variants that have the highest number of votes, in the `_getQuorumReport` function the returned `isQuorum` parameter would be false since `repeat == 0` is false:

```solidity
return (maxval >= _quorum && repeat == 0, variants[maxind]);
```

Note that this issue also exists in the commit hash 030b52feb5af2dd2ad23da0d512c5b0e55eb8259 and can be triggered by the admin either by calling `setQuorum` or `addMember` when the abovementioned conditions are met. Also, note that the free oracle member agent can frontrun the admin transaction to decide the quorum earlier in the scenario above. Thus this way `_getQuorumReport` would actually return that it is a quorum.

## Recommendation
This issue is similar to "The reportBeacon is prone to front-runnin

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LiquidCollective-Spearbit-Security-Review.pdf)

---

### Example 23: [M-03] Grieving attack by failing user’s transactions

**Source**: Code4rena
**Protocol**: Backed Protocol
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L486


## Vulnerability details

## Impact

An attacker can apply grieving attack by preventing users from interacting with some of the protocol functions. In other words whenever a user is going to reduce his debt, or buy and reduce his debt in one tx, it can be failed by the attacker.

## Proof of Concept
In the following scenario, I am explaining how it is possible to fail user's transaction to reduce their debt fully. Failing other transaction (buy and reduce the debt in one tx) can be done similarly.

 - Suppose Alice (an honest user) has debt of 1000 `PaprToken` and she intends to repay her debt fully: 
 - So, she calls the function `reduceDebt` with the following parameters:
   - `account`: Alice's address
   - `asset`: The NFT which was used as collateral
   - `amount`: 1000 * 10**18 (decimal of `PaprToken` is 18).
```
function reduceDebt(address account, ERC721 asset, uint256 amount) external override {
        _reduceDebt({account: account, asset: asset, burnFrom: msg.sender, amount: amount});
    }
```
https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L148
 - Bob (a malicious user who owns a small amount of `PaprToken`) notices Alice's transaction in the Mempool. So, Bob applies front-run attack and calls the function `reduceDebt` with the following parameters:
   - `account`: Alice's addre

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-backed)

---

### Example 24: [M-03] Frontrunning for unallowed minting of Short and Long tokens

**Source**: Code4rena
**Protocol**: prePO
**Impact**: MEDIUM

**Details**:

<https://github.com/prepo-io/prepo-monorepo/blob/feat/2022-12-prepo/apps/smart-contracts/core/contracts/PrePOMarket.sol#L68>

<https://github.com/prepo-io/prepo-monorepo/blob/feat/2022-12-prepo/apps/smart-contracts/core/contracts/PrePOMarket.sol#L109>

### Vulnerability details

#### Unallowed minting of Short and Long tokens

The documentation states that minting of the Short and Long tokens should only be done by the governance.

```solidity
File: apps/smart-contracts/core/contracts/interfaces/IPrePOMarket.sol
73:    * Minting will only be done by the team, and thus relies on the `_mintHook`
74:    * to enforce access controls. This is also why there is no fee for `mint()`
75:    * as opposed to `redeem()`.
```

The problem is, that as long as the **\_mintHook** is not set via **setMintHook**, everyone can use the mint function and mint short and long tokens.
At the moment the **\_mintHook** is not set in the contructor of PrePOMarket and so the transaction that will set the **\_mintHook** can be front run to mint short and long tokens for the attacker.

### Proof of Concept

<https://github.com/prepo-io/prepo-monorepo/blob/feat/2022-12-prepo/apps/smart-contracts/core/contracts/PrePOMarket.sol#L68>

<https://github.com/prepo-io/prepo-monorepo/blob/feat/2022-12-prepo/apps/smart-contracts/core/contracts/PrePOMarket.sol#L109>

This test shows how an attacker could frontrun the **setMintHook** function:

```node
  describe('# mint front run attack', () => {
    let mintHook: Fa

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-prepo)

---

### Example 25: [M-12] Attacker can grift syndicate staking by staking a small amount

**Source**: Code4rena
**Protocol**: Stakehouse Protocol
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-11-stakehouse/blob/a0558ed7b12e1ace1fe5c07970c7fc07eb00eebd/contracts/liquid-staking/LiquidStakingManager.sol#L882><br>
<https://github.com/code-423n4/2022-11-stakehouse/blob/23c3cf65975cada7fd2255a141b359a6b31c2f9c/contracts/syndicate/Syndicate.sol#L22>

`LiquidStakingManager._autoStakeWithSyndicate` always stakes a fixed amount of 12 ETH. However, `Syndicate.stake` only allows a total staking amount of 12 ETH and reverts otherwise:

```solidity
if (_sETHAmount + totalStaked > 12 ether) revert InvalidStakeAmount();
```

An attacker can abuse this and front-run calls to `mintDerivatives` (which call `_autoStakeWithSyndicate` internally). Because `Syndicate.stake` can be called by everyone, he can stake the minimum amount (1 gwei) such that the `mintDerivatives` call fails.

### Proof Of Concept

As soon as there is a `mintDerivatives` call in the mempool, an attacker (that owns sETH) calls `Syndicate.stake` with an amount of 1 gwei. `_autoStakeWithSyndicate` will still call `Syndicate.stake` with 12 ether. However, `_sETHAmount + totalStaked > 12 ether` will then be true, meaning that the call will revert.

### Recommended Mitigation Steps

Only allow staking through the LiquidStakingManager, i.e. add access control to `Syndicate.stake`.


**[vince0656 (Stakehouse) confirmed](https://github.com/code-423n4/2022-11-stakehouse-findings/issues/146#issuecomment-1329482113)**


***

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-stakehouse)

---

## Statistics

- Total findings analyzed: 106
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

