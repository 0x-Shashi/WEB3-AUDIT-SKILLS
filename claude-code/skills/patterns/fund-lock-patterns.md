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

