# Approve Security Patterns

## Overview

**Frequency**: 18 occurrences (0.04% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 9 | 9 | 0 | 0 |

**Common Sources**: Code4rena, Spearbit, Sherlock, Codehawks

---

## Detection Checklist

- [ ] Check for approve vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Decrease allowance when it is already set a non-zero value

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: HIGH

**Details**:

## Security Analysis Report

## Severity
**High Risk**

## Context
- AxelarFacet.sol#L71
- LibAsset.sol#L52
- FusePoolZap.sol#L64
- Executor.sol#L312

## Description
Non-standard tokens like USDT will revert the transaction when a contract or a user tries to approve an allowance when the spender allowance is already set to a non-zero value. For that reason, the previous allowance should be decreased before increasing the allowance in the related function.

- Performing a direct overwrite of the value in the allowances mapping is susceptible to front-running scenarios by an attacker (e.g., an approved spender). As OpenZeppelin mentioned, `safeApprove` should only be called when setting an initial allowance or when resetting it to zero.

### Function
```solidity
function safeApprove(
    IERC20 token,
    address spender,
    uint256 value
) internal {
    // safeApprove should only be called when setting an initial allowance,
    // or when resetting it to zero. To increase and decrease it, use
    // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'.
    require(
        (value == 0) || (token.allowance(address(this), spender) == 0),
        "SafeERC20: approve from non-zero to non-zero allowance"
    );
    _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
}
```

### Instances of the Issue
There are four instances of this issue:

1. **AxelarFacet.sol** is directly using the `approve` function, which does not check the return value 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 2: [H-04] Approvals not cleared after key transfer

**Source**: Code4rena
**Protocol**: Unlock Protocol
**Impact**: HIGH

**Details**:

_Submitted by cmichel_

The locks implement three different approval types, see `onlyKeyManagerOrApproved` for an overview:

*   key manager (map `keyManagerOf`)
*   single-person approvals (map `approved`). Cleared by `_clearApproval` or `_setKeyManagerOf`
*   operator approvals (map `managerToOperatorApproved`)

The `MixinTransfer.transferFrom` requires any of the three approval types in the `onlyKeyManagerOrApproved` modifier on the tokenId to authenticate transfers from `from`.

Notice that if the `to` address previously had a key but it expired only the `_setKeyManagerOf` call is performed, which does not clear `approved` if the key manager was already set to 0:

```solidity
function transferFrom(
  address _from,
  address _recipient,
  uint _tokenId
)
  public
  onlyIfAlive
  hasValidKey(_from)
  onlyKeyManagerOrApproved(_tokenId)
{
  // @audit this is skipped if user had a key that expired
  if (toKey.tokenId == 0) {
    toKey.tokenId = _tokenId;
    _recordOwner(_recipient, _tokenId);
    // Clear any previous approvals
    _clearApproval(_tokenId);
  }

  if (previousExpiration <= block.timestamp) {
    // The recipient did not have a key, or had a key but it expired. The new expiration is the sender's key expiration
    // An expired key is no longer a valid key, so the new tokenID is the sender's tokenID
    toKey.expirationTimestamp = fromKey.expirationTimestamp;
    toKey.tokenId = _tokenId;

    // Reset the key Manager to the key owner
    // @audit  doesn't c

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-11-unlock)

---

### Example 3: [H-02] Approved spender can spend too many tokens

**Source**: Code4rena
**Protocol**: BadgerDAO
**Impact**: HIGH

**Details**:

_Submitted by cmichel, also found by WatchPug, jonah1005, gzeon, and TomFrench_
The `approve` function has not been overridden and therefore uses the internal *shares*, whereas `transfer(From)` uses the rebalanced amount.

#### Impact
The approved spender may spend more tokens than desired. In fact, the approved amount that can be transferred keeps growing with `pricePerShare`.

Many contracts also use the same amount for the `approve` call as for the amount they want to have transferred in a subsequent `transferFrom` call, and in this case, they approve an amount that is too large (as the approved `shares` amount yields a higher rebalanced amount).

#### Recommended Mitigation Steps

The `_allowances` field should track the rebalanced amounts such that the approval value does not grow. (This does not actually require overriding the `approve` function.)
In `transferFrom`, the approvals should then be subtracted by the *transferred* `amount`, not the `amountInShares`:

```solidity
// _allowances are in rebalanced amounts such that they don't grow
// need to subtract the transferred amount
_approve(sender, _msgSender(), _allowances[sender][_msgSender()].sub(amount, "ERC20: transfer amount exceeds allowance"));
```

**[tabshaikh (Badger) confirmed and resolved](https://github.com/code-423n4/2021-10-badgerdao-findings/issues/43#issuecomment-957197908):**
 > Fix here: https://github.com/Badger-Finance/rebasing-ibbtc/pull/7

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-10-badgerdao)

---

### Example 4: H-1: If a user approves junior vault tokens to WithdrawPeriphery, anyone can withdraw/redeem his/her token

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

### Example 5: A user can steal an already transfered and bridged reSDL lock because of approval

**Source**: Codehawks
**Protocol**: stake.link
**Impact**: HIGH

**Details**:

### Relevant GitHub Links
<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-12-stake-link/blob/main/contracts/core/sdlPool/SDLPoolPrimary.sol#L172-L199">https://github.com/Cyfrin/2023-12-stake-link/blob/main/contracts/core/sdlPool/SDLPoolPrimary.sol#L172-L199</a>

<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-12-stake-link/blob/main/contracts/core/sdlPool/SDLPoolSecondary.sol#L259-L281">https://github.com/Cyfrin/2023-12-stake-link/blob/main/contracts/core/sdlPool/SDLPoolSecondary.sol#L259-L281</a>


## Summary
The reSDL token approval is not deleted when the lock is bridged to an other chain

## Vulnerability Details
When a reSDL token is bridged to an other chain, the `handleOutgoingRESDL()` function is called to make the state changes into the `sdlPool` contract. The function executes the following:

```
    function handleOutgoingRESDL(
        address _sender,
        uint256 _lockId,
        address _sdlReceiver
    )
        external
        onlyCCIPController
        onlyLockOwner(_lockId, _sender)
        updateRewards(_sender)
        updateRewards(ccipController)
        returns (Lock memory)
    {
        Lock memory lock = locks[_lockId];

        delete locks[_lockId].amount;
        delete lockOwners[_lockId];
        balances[_sender] -= 1;

        uint256 totalAmount = lock.amount + lock.boostAmount;
        effectiveBalances[_sender] -= totalAmount;
        effectiveBalances[ccipController] += totalAmount;


*[Content truncated...]*

---

### Example 6: H-11: Sense PTs can never be redeemed

**Source**: Sherlock
**Protocol**: Illuminate
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-10-illuminate-judging/issues/117 

## Found by 
IllIllI, neumo, Ruhum, 0x52

## Summary

Sense PTs can never be redeemed


## Vulnerability Detail

Most of the protocols that require the user of the `Converter` contract have code that approves the `Converter` for that protocol, but there is no such approval for Sense.


## Impact

_Permanent freezing of funds_

Users will be able to lend and mint using Sense, but when it's time for Illuminate to redeem the Sense PTs, the call will always revert, meaning the associated underlying will be locked in the contract, and users that try to redeem their Illuminate PTs will have lost principal.

While the Illuminate project does have an emergency `withdraw()` function that would allow an admin to rescue the funds and manually distribute them, this would not be trustless and defeats the purpose of having a smart contract.


## Code Snippet
The Sense flavor of `redeem()` requires the use of the `Converter`:
```solidity
// File: src/Redeemer.sol : Redeemer.redeem()   #1

366            // Get the starting balance to verify the amount received afterwards
367            uint256 starting = IERC20(u).balanceOf(address(this));
368    
369            // Get the divider from the adapter
370            ISenseDivider divider = ISenseDivider(ISenseAdapter(a).divider());
371    
372            // Redeem the tokens from the Sense contract
373            ISenseDivider(divider).redeem(a, s, amount);
374   

*[Content truncated...]*

---

### Example 7: Receiver doesn't always reset allowance

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: HIGH

**Details**:

## Security Report

## Severity
**High Risk**

## Context
Receiver.sol#L224-L297

## Description
The function `_swapAndCompleteBridgeTokens()` of Receiver resets the approval to the executor at the end of an ERC20 transfer. However, if there is insufficient gas, the approval is not reset. This allows the executor to access any tokens (of the same type) left in the Receiver.

```solidity
function _swapAndCompleteBridgeTokens(...) {
    ...
    if (LibAsset.isNativeAsset(assetId)) {
        ...
    } else { // case 2: ERC20 asset
        ...
        token.safeIncreaseAllowance(address(executor), amount);
        if (reserveRecoverGas && gasleft() < _recoverGas) {
            token.safeTransfer(receiver, amount);
            ...
            return; // no safeApprove 0
        }
        try executor.swapAndCompleteBridgeTokens{...} {
            ...
        }
        token.safeApprove(address(executor), 0);
    }
}
```

## Recommendation
Only increase the allowance if sufficient gas is available, for example in the following way:

```solidity
function _swapAndCompleteBridgeTokens(...) {
    ...
    if (LibAsset.isNativeAsset(assetId)) {
        ...
    } else { // case 2: ERC20 asset
        ...
        - token.safeIncreaseAllowance(address(executor), amount);
        if (reserveRecoverGas && gasleft() < _recoverGas) {
            token.safeTransfer(receiver, amount);
            ...
            return;
        }
        + token.safeIncreaseAllowance(address(executor), amount);
 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-retainer1-Spearbit-Security-Review.pdf)

---

### Example 8: Multiple ERC4626Router and ERC4626RouterBase functions will always revert

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
- `ERC4626Router.sol#L49-58`
- `ERC4626RouterBase.sol#L47`
- `ERC4626RouterBase.sol#L60`

## Description
The intention of the `ERC4626Router.sol` functions is that they are approval-less ways to deposit and redeem:

> For the below, no approval needed, assumes vault is already max approved.

As long as the user has approved the `TRANSFER_PROXY` for WETH, this works for the `depositToVault` function:
- WETH is transferred from the user to the router with `pullTokens`.
- The router approves the vault for the correct amount of WETH.
- `vault.deposit()` is called, which uses `safeTransferFrom` to transfer WETH from the router into the vault.

However, for the `redeemMax` function, it doesn't work:
- Approves the vault to spend the router's WETH.
- `vault.redeem()` is called, which tries to transfer vault tokens from the router to the vault, and then mints withdraw proxy tokens to the receiver.

This error occurs assuming that the vault tokens would be burned, in which case the logic would work. But since they are transferred into the vault until the end of the epoch, we require approvals.

The same issue also exists in these two functions in `ERC4626RouterBase.sol`:
- `redeem()`: this is where the incorrect approval lives, so the same issue occurs when it is called directly.
- `withdraw()`: the same faulty approval exists in this function.

## Recommendation
`redeemMax` should follow the same flow as `deposit` to make this work:
- `redeemMax` 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 9: Facets approve arbitrary addresses for ERC20 tokens

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
Across the following files and lines:
- `AcrossFacet.sol#L103`
- `AmarokFacet.sol#L145`
- `AnyswapFacet.sol#L127`
- `ArbitrumBridge-Facet.sol#L111`
- `CBridgeFacet.sol#L103`
- `GenericBridgeFacet.sol#L111`
- `GnosisBridgeFacet.sol#L119`
- `HopFacet.sol#L106`
- `HyphenFacet.sol#L101`
- `NXTPFacet.sol#L127`
- `OmniBridgeFacet.sol#L88`
- `OptimismBridge-Facet.sol#L100`
- `PolygonBridgeFacet.sol#L101`
- `StargateFacet.sol#L229`
- `WormholeFacet.sol#L94`

## Description
All the facets pointed above approve an address for an ERC20 token, where both these values are provided by the user:

```solidity
LibAsset.maxApproveERC20(IERC20(token), router, amount);
```

The parameter names change depending on the context. So for any ERC20 token that the `LifiDiamond` contract holds, the user can:
- Call any of the functions in these facets to approve another address for that token.
- Use the approved address to transfer tokens out of the `LifiDiamond` contract.

**Note:** Normally, there shouldnt be any tokens in the `LiFi Diamond` contract, so the risk is limited. Also, see "Hardcode bridge addresses via immutable."

## Recommendation
For each bridge facet, the bridge approval contract address is already known. Store these addresses in an immutable or a storage variable instead of taking them as user input. Only approve and interact with these pre-defined addresses.

## LiFi
Fixed with PR #79, PR #102, PR #103

## Spearbit
Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 10: [M-19] `HolographERC721.approve` not EIP-721 compliant

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: MEDIUM

**Details**:

[HolographERC721.sol#L272](https://github.com/code-423n4/2022-10-holograph/blob/24bc4d8dfeb6e4328d2c6291d20553b1d3eff00b/src/enforcer/HolographERC721.sol#L272)<br>

According to EIP-721, we have for `approve`:

```solidity
///  Throws unless `msg.sender` is the current NFT owner, or an authorized
///  operator of the current owner.
```

An operator in the context of EIP-721 is someone who was approved via `setApprovalForAll`:

```solidity
/// @notice Enable or disable approval for a third party ("operator") to manage
///  all of `msg.sender`'s assets
/// @dev Emits the ApprovalForAll event. The contract MUST allow
///  multiple operators per owner.
/// @param _operator Address to add to the set of authorized operators
/// @param _approved True if the operator is approved, false to revoke approval
function setApprovalForAll(address _operator, bool _approved) external;
```

Besides operators, there are also approved addresses for a token (for which `approve` is used). However, approved addresses can only transfer the token, see for instance the `safeTransferFrom` description:

```solidity
/// @dev Throws unless `msg.sender` is the current owner, an authorized
///  operator, or the approved address for this NFT.
```

`HolographERC721` does not distinguish between authorized operators and approved addresses when it comes to the `approve` function. Because `_isApproved(msg.sender, tokenId)` is used there, an approved address can approve another address, which is a violation of the

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 11: [H-03] Approval for NFT transfers is not removed after transfer

**Source**: Code4rena
**Protocol**: Visor
**Impact**: HIGH

**Details**:

_Submitted by cmichel, also found by gpersoon, and pauliax_

The `Visor.transferERC721` does not reset the approval for the NFT.

An approved delegatee can move the NFT out of the contract once.
It could be moved to a market and bought by someone else who then deposits it again to the same vault.
The first delegatee can steal the NFT and move it out of the contract a second time.

Recommend resetting the approval on transfer.

**[xyz-ctrl (Visor) confirmed](https://github.com/code-423n4/2021-05-visorfinance-findings/issues/48#issuecomment-856953219):**
> We will be mitigating this issue for our next release and before these experimental features are introduced in platform.
> PR pending

**[ztcrypto (Visor) commented](https://github.com/code-423n4/2021-05-visorfinance-findings/issues/48#issuecomment-889192312):**
> duplicate of above ones and fixed

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-05-visorfinance)

---

### Example 12: M-17: Did Not Approve To Zero First

**Source**: Sherlock
**Protocol**: Notional
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/59 

## Found by 
xiaoming90, 0x52, csanuragjain

## Summary

Allowance was not set to zero first before changing the allowance.

## Vulnerability Detail

Some ERC20 tokens (like USDT) do not work when changing the allowance from an existing non-zero allowance value. For example Tether (USDT)'s `approve()` function will revert if the current approval is not zero, to protect against front-running changes of approvals.

The following  attempt to call the `approve()` function without setting the allowance to zero first.

https://github.com/sherlock-audit/2022-09-notional/blob/main/leveraged-vaults/contracts/utils/TokenUtils.sol#L18

```solidity
File: TokenUtils.sol
18:     function checkApprove(IERC20 token, address spender, uint256 amount) internal {
19:         if (address(token) == address(0)) return;
20: 
21:         IEIP20NonStandard(address(token)).approve(spender, amount);
22:         _checkReturnCode();
23:     }
```

However, if the token involved is an ERC20 token that does not work when changing the allowance from an existing non-zero allowance value, it will break a number of key functions or features of the protocol as the `TokenUtils.checkApprove` function is utilised extensively within the vault as shown below.

https://github.com/sherlock-audit/2022-09-notional/blob/main/leveraged-vaults/contracts/vaults/balancer/internal/pool/TwoTokenPoolUtils.sol#L159

```solidity
File: TwoTokenPoolUtils.

*[Content truncated...]*

---

### Example 13: [M-01] ``FULL_RESTRICTED`` Stakers can bypass restriction through approvals

**Source**: Code4rena
**Protocol**: Ethena Labs
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2023-10-ethena/blob/ee67d9b542642c9757a6b826c82d0cae60256509/contracts/StakedUSDe.sol#L225-L238><br>
<https://github.com/code-423n4/2023-10-ethena/blob/ee67d9b542642c9757a6b826c82d0cae60256509/contracts/StakedUSDe.sol#L245-L248>

The `StakedUSDe` contract implements a method to `SOFTLY` or `FULLY` restrict user address, and either transfer to another user or burn.

However there is an underlying issue. A fully restricted address is supposed to be unable to withdraw/redeem, however this issue can be walked around via the approve mechanism.

The openzeppelin `ERC4626` contract allows approved address to withdraw and redeem on behalf of another address so far there is an approval.

```solidity
    function redeem(uint256 shares, address receiver, address owner) public virtual override returns (uint256) 
```

Blacklisted Users can explore this loophole to redeem their funds fully. This is because in the overridden `_withdraw` function, the token owner is not checked for restriction.

```solidity
  function _withdraw(address caller, address receiver, address _owner, uint256 assets, uint256 shares)
    internal
    override
    nonReentrant
    notZero(assets)
    notZero(shares)
  {
    if (hasRole(FULL_RESTRICTED_STAKER_ROLE, caller) || hasRole(FULL_RESTRICTED_STAKER_ROLE, receiver)) {
      revert OperationNotAllowed();
    }
```

Also in the overridden `_beforeTokenTransfer` there is a clause added to allow burning from restricted addresses:

```s

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-10-ethena)

---

### Example 14: Seaport auctions not compatible with USDT

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

## Security Analysis Report

## Severity
**Medium Risk**

## Context
`CollateralToken.sol#L173`

## Description
As per the ERC20 specification, the `approve()` function is expected to return a boolean:

```solidity
function approve(address _spender, uint256 _value) public returns (bool success)
```

However, USDT deviates from this standard, and its `approve()` method does not have a return value. Hence, if USDT is used as a payment token, the following line reverts in `validateOrder()` as it expects return data but doesn't receive it:

```solidity
paymentToken.approve(address(transferProxy), s.LIEN_TOKEN.getOwed(stack));
```

## Recommendation
Use Solmate's `safeApprove()` function to accommodate USDT's `approve()`:

```solidity
paymentToken.safeApprove(address(transferProxy), s.LIEN_TOKEN.getOwed(stack));
```

## Additional Information
- **Astaria:** Fixed in PR339.
- **Spearbit:** Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review-July.pdf)

---

### Example 15: approve() function can be front-ran resulting in token theft

**Source**: Spearbit
**Protocol**: Liquid Collective
**Impact**: MEDIUM

**Details**:

## Security Advisory

## Severity
**Medium Risk**

## Context
- SharesManager.1.sol#L143
- WLSETH.1.sol#L116-L120

## Description
The `approve()` function has a known race condition that can lead to token theft. If a user calls the `approve` function a second time on a spender that was already allowed, the spender can front-run the transaction and call `transferFrom()` to transfer the previous value and still receive the authorization to transfer the new value.

## Recommendation
Consider implementing functionality that allows a user to increase and decrease their allowance similar to Lido's implementation. This will help prevent users from losing funds from front-running attacks.

- **Alluvial:** Recommendation implemented in SPEARBIT/9.
- **Spearbit:** Acknowledged. Note: if you want to follow the same logic of OpenZeppelin ERC20 implementation, the `_spendAllowance` in both SharesManager and WLSETH should execute `emit Approval(owner, spender, amount);`.
- **Alluvial:** Fixed in PR 151.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LiquidCollective-Spearbit-Security-Review.pdf)

---

### Example 16: [M-29] TRSRY susceptible to loan / withdraw confusion

**Source**: Code4rena
**Protocol**: Olympus DAO
**Impact**: MEDIUM

**Details**:

_Submitted by Trust, also found by 0xSky, datapunk, and tonisives_

<https://github.com/code-423n4/2022-08-olympus/blob/main/src/modules/TRSRY.sol#L64-L102><br>

Treasury allocates approvals in the withdrawApproval mapping which is set via setApprovalFor(). In both withdrawReserves() and in getLoan(), \_checkApproval() is used to verify user has enough approval and subtracts the withdraw / loan amount. Therefore, there is no differentiation in validation between loan approval and withdraw approval. Policies which will use getLoan() (currently none) can simply withdraw the tokens without bookkeeping it as a loan.

### Proof of Concept

1.  Policy P has getLoan permission
2.  setApprovalFor(policy, token, amount) was called to grant P permission to loan amount
3.  P calls withdrawReserves(address, token, amount) and directly withdraws the funds without registering as loan

### Recommended Mitigation Steps

A separate mapping called loanApproval should be implemented, and setLoanApprovalFor() will set it, getLoan() will reduce loanApproval balance.

**[ind-igo (Olympus) confirmed, but disagreed with severity and commented](https://github.com/code-423n4/2022-08-olympus-findings/issues/75#issuecomment-1239657706):**
 > Confirmed. Good suggestion. Would put as low risk though.

**[0xean (judge) commented](https://github.com/code-423n4/2022-08-olympus-findings/issues/75#issuecomment-1250396074):**
 > Currently thinking Medium is appropriate for this issue, but will circle back on it

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-08-olympus)

---

### Example 17: H-1: Escrow approvals are not cleared when club is transferred allowing for abuse after transfer

**Source**: Sherlock
**Protocol**: Footium
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-04-footium-judging/issues/289 

## Found by 
0x52, BenRai, Brenzee, CMierez, J4de, MiloTruck, PokemonAuditSimulator, Quantish, cergyk, ctf\_sec, mstpr-brainbot, pengun, sashik\_eth, shaka, shogoki, toshii
## Summary

Escrow approvals remain even across club token transfers. This allows a malicious club owners to sell their club then drain everything after sale due to previous approvals.

## Vulnerability Detail

ERC20 and ERC721 token approval persist regardless of the owner of the club. The result is that approvals set by one owner can be accessed after a token has been sold or transferred. This allows the following attack:

1) User A owns clubId = 1
2) User A sets approval to themselves
3) User A sells clubId = 1 to User B
4) User A uses persistent approval to drain all players and tokens

## Impact

Malicious approvals can be used to drain club after sale

## Code Snippet

[FootiumEscrow.sol#L75-L81](https://github.com/sherlock-audit/2023-04-footium/blob/main/footium-eth-shareable/contracts/FootiumEscrow.sol#L75-L81)

[FootiumEscrow.sol#L90-L96](https://github.com/sherlock-audit/2023-04-footium/blob/main/footium-eth-shareable/contracts/FootiumEscrow.sol#L90-L96)

## Tool used

Manual Review

## Recommendation

Club escrow system needs to be redesigned

---

### Example 18: [M-23] Function `withdraw()` and `redeem()` in ERC4626RouterBase would revert always because they have unnecessary allowance setting

**Source**: Code4rena
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

<https://github.com/AstariaXYZ/astaria-gpl/blob/4b49fe993d9b807fe68b3421ee7f2fe91267c9ef/src/ERC4626RouterBase.sol#L48><br>
<https://github.com/AstariaXYZ/astaria-gpl/blob/4b49fe993d9b807fe68b3421ee7f2fe91267c9ef/src/ERC4626RouterBase.sol#L62>

Functions withdraw() and redeem()  in ERC4626RouterBase  are used to withdraw user funds from vaults and they call `vault.withdraw()` and `vault.redeem()` and logics in vault transfer user shares and user required to give spending allowance for vault and there is no need for ERC4626RouterBase to set approval for vault and because those approved tokens won't be used and code uses `safeApprove()` so next calls to `withdraw()` and `redeem()` would revert because code would tries to change allowance amount while it's not zero. those functions would revert always and AstariaRouter uses them and user won't be able to use those function and any other protocol integrating with Astaria calling those function would have broken logic. also if UI interact with protocol with router functions then UI would have broken parts too. and functions in router support users to set slippage allowance and without them users have to interact with vault directly and they may lose funds because of the slippage.

### Proof of Concept

This is `withdraw()` and `redeem()` code in ERC4626RouterBase:

      function withdraw(
        IERC4626 vault,
        address to,
        uint256 amount,
        uint256 maxSharesOut
      ) public payable virtual override return

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-astaria)

---

## Statistics

- Total findings analyzed: 18
- Examples shown: 18
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

