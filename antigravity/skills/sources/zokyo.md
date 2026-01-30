# Zokyo - Audit Findings

## Overview

**Total Findings**: 3,376 (6.68% of database)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 468 | 659 | 2249 | 0 |

## Common Vulnerability Types

| Vulnerability | Count |
|--------------|-------|
| Liquidation | 1 |
| Grief Attack | 1 |
| Front-Running | 1 |

---

## Notable Findings

### 1. A vault can be added to OracleVaultController after receiving deposits leading to incorrect price

**Protocol**: Vaultcraft | **Impact**: HIGH

**Severity**: High	

**Status**: Acknowledged

**Description**

The function `addVault()` within the `OracleVaultController.sol` smart contract is used to add a vault to the controller to be able to update its price. The function always initialize the price to 1e18 (1:1) -- This is to prevent pausing the vault on the first update, so the `addVault()` function should be called before the vault has received any deposits. However, there not exist any check to ensure that there were no previous deposits when adding a new vault:
```solidity
function addVault(address vault) external onlyOwner { 
   ...

---

### 2. convertToAssets is receiving assets decimals instead of shares decimals, possibly leading to a miscalculation

**Protocol**: Vaultcraft | **Impact**: HIGH

**Severity**: Critical	

**Status**: Acknowledged

**Description**

When calculating how much worth a share is in the protocol (for example when calculating fees) we perform the following 
```solidity
function _accruedPerformanceFee(
        Fees memory fees_
    ) internal view returns (uint256) {
        uint256 shareValue = convertToAssets(10 ** asset.decimals());
```

But the function convertToAssets is being passed one asset instead of one share , although this might not have a difference if both shares and asset have the same decimals but if the asset is for example  USDC/UDST then the ...

---

### 3. Attacker Can Grief The Management Fee To Be Lesser Than Expected

**Protocol**: Vaultcraft | **Impact**: HIGH

**Severity**: Critical	

**Status**: Resolved

**Description**

Fee is accrued when the share value increases / accrues value , then anyone can call the takeFees function which will accrue performance and management fee and send it to the fee recipient. 

But an attacker can do the following 

Call takeFees even when the share value has not increased, therefore no fee shares would be minted to the fee recipient but the feesUpdatedAt parameter would be updated anyhow.
```solidity
 if (shareValue > fees_.highWaterMark) fees.highWaterMark = shareValue;


        if (fee > 0) _mint(fees_.feeRecip...

---

### 4. Loss of fulfiller funds and fees due to wrong comparison between depositsAmount and total_amount

**Protocol**: Bando | **Impact**: HIGH

**Severity**: Critical

**Status**: Resolved

**Location**: BandoERC20FulfillableV1.sol

**Walkthrough**:
Say a user will like to submit a request for a ERC20Service.

**Initial states:**

```solidity
function getERC20DepositsFor(address token, address payer, uint256 serviceID) public view returns (uint256 amount) {
    amount = _erc20_deposits[serviceID][token][payer];
}
```

The initial deposit for the user is 0.

So when the user calls the router contract:
```solidity
function requestERC20Service(
    uint256 serviceID, 
    ERC20FulFillmentRequest memory request
) public payable whenNotPau...

---

### 5. Fund locked due to lack of an implementation for withdrawing service fees

**Protocol**: Bando | **Impact**: HIGH

**Severity**: Critical

**Status**: Resolved

**Location**: BandoRouterV1.sol

**Description**

In the BandoRouterV1 contract, the requestService() function requires the caller to pay the sum of request.weiAmount and service.feeAmount.
```solidity
(bool success, uint256 total_amount) = request.weiAmount.tryAdd(service.feeAmount);
if (!success) {
    revert OverflowError();
}
       
if (msg.value != total_amount) {
    revert AmountMismatch();
}
```

But the function calls the _escrow.deposit() function with only request.weiAmount and service.feeAmount is locked in the contract.
```solidity
IB...

---

### 6. Lack of an implementation for withdrawing beneficiaries balance

**Protocol**: Bando | **Impact**: HIGH

**Severity**: Critical

**Status**: Resolved

**Location**: BandoFulfillmentManagerV1.sol

**Description**

The beneficiaryWithdraw() function in both BandoERC20FulfillableV1 and BandoFulfillableV1 contracts are only designed to be called by the manager contract but the BandoFulfillmentManagerV1 contract is missing an implementation for withdrawing the beneficiaries available balances.
```solidity
function beneficiaryWithdraw(uint256 serviceID, address token) public virtual nonReentrant {
        require(_manager == msg.sender, "Caller is not the manager");
        ...
}
```

**Recommendation*...

---

### 7. Rounding While Calculating Option Shares Might Lead To Winner Receiving 0 Rewards

**Protocol**: Filament | **Impact**: HIGH

**Severity** - High

**Status** - Acknowledged

The winning option shares is calculated as follows 
```solidity
function _getUserDuelOptionShare(
        string memory _duelId,
        uint256 _optionIndex,
        address _user
    ) internal view returns (uint256 optionShare) {
        address optionToken = optionIndexToOptionToken[_duelId][_optionIndex];
        uint256 optionTokenBalance = IERC20(optionToken).balanceOf(_user);
        uint256 totalOptionTokenSupply = IERC20(optionToken).totalSupply();
        optionShare = (optionTokenBalance * 1e18) / totalOptionTokenSupply;
    }
```

I...

---

### 8. Users Can Lose All Their Rewards Even If Their Option Won The Duel

**Protocol**: Filament | **Impact**: HIGH

**Severity** - Critical

**Status** - Resolved

**Description**

Consider the following 

UserA joins a duel (say duelId = 1)  , provides an option and an option index , and as amount provides 1000 USDC
This would deploy a new options token , like this 
OptionToken newOptionToken = new OptionToken(_option, _option);

And mapping will be updated for the optionIndex 
optionIndexToOptionToken[_duelId][_optionsIndex] = address(newOptionToken);

And this newOptionToken is minted to the user 

newOptionToken.mint(msg.sender, amountTokenToMint);

Now userB arrives and joins the same duel i.e. due...

---

### 9. User Controlled Options Price

**Protocol**: Filament | **Impact**: HIGH

**Severity** - Critical

**Severity** - Resolved

**Description**

When joining a duel the amount put up as wager is compared against an options price and cant be lower than that price. But since the options price is controlled by the user 
```solidity
function joinDuel(
        string memory _duelId,
        string memory _option,
        uint256 _optionsIndex,
        uint256 _optionPrice,
        uint256 _amount
    )
```

The user can provide a very low value as the option price( 1 wei)  , in that case the amountTokenToMint would be large 
```solidity
uint256 amountTokenToMint = (_amoun...

---

### 10. Tokens will get locked forever after pausing the contract.

**Protocol**: Beyond | **Impact**: HIGH

**Severity**: Critical	

**Status**: Resolved

**Description**


The `PausableToken` smart contract is an ERC20 token defined as `Pausable`. The token implements `pause()` and `unpause()` functions to define if the contract is paused or not. The ERC20 token only allows `transfer()`, `transferFrom()`, `approve()`, `increaseAllowance()` and `decreaseAllowance()` to be executed while the contract is not paused as these functions implements a `whenNotPaused` modifier.
```solidity
function transfer(
       address to,
       uint256 amount
   ) public override whenNotPaused returns (bool) { 
      ...

---

### 11. Not enough Chainlink checks can make the protocol to behave incorrectly

**Protocol**: Beyond | **Impact**: HIGH

**Severity**: Critical	

**Status**: Resolved

**Description**

The `TokenBridge.Base.sol` smart contract implements a `getChainlinkDataFeedLatestAnswer()` function which uses Chainlink Price Feeds to retrieve assets prices:
```solidity
/**
    * Returns the latest answer
    * @param dataFeed Chainlink data feed
    * @return answer The latest answer
    */
   function getChainlinkDataFeedLatestAnswer( 
       AggregatorV3Interface dataFeed
   ) internal view returns (int) {
       // prettier-ignore
       (
           /* uint80 roundId */,
           int answer,
           /* uint startedA...

---

### 12. Management Fee For The First Time Will Be Way Larger Than It Should Be

**Protocol**: Teahouse | **Impact**: HIGH

**Severity** - High

**Status** - Resolved

**Description**: 

In TeaVaultAmbient.sol, the lastCollectedManagementFee should be initialized as block.timestamp , if not when the management fee is accrued for the first time it will be accrued as 
```solidity
function _collectManagementFee() internal returns (uint256 collectedShares) {
        uint256 timeDiff = block.timestamp - lastCollectManagementFee;
        if (timeDiff > 0) {
            unchecked {
                uint256 feeTimesTimediff = feeConfig.managementFee * timeDiff;//10000 * td
                uint256 denominator = (
          ...

---

### 13. _fractionOfShares Function in TeaVaultAmbient Contract May Cause the Vault to Round in the Incorrect Direction During Mathematical Operations

**Protocol**: Teahouse | **Impact**: HIGH

**Severity**: High

**Status**: Resolved

**Location**: TeaVaultAmbient.sol#_fractionOfShares

**Description**: 

The _fractionOfShares function is used in the TeaVaultAbient contract to aid the distribution and pricing of vault shares. This function takes a boolean value where true indicates the intention to round up and false indicates the intention to round down. However, these operations are performed in an incorrect manner as mulDivRoundingUp is called when _isRoundingUp is false. This may cause the user to receive more and less shares than they deserve.

**Recommendation**

Its recommen...

---

### 14. The opponent has a higher probability of winning than the initiator of the game.

**Protocol**: Xyro | **Impact**: HIGH

**Severity**: High	

**Status**: Resolved

**Description**

The `OneVsOneExactPrice.sol` smart contract allows creating games where the exact result of an asset should be guessed. The game is played by the initiator and an opponent. The one who guess the closest price to the final price is the winner. 
```solidity
uint256 diff1 = game.initiatorPrice > uint192(finalPrice) / 1e14 
           ? game.initiatorPrice - uint192(finalPrice) / 1e14
           : uint192(finalPrice) / 1e14 - game.initiatorPrice;
       uint256 diff2 = game.opponentPrice > uint192(finalPrice) / 1e14 
           ? game.opp...

---

### 15. One side players have more probability of winning than the other.

**Protocol**: Xyro | **Impact**: HIGH

**Severity**: High	

**Status**: Resolved

**Description**

In the `UpDown` game, players can bet that an assets price will be up or down compared to the current price. If the price is up, players that voted for it will win and vice versa. However, the current implementation of the `finalizeGame()` function within the `UpDown.sol` smart contract allocates more probability of winning to the players that voted down, instead of allocating it 50/50.


```solidity
if (uint192(finalPrice / 1e14) > _game.startingPrice) { // @audit why / 1e14 ahora?
           uint256 finalRate = ITreasury(treasury)....

---


## Statistics

- Total findings from Zokyo: 3,376
- Last updated: 2026-01-29

