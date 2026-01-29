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
This is forked from UniswapV2 source code, and it’s meant and known to overflow. It works 
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

In the `JalaPair::_update` function, overflow is intentionally desired in the calculations for `timeElapsed` and `priceCumulative`. This is forked from the UniswapV2 source code, and it’s meant and known to overflow. UniswapV2 was developed using Solidity 0.6.6, where arithmetic operations overflow and underflow by default. However, Jala utilizes Solidity >=0.8.0, where such operations will automatically revert.

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
