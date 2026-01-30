# Rounding Security Patterns

## Overview

**Frequency**: 32 occurrences (0.06% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 17 | 15 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Spearbit, Cyfrin, OpenZeppelin

---

## Detection Checklist

- [ ] Check for rounding vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Rounding up of taker fees of constituent orders may exceed collected fee

**Source**: Spearbit
**Protocol**: CLOBER
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
- OrderBook.sol#L463 
- OrderBook.sol#L478-L482 
- OrderBook.sol#L604 

## Description
If multiple orders are taken, the taker fee calculated is rounded up once, but that of each taken maker order could be rounded up as well, leading to more fees accounted for than actually taken.

### Example:
- takerFee = 100011 (10.0011%)
- 2 maker orders of amounts 400000 and 377000
- total amount = 400000 + 377000 = 777000
- Taker fee taken = 777000 * 100011 / 1000000 = 77708.547  77709 

Maker fees would be:
- 377000 * 100011 / 1000000 = 37704.147  37705
- 400000 * 100011 / 1000000 = 40004.4  40005

This results in 1 wei more than actually taken.

Below is a foundry test to reproduce the problem, which can be inserted into `Claim.t.sol`:

```solidity
function testClaimFeesFailFromRounding() public {
    _createOrderBook(0, 100011); // 10.0011% taker fee
    // create 2 orders
    uint256 orderIndex1 = _createPostOnlyOrder(Constants.BID, Constants.RAW_AMOUNT);
    uint256 orderIndex2 = _createPostOnlyOrder(Constants.BID, Constants.RAW_AMOUNT);
    // take both orders
    _createTakeOrder(Constants.BID, 2 * Constants.RAW_AMOUNT);
    CloberOrderBook.OrderKey[] memory ids = new CloberOrderBook.OrderKey[](2);
    ids[0] = CloberOrderBook.OrderKey({
        isBid: Constants.BID,
        priceIndex: Constants.PRICE_INDEX,
        orderIndex: orderIndex1
    });
    ids[1] = CloberOrderBook.OrderKey({
        isBid: Constants.BID,
        priceIndex: Const

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Clober-Spearbit-Security-Review.pdf)

---

### Example 2: [H-04] User's Accrued Rewards Will Be Lost

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: HIGH

**Details**:

If the user deposits too little GMX compared to other users (or total supply of pxGMX), the user will not be able to receive rewards after calling the `PirexRewards.claim` function. Subsequently, their accrued rewards will be cleared out (set to zero), and they will lose their rewards.

The amount of reward tokens that are claimable by a user is computed in Line 403 of the `PirexRewards.claim` function.

If the balance of pxGMX of a user is too small compared to other users (or total supply of pxGMX), the code below will always return zero due to rounding issues within solidity.

```solidity
uint256 amount = (rewardState * userRewards) / globalRewards;
```

Since the user's accrued rewards is cleared at Line 391 within the `PirexRewards.claim` function (`p.userStates[user].rewards = 0;`), the user's accrued rewards will be lost.

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/PirexRewards.sol#L373>

```solidity
File: PirexRewards.sol
368:     /**
369:         @notice Claim rewards
370:         @param  producerToken  ERC20    Producer token contract
371:         @param  user           address  User
372:     */
373:     function claim(ERC20 producerToken, address user) external {
374:         if (address(producerToken) == address(0)) revert ZeroAddress();
375:         if (user == address(0)) revert ZeroAddress();
376: 
377:         harvest();
378:         userAccrue(producerToken, user);
379: 
380:         ProducerToken s

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-redactedcartel)

---

### Example 3: [H-03] Malicious Users Can Drain The Assets Of Auto Compound Vault

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/PirexERC4626.sol#L156>

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGmx.sol#L199>

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/AutoPxGmx.sol#L315>

### Proof of Concept

> Note: This issue affects both the AutoPxGmx and AutoPxGlp vaults. Since the root cause is the same, the PoC of AutoPxGlp vault is omitted for brevity.

The `PirexERC4626.convertToShares` function relies on the `mulDivDown` function in Line 164 when calculating the number of shares needed in exchange for a certain number of assets. Note that the computation is rounded down, therefore, if the result is less than 1 (e.g. 0.9), Solidity will round them down to zero. Thus, it is possible that this function will return zero.

<https://github.com/code-423n4/2022-11-redactedcartel/blob/03b71a8d395c02324cb9fdaf92401357da5b19d1/src/vaults/PirexERC4626.sol#L156>

```solidity
File: PirexERC4626.sol
156:     function convertToShares(uint256 assets)
157:         public
158:         view
159:         virtual
160:         returns (uint256)
161:     {
162:         uint256 supply = totalSupply; // Saves an extra SLOAD if totalSupply is non-zero.
163: 
164:         return supply == 0 ? assets : assets.mulDivDown(supply, totalAssets());
165:     }
```

The `AutoPxGmx.previewWithdr

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-redactedcartel)

---

### Example 4: [H-01] Bidders might fail to withdraw their unused funds after the auction was finalized because the contract doesn't have enough balance.

**Source**: Code4rena
**Protocol**: SIZE
**Impact**: HIGH

**Details**:

Bidders might fail to withdraw their unused funds after the auction was finalized because the contract doesn't have enough balance.

The main flaw is the seller might receive more quote tokens than the bidders offer after the auction was finalized.

If there is no other auctions to use the same quote token, the last bidder will fail to withdraw his funds because the contract doesn't have enough balance of quote token.

### Proof of Concept

After the auction was finalized, the seller receives the `filledQuote` amount of quote token using [data.filledBase](https://github.com/code-423n4/2022-11-size/blob/706a77e585d0852eae6ba0dca73dc73eb37f8fb6/src/SizeSealed.sol#L325).

```solidity
    // Calculate quote amount based on clearing price
    uint256 filledQuote = FixedPointMathLib.mulDivDown(clearingQuote, data.filledBase, clearingBase);
```

But when the bidders withdraw the funds using `withdraw()`, they offer the quote token [using this formula](https://github.com/code-423n4/2022-11-size/blob/706a77e585d0852eae6ba0dca73dc73eb37f8fb6/src/SizeSealed.sol#L375-L382).

```solidity
    // Refund unfilled quoteAmount on first withdraw
    if (b.quoteAmount != 0) {
        uint256 quoteBought = FixedPointMathLib.mulDivDown(baseAmount, a.data.lowestQuote, a.data.lowestBase);
        uint256 refundedQuote = b.quoteAmount - quoteBought;
        b.quoteAmount = 0;

        SafeTransferLib.safeTransfer(ERC20(a.params.quoteToken), msg.sender, refundedQuote);
    }
```

Even if they use the 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-size)

---

### Example 5: [H-01] Precision loss in the invariant function can lead to loss of funds

**Source**: Code4rena
**Protocol**: Numoen
**Impact**: HIGH

**Details**:

[src/core/Pair.sol#L56](https://github.com/code-423n4/2023-01-numoen/blob/2ad9a73d793ea23a25a381faadc86ae0c8cb5913/src/core/Pair.sol#L56)<br>

An attacker can steal the funds without affecting the invariant.

### Proof of Concept

We can say the function `Pair.invariant()` is the heart of the protocol.<br>
All the malicious trades should be prevented by this function.

```solidity
Pair.sol
52:   /// @inheritdoc IPair
53:   function invariant(uint256 amount0, uint256 amount1, uint256 liquidity) public view override returns (bool) {
54:     if (liquidity == 0) return (amount0 == 0 && amount1 == 0);
55:
56:     uint256 scale0 = FullMath.mulDiv(amount0, 1e18, liquidity) * token0Scale;//@audit-info precison loss
57:     uint256 scale1 = FullMath.mulDiv(amount1, 1e18, liquidity) * token1Scale;//@audit-info precison loss
58:
59:     if (scale1 > 2 * upperBound) revert InvariantError();
60:
61:     uint256 a = scale0 * 1e18;
62:     uint256 b = scale1 * upperBound;
63:     uint256 c = (scale1 * scale1) / 4;
64:     uint256 d = upperBound * upperBound;
65:
66:     return a + b >= c + d;
67:   }

```

The problem is there is a precision loss in the L56 and L57.<br>
The precision loss can result in the wrong invariant check result.<br>
Let's say the `token0` has 6 decimals and liquidity has more than 24 decimals.<br>
Then the first `FullMath.mulDiv` will cause significant rounding before it's converted to D18.<br>
To clarify the difference I wrote a custom function `invariant()` to see 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-numoen)

---

### Example 6: [H-04] Division rounding can make fraction-price lower than intended (down to zero)

**Source**: Code4rena
**Protocol**: Fractional
**Impact**: HIGH

**Details**:

_Submitted by 0xA5DF, also found by 0x52, exd0tpy, horsefacts, hyh, kenzo, Lambda, minhquanym, panprog, scaraven, shenwilly, and simon135_

Divisions in EVM are rounded down, which means when the fraction price is close to 1 (e.g. 0.999) it would effectively be zero, when it's close to 2 (1.999) it would be rounded to 1 - losing close to 50% of the intended price.

*   In case the proposer had any fractions, the buyout module puts them for sale and he can lose his fractions while getting in exchange either zero or a significantly lower price than intended
*   Even when the proposer doesn't hold any fractions, if the buyout succeeds - the difference (i.e. `buyoutPrice - fractionPrice*totalSupply`) goes to those who cash out their fractions after the buyout ends.
    *   That's going to disincentivize users to sell their fractions during the buyout, because they may get more if they keep it till the buyout ends.
    *   In other words, not only that the extra money the proposer paid doesn't increase the chance of the buyout to succeed, it actually decreases it.

### Proof of Concept

I've added the following tests to `test/Buyout.t.sol`.

```solidity

    // add Eve to the list of users 
    function setUp() public {
        setUpContract();
        alice = setUpUser(111, 1);
        bob = setUpUser(222, 2);
        eve = setUpUser(333, 3);

        vm.label(address(this), "BuyoutTest");
        vm.label(alice.addr, "Alice");
        vm.label(bob.addr, "Bob");
        vm.label(

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-fractional)

---

### Example 7: [H-02] Attacker can amplify a rounding error in MagicLP to break the I invariant and cause malicious pricing

**Source**: Code4rena
**Protocol**: Abracadabra Money
**Impact**: HIGH

**Details**:

One of the two key parameters in MagicLP pools is `I`, which is defined to be the ideal ratio between the two reserves. It is set during MagicLP initialization:
`_I_ = i;`

It is used when performing the initial LP deposit, in `buyShares()`:

    if (totalSupply() == 0) {
        // case 1. initial supply
        if (quoteBalance == 0) {
            revert ErrZeroQuoteAmount();
        }
        shares = quoteBalance < DecimalMath.mulFloor(baseBalance, _I_) ? DecimalMath.divFloor(quoteBalance, _I_) : baseBalance;
        _BASE_TARGET_ = shares.toUint112();
        _QUOTE_TARGET_ = DecimalMath.mulFloor(shares, _I_).toUint112();
        if (_QUOTE_TARGET_ == 0) {
            revert ErrZeroQuoteTarget();
        }
        if (shares <= 2001) {
            revert ErrMintAmountNotEnough();
        }
        _mint(address(0), 1001);
        shares -= 1001;

The `QUOTE_TARGET` is determined by multiplying the `BASE_TARGET` with `I`.

The flaw is in the check below:
`shares = quoteBalance < DecimalMath.mulFloor(baseBalance, _I_) ? DecimalMath.divFloor(quoteBalance, _I_) : baseBalance;`
Essentially there needs to be enough `quoteBalance` at the `I` ratio to mint `baseBalance` shares, if there's not enough then shares are instead determined by dividing the `quoteBalance` with `I`.
An attacker can abuse the `mulFloor()` to create a major inconsistency.
Suppose `quoteBalance = 1`, `baseBalance = 19999`, `I = 1e14`. Then we have:
`1 < 19999 * 1e14 / 1e18 => 1 < 1 => False`
Therefore `shar

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-03-abracadabra-money)

---

### Example 8: [H-02] Builder can halve the interest paid to a community owner due to arithmetic rounding

**Source**: Code4rena
**Protocol**: Rigor Protocol
**Impact**: HIGH

**Details**:

_Submitted by scaraven, also found by 0x52, auditor0517, Deivitto, hansfriese, Lambda, rbserver, simon135, smiling&#95;heretic, sseefried, and TrungOre_

[Community.sol#L685-L686](https://github.com/code-423n4/2022-08-rigor/blob/5ab7ea84a1516cb726421ef690af5bc41029f88f/contracts/Community.sol#L685-L686)<br>

Due to arithmetic rounding in `returnToLender()`, a builder can halve the APR paid to a community owner by paying every 1.9999 days. This allows a builder to drastically decrease the amount of interest paid to a community owner, which in turn allows them to advertise very high APR rates to secure funding, most of which they will not pay.

This issue occurs in the calculation of `noOfDays` in `returnToLender()` which calculates the number of days since interest has last been calculated. If a builder repays a very small amount of tokens every 1.9999 days, then the `noOfDays` will be rounded down to `1 days` however `lastTimestamp` is updated to the current timestamp anyway, so the builder essentially accumulates only 1 day of interest after 2 days.

I believe this is high severity because a community owner can have a drastic decrease in interest gained from a loan which counts as lost rewards. Additionally, this problem does not require a malicious builder because if a builder pays at a wrong time, the loaner receives less interest anyway.

### Proof of Concept

1.  A community owner provides a loan of 500\_000 tokens to a builder with an APR of 10% (ignoring treasury fees)

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-08-rigor)

---

### Example 9: H-10: ERC721Pool's take will proceed with truncated collateral amount and full debt when borrower's collateral is fractional

**Source**: Sherlock
**Protocol**: Ajna
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-ajna-judging/issues/68 

## Found by 
hyh

## Summary

Caller of take() can end up paying the debt corresponding to the fractional ERC721 collateral of a borrower, but receiving only truncated part of the this collateral in return (paying the debt for `1.9`, receiving `1.0`), with the borrower keeping the remainder.

## Vulnerability Detail

Fractional part of ERC721 collateral is gifted to the borrower in Auctions's _take() (L889-898) when `params_.collateral` doesn't allow an increase. Say when `vars.collateralAmount = params_.collateral = 1.9e18`, while taker specified collateral is `2`, it will proceed with paying the debt corresponding to `1.9e18`, which was calculated before in _calculateTakeFlowsAndBondChange(), but will pay the caller only `1e18` of collateral, leaving `0.9e18` with the borrower at caller's expense.

It happens only when `params_.collateral = borrower.collateral` isn't whole 18dp integer, the state that can periodically occur after ERC721Pool's bucketTake(), which applies _calculateTakeFlowsAndBondChange() result to the borrower's balance without rounding, so a partial bucketTake() will leave it as a 18dp fraction.

## Impact

Caller's funds will be lost as they pay borrower's debt according to the untruncated `params_.collateral` value, but receive only truncated amount of collateral.

As both take() and bucketTake() are routine operations and there are no low probability prerequisites, and given the 

*[Content truncated...]*

---

### Example 10: `VoteKickPolicy._endVote()` might revert forever due to underflow

**Source**: Cyfrin
**Protocol**: Streamr
**Impact**: HIGH

**Details**:

**Severity:** High

**Description:** In `onFlag()`, `targetStakeAtRiskWei[target]` might be less than the total rewards for the flagger/reviewers due to rounding.

```solidity
File: contracts\OperatorTokenomics\StreamrConfig.sol
22:     /**
23:      * Minimum amount to pay reviewers+flagger
24:      * That is: minimumStakeWei >= (flaggerRewardWei + flagReviewerCount * flagReviewerRewardWei) / slashingFraction
25:      */
26:     function minimumStakeWei() public view returns (uint) {
27:         return (flaggerRewardWei + flagReviewerCount * flagReviewerRewardWei) * 1 ether / slashingFraction;
28:     }
```

- Let's assume `flaggerRewardWei + flagReviewerCount * flagReviewerRewardWei = 100, StreamrConfig.slashingFraction = 0.03e18(3%), minimumStakeWei() = 1000 * 1e18 / 0.03e18 = 10000 / 3 = 3333.`
- If we suppose `stakedWei[target] = streamrConfig.minimumStakeWei()`, then `targetStakeAtRiskWei[target] = 3333 * 0.03e18 / 1e18 = 99.99 = 99.`
- As a result, `targetStakeAtRiskWei[target]` is less than total rewards(=100), and `_endVote()` will revert during the reward distribution due to underflow.

The above scenario is possible only when there is a rounding during `minimumStakeWei` calculation. So it works properly with the default `slashingFraction = 10%`.

**Impact:** The `VoteKickPolicy` wouldn't work as expected and malicious operators won't be kicked forever.

**Recommended Mitigation:** Always round the `minimumStakeWei()` up.

**Client:** Fixed in commit [615b531](https:

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-11-03-cyfrin-streamr.md)

---

### Example 11: [H-06] `EUSD.mint` function wrong assumption of cases when calculated sharesAmount = 0

**Source**: Code4rena
**Protocol**: Lybra Finance
**Impact**: HIGH

**Details**:

### Lines of code

<https://github.com/code-423n4/2023-06-lybra/blob/main/contracts/lybra/token/EUSD.sol#L299-#L306> <br><https://github.com/code-423n4/2023-06-lybra/blob/main/contracts/lybra/token/EUSD.sol#L414-#L418>

### Impact

*   `Mint` function might calculate the `sharesAmount` incorrectly.
*   User can profit by manipulating the protocol to enjoy 1-1 share-eUSD ratio even when share prices is super high.

### Proof of Concept

Currently, the function `EUSD.mint` calls function `EUSD.getSharesByMintedEUSD` to calculate the shares corresponding to the input eUSD amount:

```solidity
function mint(address _recipient, uint256 _mintAmount) external onlyMintVault MintPaused returns (uint256 newTotalShares) {
        require(_recipient != address(0), "MINT_TO_THE_ZERO_ADDRESS");

        uint256 sharesAmount = getSharesByMintedEUSD(_mintAmount);
        if (sharesAmount == 0) {
            //EUSD totalSupply is 0: assume that shares correspond to EUSD 1-to-1
            sharesAmount = _mintAmount;
        }
        ...
}
function getSharesByMintedEUSD(uint256 _EUSDAmount) public view returns (uint256) {
        uint256 totalMintedEUSD = _totalSupply;
        if (totalMintedEUSD == 0) {
            return 0;
        } else {
            return _EUSDAmount.mul(_totalShares).div(totalMintedEUSD);
        }
}
```

As you can see in the comment after `sharesAmount` is checked, `//EUSD totalSupply is 0: assume that shares correspond to EUSD 1-to-1`. The code assumes that if `shar

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-lybra)

---

### Example 12: [H-10] First vault depositor can steal other's assets

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

### Example 13: [H-02] Division Before Multiplication Can Lead To Zero Rounding Of Return Amount

**Source**: Code4rena
**Protocol**: Illuminate
**Impact**: HIGH

**Details**:

_Submitted by kirk-baird, also found by csanuragjain, datapunk, and ladboy233_

There is a division before multiplication bug that exists in [`lend()`](https://github.com/code-423n4/2022-06-illuminate/blob/92cbb0724e594ce025d6b6ed050d3548a38c264b/lender/Lender.sol#L280) for the Swivel case.

If `order.premium` is less than `order.principal` then `returned` will round to zero due to the integer rounding.

When this occurs the user's funds are essentially lost. That is because they transfer in the underlying tokens but the amount sent to `yield(u, y, returned, address(this))` will be zero.

### Proof of Concept

```solidity
    function lend(
        uint8 p,
        address u,
        uint256 m,
        uint256[] calldata a,
        address y,
        Swivel.Order[] calldata o,
        Swivel.Components[] calldata s
    ) public unpaused(p) returns (uint256) {

        // lent represents the number of underlying tokens lent
        uint256 lent;
        // returned represents the number of underlying tokens to lend to yield
        uint256 returned;

        {
            uint256 totalFee;
            // iterate through each order a calculate the total lent and returned
            for (uint256 i = 0; i < o.length; ) {
                Swivel.Order memory order = o[i];
                // Require the Swivel order provided matches the underlying and maturity market provided
                if (order.underlying != u) {
                    revert NotEqual('underlying');
           

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-06-illuminate)

---

### Example 14: Shares distributed to operators suffer from rounding error

**Source**: Spearbit
**Protocol**: Liquid Collective
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context: 
River.1.sol#L238

## Description: 
*rewardOperators* distribute a portion of the overall shares distributed to operators based on the number of active and funded validators that each operator has.

The current number of shares distributed to a validator is calculated by the following code:

```solidity
_mintRawShares(operators[idx].feeRecipient, validatorCounts[idx] * rewardsPerActiveValidator);
```

where *rewardsPerActiveValidator* is calculated as:

```solidity
uint256 rewardsPerActiveValidator = _reward / totalActiveValidators;
```

This means that in reality each operator receives:

*validatorCounts[idx] * (_reward / totalActiveValidators)* shares. Such share calculation suffers from a rounding error caused by division before multiplication.

## Recommendation: 
Consider re-writing the number of shares distributed to each operator:

```solidity
// removed --- > uint256 rewardsPerActiveValidator = _reward / totalActiveValidators;
for (uint256 idx = 0; idx < validatorCounts.length;) {
    _mintRawShares(
        operators[idx].feeRecipient,
        (validatorCounts[idx] * _reward) / totalActiveValidators
    );
    ...
}
```

Note that this will reduce the rounding error, but it adds 1 DIVgas cost (5 gas) per iteration. Also, the rounding errors favor the users/depositors.

## Alluvial: 
The whole operator rewarding system has been removed in SPEARBIT/8.

## Spearbit: 
Acknowledged.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LiquidCollective-Spearbit-Security-Review.pdf)

---

### Example 15: Avoid multiple divisions when calculating operatorRewards

**Source**: Spearbit
**Protocol**: Liquid Collective
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
River.1.sol#L277

## Description/Recommendation
In `_onEarnings`, we calculate the `sharesToMint` and `operatorRewards` by dividing two numbers. We can reduce the number of divisions to one and also delegate this division to `_rewardOperators`. This would further avoid the rounding errors that we get when we divide two numbers in EVM. 

Here is the original code:

```solidity
uint256 globalFee = GlobalFee.get();
uint256 numerator = _amount * currentTotalSupply * globalFee;
uint256 denominator = (_assetBalance() * BASE) - (_amount * globalFee);
uint256 sharesToMint = denominator == 0 ? 0 : (numerator / denominator);
uint256 operatorRewards = (sharesToMint * OperatorRewardsShare.get()) / BASE;
uint256 mintedRewards = _rewardOperators(operatorRewards);
```

Instead of passing `operatorRewards`, we can pass two values: one for the numerator and one for the denominator. This way, we can avoid extra rounding errors introduced in `_rewardOperators`. `_rewardOperators` also needs to be changed slightly to account for these two new values.

Heres the updated code:

```solidity
uint256 globalFee = GlobalFee.get();
uint256 numerator = _amount * currentTotalSupply * globalFee * OperatorRewardsShare.get();
uint256 denominator = ((_assetBalance() * BASE) - (_amount * globalFee)) * BASE;
uint256 mintedRewards;

if (denominator != 0) { // note: this was added to avoid calling `_rewardOperators` if `denominator == 0`
    mintedRewards = _rewardOperators(n

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LiquidCollective-Spearbit-Security-Review.pdf)

---

### Example 16: [M-07] Oracles two-day feature can be gamed

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

### Example 17: [M-03] Rounding error in `buyQuote` might result in free tokens

**Source**: Code4rena
**Protocol**: Caviar
**Impact**: MEDIUM

**Details**:

In order to guarantee the contract does not become insolvent, incoming assets should be rounded up, while outgoing assets should be rounded down.

The function `buyQuote()` calculates the amount of base tokens required to buy a given amount of fractional tokens. However, this function rounds down the required amount, which is in favor of the buyer (i.e. he/she has to provide less base tokens for the amount of receiving fractional tokens.

Depending on the amount of current token reserves and the amount of fractional tokens the user wishes to buy, it might be possible to receive free fractional tokens.

Assume the following reserve state:

*   base token reserve: 0,1 WBTC (=`1e7`)
*   fractional token reserve: 10.000.000 (=`1e25`)

The user wishes to buy 0,9 fractional tokens (=`9e17`). Then, the function `buyQuote()` will calculate the amount of base tokens as follows:

`(9e17 * 1000 * 1e7) / ((1e25 - 9e17) * 997) = 0,903`

As division in Solidity will round down, the amount results in `0` amount of base tokens required (WBTC) to buy 0,9 fractional tokens.

### Impact

Using the example above, 0,9 fractional tokens is a really small amount (`0,1 BTC / 1e7 = +- $0,00017`). Moreover, if the user keeps repeating this attack, the fractional token reserve becomes smaller, which will result in a buyQuote amount of >1, after which the tokens will not be free anymore.

Additionally, as the contract incorporates a fee of 30bps, it will likely not be insolvent. The downside would be th

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-caviar)

---

### Example 18: [M-02] Users can avoid paying fees if they manage to update their accrued fees periodically

**Source**: Code4rena
**Protocol**: Inverse Finance
**Impact**: MEDIUM

**Details**:

[DBR.sol#L287](https://github.com/code-423n4/2022-10-inverse/blob/main/src/DBR.sol#L287)<br>

While a user borrows DOLA, his debt position in the DBR contract accrues more debt over time. However, Solidity contracts cannot update their storage automatically over time; state updates must always be triggered by externally owned accounts. For this reason, the DBR contract cannot accurately represent a user's debt position in its storage at all times. Instead, the contract offers a method `accrueDueTokens` that, when called, updates the internal storage with the debts that accrued since the last update. This method is called before all critical financial operations that depend on an accurate value of the accumulated deficit in the contract's storage. On top, this method can also be invoked permissionless at any time. Suppose a borrower manages to call this function periodically and keep the time difference between updates short. In that case, a rounding error in the computation of the accrued debt can cause the expression to round down to zero. In this case, the user successfully avoided paying interest on his debt.

### Proof of Concept

For reference, here is the affected code:

```Solidity
    function accrueDueTokens(address user) public {
        uint debt = debts[user];
        if(lastUpdated[user] == block.timestamp) return;
        uint accrued = (block.timestamp - lastUpdated[user]) * debt / 365 days;
        dueTokensAccrued[user] += accrued;
        totalDueTokensAccru

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-inverse)

---

### Example 19: H-5: Adding liquidity can be `DoS`ed due to calculation mismatches

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

### Example 20: H-2: FundingRateArbitrage contract can be drained due to rounding error

**Source**: Sherlock
**Protocol**: JOJO Exchange Update
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-12-jojo-exchange-update-judging/issues/57 

## Found by 
detectiveking
## Summary

In the `requestWithdraw`, rounding in the wrong direction is done which can lead to contract being drained. 

## Vulnerability Detail

In the `requestWithdraw` function in `FundingRateArbitrage`, we find the following lines of code:

```solidity
jusdOutside[msg.sender] -= repayJUSDAmount;
uint256 index = getIndex();
uint256 lockedEarnUSDCAmount = jusdOutside[msg.sender].decimalDiv(index);
require(
     earnUSDCBalance[msg.sender] >= lockedEarnUSDCAmount, "lockedEarnUSDCAmount is bigger than earnUSDCBalance"
);
withdrawEarnUSDCAmount = earnUSDCBalance[msg.sender] - lockedEarnUSDCAmount;
```

Because we round down when calculating `lockedEarnUSDCAmount`, `withdrawEarnUSDCAmount` is higher than it should be, which leads to us allowing the user to withdraw more than we should allow them to given the amount of JUSD they repaid. 

The execution of this is a bit more complicated, let's go through an example. We will assume there's a bunch of JUSD existing in the contract and the attacker is the first to deposit. 

Steps:

1. The attacker deposits 1 unit of USDC and then manually sends in another 100 * 10^6 - 1 (not through deposit, just a transfer). The share price / price per earnUSDC will now be $100. Exactly one earnUSDC is in existence at the moment. 
2. Next the attacker creates a new EOA and deposits a little over $101 worth of USDC (so that after f

*[Content truncated...]*

---

### Example 21: [H-04] Reserved token rounding can be abused to honeypot and steal user's funds

**Source**: Code4rena
**Protocol**: Juicebox
**Impact**: HIGH

**Details**:

When the project wishes to mint reserved tokens, they call mintReservesFor which allows minting up to the amount calculated by DelegateStore's \_numberOfReservedTokensOutstandingFor. The function has this line:

    // No token minted yet? Round up to 1.
    if (_storedTier.initialQuantity == _storedTier.remainingQuantity) return 1;

In order to ease calculations, if reserve rate is not 0 and no token has been minted yet, the function allows a single reserve token to be printed. It turns out that this introduces a very significant risk for users. Projects can launch with several tierIDs of similar contribution size, and reserve rate as low as 1%. Once a victim contributes to the project, it can instantly mint a single reserve token of all the rest of the tiers. They can then redeem the reserve token and receive most of the user's contribution, without putting in any money of their own.

Since this attack does not require setting "dangerous" flags like lockReservedTokenChanges or lockManualMintingChanges, it represents a very considerable threat to unsuspecting users. Note that the attack circumvents user voting or any funding cycle changes which leave time for victim to withdraw their funds. 

### Impact

Honeypot project can instantly take most of first user's contribution.

### Proof of Concept

New project launches, with 10 tiers, of contributions 1000, 1050, 1100, ...

Reserve rate is set to 1% and redemption rate = 100%

User contributes 1100 and gets a Tier 3 NFT reward

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-juicebox)

---

### Example 22: M-7: Market Price Lower Than Expected

**Source**: Sherlock
**Protocol**: Bond Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-bond-judging/issues/20 

## Found by 
xiaoming90

## Summary

The market price does not conform to the specification documented within the whitepaper. As a result, the computed market price is lower than expected.

## Vulnerability Detail

The following definition of the market price is taken from the whitepaper. Taken from Page 13 of the whitepaper - Definition 25

![image-20221114132609169](https://user-images.githubusercontent.com/102820284/201850739-496a5e30-bb92-40e3-acfc-6d46821a4eab.png)

The integer implementation of the market price must be rounded up per the whitepaper. This ensures that the integer implementation of the market price is greater than or equal to the real value of the market price so as to protect makers from selling tokens at a lower price than expected.

Within the `BondBaseSDA.marketPrice` function, the computation of the market price is rounded up in Line 688, which conforms to the specification.

https://github.com/sherlock-audit/2022-11-bond/blob/main/src/bases/BondBaseSDA.sol#L687

```solidity
File: BondBaseSDA.sol
687:     function marketPrice(uint256 id_) public view override returns (uint256) {
688:         uint256 price = currentControlVariable(id_).mulDivUp(currentDebt(id_), markets[id_].scale);
689: 
690:         return (price > markets[id_].minPrice) ? price : markets[id_].minPrice;
691:     }
```

However, within the `BondBaseSDA._currentMarketPrice` function, the market price is rounded

*[Content truncated...]*

---

### Example 23: [M-17] Malicious Users Can Drain The Assets Of Vault. (Due to not being ERC4626 Complaint)

**Source**: Code4rena
**Protocol**: Popcorn
**Impact**: MEDIUM

**Details**:

Malicious users can drain the assets of the vault.

### Proof of Concept

The `withdraw` function users `convertToShares` to convert the assets to the amount of shares. These shares are burned from the users account and the assets are returned to the user.

The function `withdraw` is shown below:

```solidity
function withdraw(
        uint256 assets,
        address receiver,
        address owner
    ) public nonReentrant syncFeeCheckpoint returns (uint256 shares) {
        if (receiver == address(0)) revert InvalidReceiver();

        shares = convertToShares(assets);
/// .... [skipped the code]
```

The function `convertToShares` is shown below:

```solidity
function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply(); // Saves an extra SLOAD if totalSupply is non-zero.

        return
            supply == 0
                ? assets
                : assets.mulDiv(supply, totalAssets(), Math.Rounding.Down);
    }
```

It uses `Math.Rounding.Down` , but it should use `Math.Rounding.Up`

Assume that the vault with the following state:

*   Total Asset = 1000 WETH
*   Total Supply = 10 shares

Assume that Alice wants to withdraw 99 WETH from the vault. Thus, she calls the**`Vault.withdraw(99 WETH)`**function.

The calculation would go like this:

```solidity
assets = 99
return value = assets * supply / totalAssets()
return value = 99 * 10 / 1000
return value = 0
```

The value would be rounded round to zero. This will be 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-popcorn)

---

### Example 24: M-5: Math rounding in AutoRoller.sol is not ERC4626-complicant: previewWithdraw should round up.

**Source**: Sherlock
**Protocol**: Sense
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-sense-judging/issues/30 

## Found by 
ctf\_sec

## Summary

Math rounding in AutoRoller.sol is not ERC4626-complicant: previewWithdraw should round up.

## Vulnerability Detail

Per EIP 4626's Security Considerations (https://eips.ethereum.org/EIPS/eip-4626)

> Finally, ERC-4626 Vault implementers should be aware of the need for specific, opposing rounding directions across the different mutable and view methods, as it is considered most secure to favor the Vault itself during calculations over its users:

> If (1) its calculating how many shares to issue to a user for a certain amount of the underlying tokens they provide or (2) its determining the amount of the underlying tokens to transfer to them for returning a certain amount of shares, it should round down.
If (1) its calculating the amount of shares a user has to supply to receive a given amount of the underlying tokens or (2) its calculating the amount of underlying tokens a user has to provide to receive a certain amount of shares, it should round up.

Then previewWithdraw in AutoRoller.sol should round up.

The original implementation for previewWithdraw in Solmate ERC4626 is:

```solidity
    function previewWithdraw(uint256 assets) public view virtual returns (uint256) {
        uint256 supply = totalSupply; // Saves an extra SLOAD if totalSupply is non-zero.

        return supply == 0 ? assets : assets.mulDivUp(supply, totalAssets());
    }
```

It is roundi

*[Content truncated...]*

---

### Example 25: M-12: Debt Decay Faster Than Expected

**Source**: Sherlock
**Protocol**: Bond Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-bond-judging/issues/12 

## Found by 
xiaoming90

## Summary

The debt decay at a rate faster than expected, causing market makers to sell bond tokens at a lower price than expected.  

## Vulnerability Detail

The following definition of the debt decay reference time following any purchases at time `t` taken from the whitepaper. The second variable, which is the delay increment, is rounded up. Following is taken from Page 15 of the whitepaper - Definition 27

![image-20221114170852736](https://user-images.githubusercontent.com/102820284/201844416-023c6d4f-893d-40ab-b6cb-6e33402d8e78.png)

However, the actual implementation in the codebase differs from the specification. At Line 514, the delay increment is rounded down instead.

https://github.com/sherlock-audit/2022-11-bond/blob/main/src/bases/BondBaseSDA.sol#L514

```solidity
File: BondBaseSDA.sol
513:         // Set last decay timestamp based on size of purchase to linearize decay
514:         uint256 lastDecayIncrement = debtDecayInterval.mulDiv(payout_, lastTuneDebt);
515:         metadata[id_].lastDecay += uint48(lastDecayIncrement);
```

## Impact

When the delay increment (TD) is rounded down, the debt decay reference time increment will be smaller than expected. The debt component will then decay at a faster rate. As a result, the market price will not be adjusted in an optimized manner, and the market price will fall faster than expected, causing market makers to sel

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 32
- Examples shown: 25
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

