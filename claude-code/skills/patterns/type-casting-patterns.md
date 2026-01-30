# Type casting Security Patterns

## Overview

**Frequency**: 14 occurrences (0.03% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 5 | 9 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Spearbit

---

## Detection Checklist

- [ ] Check for type casting vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Typed structured data hash used for signing commitments is calculated incorrectly

**Source**: Spearbit
**Protocol**: Astaria
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
- `VaultImplementation.sol#L150-L151`
- `VaultImplementation.sol#L172-L176`
- `IVaultImplementation.sol#L41`

## Description
Since  
`STRATEGY_TYPEHASH == keccak256("StrategyDetails(uint256 nonce,uint256 deadline,bytes32 root)")`  
The hash calculated in `_encodeStrategyData` is incorrect according to EIP-712. `s.strategistNonce` is of type `uint32` and the nonce type used in the type hash is `uint256`.

Also, the struct name used in the typehash collides with the `StrategyDetails` struct name defined as:
```solidity
struct StrategyDetails {
    uint8 version;
    uint256 deadline;
    address vault;
}
```

## Recommendation
We suggest the following:
1. Update the `STRATEGY_TYPEHASH` to reflect the correct type `uint32` for the nonce.
2. Keep the `STRATEGY_TYPEHASH` using the non-inlined version below since the compiler would inline the value off-chain:
   ```solidity
   bytes32 public constant STRATEGY_TYPEHASH = keccak256("StrategyDetails(uint32 nonce,uint256 deadline,bytes32 root)");
   ```
3. To avoid name collision for the two structs, rename one of the `StrategyDetails` (even though one is not defined directly).

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Astaria-Spearbit-Security-Review.pdf)

---

### Example 2: [H-03] Risk of silent overflow in reserves update

**Source**: Code4rena
**Protocol**: Caviar
**Impact**: HIGH

**Details**:

<https://github.com/code-423n4/2023-04-caviar/blob/main/src/PrivatePool.sol#L230-L231> 

<https://github.com/code-423n4/2023-04-caviar/blob/main/src/PrivatePool.sol#L323-L324>

### Vulnerability details

The [`buy()`](https://github.com/code-423n4/2023-04-caviar/blob/main/src/PrivatePool.sol#L211) and [`sell()`](https://github.com/code-423n4/2023-04-caviar/blob/main/src/PrivatePool.sol#L301) functions update the `virtualBaseTokenReserves` and `virtualNftReserves` variables during each trade. However, these two variables are of type `uint128`, while the values that update them are of type `uint256`. This means that casting to a lower type is necessary, but this casting is performed without first checking that the values being cast can fit into the lower type. As a result, there is a risk of a silent overflow occurring during the casting process.

```solidity
    function buy(uint256[] calldata tokenIds, uint256[] calldata tokenWeights, MerkleMultiProof calldata proof) 
        public
        payable
        returns (uint256 netInputAmount, uint256 feeAmount, uint256 protocolFeeAmount)
    {
        // ~~~ Checks ~~~ //

        // calculate the sum of weights of the NFTs to buy
        uint256 weightSum = sumWeightsAndValidateProof(tokenIds, tokenWeights, proof);

        // calculate the required net input amount and fee amount
        (netInputAmount, feeAmount, protocolFeeAmount) = buyQuote(weightSum);
        ...
        // update the virtual reserves
        virtualBaseTo

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-04-caviar)

---

### Example 3: H-9: Downcasting to uint96 can cause assets to be lost for some tokens

**Source**: Sherlock
**Protocol**: Axis Finance
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2024-03-axis-finance-judging/issues/181 

## Found by 
FindEverythingX, hash, pseudoArtist
## Summary
Downcasting to uint96 can cause assets to be lost for some tokens

## Vulnerability Detail

After summing the individual bid amounts, the total bid amount is downcasted to uint96 without any checks

```solidity
            settlement_.totalIn = uint96(result.totalAmountIn);
```

uint96 can be overflowed for multiple well traded tokens:

Eg:

shiba inu :
current price = $0.00003058
value of type(uint96).max tokens ~= 2^96 * 0.00003058 / 10^18 == 2.5 million $

Hence auctions that receive more than type(uint96).max amount of tokens will be downcasted leading to extreme loss for the auctioner

## Impact

The auctioner will suffer extreme loss in situations where the auctions bring in >uint96 amount of tokens

## Code Snippet

downcasting totalAmountIn to uint96
https://github.com/sherlock-audit/2024-03-axis-finance/blob/cadf331f12b485bac184111cdc9ba1344d9fbf01/moonraker/src/modules/auctions/EMPAM.sol#L825

## Tool used

Manual Review

## Recommendation

Use a higher type or warn the user's of the limitations on the auction sizes



## Discussion

**0xJem**

Duplicate of #34 

**Oighty**

Pretty similar to #209. Might be a duplicate.

**nevillehuang**

Agree both hinges on a high `totalAmountIn`

**kosedogus**

Escalate

Since there are minutes until the end of auction period, I might miss something, if that is the case sorry about that.


*[Content truncated...]*

---

### Example 4: [M-02] The tier setting parameter are unsafely downcasted from type uint256 to type uint80 / uint48 / uint40 / uint16

**Source**: Code4rena
**Protocol**: Juicebox
**Impact**: MEDIUM

**Details**:

<https://github.com/jbx-protocol/juice-nft-rewards/blob/f9893b1497098241dd3a664956d8016ff0d0efd0/contracts/JBTiered721Delegate.sol#L240><br>
<https://github.com/jbx-protocol/juice-nft-rewards/blob/f9893b1497098241dd3a664956d8016ff0d0efd0/contracts/JBTiered721DelegateStore.sol#L628><br>
<https://github.com/jbx-protocol/juice-nft-rewards/blob/f9893b1497098241dd3a664956d8016ff0d0efd0/contracts/JBTiered721DelegateStore.sol#L689>

The tier setting parameter are unsafely downcasted from uint256 to uint80 / uint48 / uint16

the tier is setted by owner is crucial because the parameter affect how nft is minted.

the callstack is

`JBTiered721Delegate.sol#initialize` -> `Store#recordAddTiers`

```solidity
function recordAddTiers(JB721TierParams[] memory _tiersToAdd)
```

what does the struct `JB721TierParams` look like? all parameter in `JB721TierParams` is uint256 type

```solidity
struct JB721TierParams {
  uint256 contributionFloor;
  uint256 lockedUntil;
  uint256 initialQuantity;
  uint256 votingUnits;
  uint256 reservedRate;
  address reservedTokenBeneficiary;
  bytes32 encodedIPFSUri;
  bool allowManualMint;
  bool shouldUseBeneficiaryAsDefault;
}
```

however in side the function

```solidity
// Record adding the provided tiers.
if (_pricing.tiers.length > 0) _store.recordAddTiers(_pricing.tiers);
```

all uint256 parameter are downcasted.

```solidity
// Add the tier with the iterative ID.
_storedTierOf[msg.sender][_tierId] = JBStored721Tier({
contributionFloor: uint80(_tierTo

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-juicebox)

---

### Example 5: [M-02] Unsafe cast in `getCollateralRatio()`

**Source**: Code4rena
**Protocol**: Angle Protocol
**Impact**: MEDIUM

**Details**:

`LibGetters.getCollateralRatio()` might return the incorrect ratio due to the unsafe cast.

### Proof of Concept

`getCollateralRatio()` outputs the collateral ratio using the total collaterals and issued agTokens.

```solidity
    // The `stablecoinsIssued` value need to be rounded up because it is then used as a divizer when computing
    // the amount of stablecoins issued
    stablecoinsIssued = uint256(ts.normalizedStables).mulDiv(ts.normalizer, BASE_27, Math.Rounding.Up);
    if (stablecoinsIssued > 0)
        collatRatio = uint64(totalCollateralization.mulDiv(BASE_9, stablecoinsIssued, Math.Rounding.Up)); //@audit unsafe cast
    else collatRatio = type(uint64).max;
```

Typically, the `collatRatio` should be around `BASE_9` but the ratio might be larger than `type(uint64).max` during the initial stage.

Furthermore, `totalCollateralization` is calculated using the [raw balance of collaterals](https://github.com/AngleProtocol/angle-transmuter/blob/9707ee4ed3d221e02dcfcd2ebaa4b4d38d280936/contracts/transmuter/libraries/LibGetters.sol#L73) and it might be manipulated when [stablecoinsIssued](https://github.com/AngleProtocol/angle-transmuter/blob/9707ee4ed3d221e02dcfcd2ebaa4b4d38d280936/contracts/transmuter/libraries/LibGetters.sol#L85) is not large.

Then [collatRatio](https://github.com/AngleProtocol/angle-transmuter/blob/9707ee4ed3d221e02dcfcd2ebaa4b4d38d280936/contracts/transmuter/libraries/LibGetters.sol#L87) might be cast to the wrong value.

After all, `getCollater

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-dev-test-repo)

---

### Example 6: [M-10] Unsafe downcasting in issue(...) can be exploited to cause permanent DoS

**Source**: Code4rena
**Protocol**: Reserve
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/reserve-protocol/protocol/blob/df7ecadc2bae74244ace5e8b39e94bc992903158/contracts/p1/RToken.sol#L230-L243


## Vulnerability details

## Unsafe downcasting in `issue(...)` can be exploited to cause permanent DoS

#### Important note!
I first found this bug in `issue(...)` at first, but unsafe downcasting appears in many other areas of the codebase, and seem to also be exploitable but no PoC is provided due to time constraints. Either way, using some form of safe casting library to **replace all occurences** of unsafe downcasting will prevent all the issues. I also do not list the individual instances of unsafe downcasting as all occurences should be replaced with safe cast.

### Details
The `amtRToken` is a user supplied parameter in the `issue(uint256 amtRToken)` function
```sol
uint192 amtBaskets = uint192(
	totalSupply() > 0 ? mulDiv256(basketsNeeded, amtRToken, totalSupply()) : amtRToken
);
```
The calculated amount is unsafely downcasted into `uint192`.

This means that if the resulting calculation is a multiple of $2^{192}$, `amtBaskets = 0`

The code proceeds to the following line, where `erc20s` and `deposits` arrays will be empty since we are asking for a quote for 0. (see `quote(...)` in `BasketHandler.sol` where amounts are multiplied by zero)
```sol
(address[] memory erc20s, uint256[] memory deposits) = basketHandler.quote(
            amtBaskets,
            CEIL
        );
```
This means an attacker can call `issue(...)` with

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-reserve)

---

### Example 7: [M-21] Truncation in casting can lead to a founder receiving all the base tokens

**Source**: Code4rena
**Protocol**: Nouns Builder
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-09-nouns-builder/blob/7e9fddbbacdd7d7812e912a369cfd862ee67dc03/src/token/Token.sol#L71-L126><br>
<https://github.com/code-423n4/2022-09-nouns-builder/blob/7e9fddbbacdd7d7812e912a369cfd862ee67dc03/src/token/Token.sol#L88>

The initialize function of the `Token` contract receives an array of `FounderParams`, which contains the ownership percent of each founder as a `uint256`. The initialize function checks that the sum of the percents is not more than 100, but the value that is added to the sum of the percent is truncated to fit in `uint8`. This leads to an error because the value that is used for assigning the base tokens is the original, not truncated, `uint256` value.

This can lead to wrong assignment of the base tokens, and can also lead to a situation where not all the users will get the correct share of base tokens (if any).

### Proof of Concept

To verify this bug I created a foundry test. You can add it to the test folder and run it with `forge test --match-test testFounderGettingAllBaseTokensBug`.

This test deploys a token implementation and an `ERC1967` proxy that points to it, and initializes the proxy using an array of 2 founders, each having 256 ownership percent. The value which is added to the `totalOwnership` variable is a `uint8`, and when truncating 256 to fit in a `uint8` it will turn to 0, so this check will pass.

After the call to initialize, the test asserts that all the base token ids belongs to the first founder, w

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-09-nouns-builder)

---

### Example 8: [H-02] A malicious user can steal other user's deposits from Vault.sol

**Source**: Code4rena
**Protocol**: PoolTogether
**Impact**: HIGH

**Details**:

### Lines of code

<https://github.com/GenerationSoftware/pt-v5-vault/blob/b1deb5d494c25f885c34c83f014c8a855c5e2749/src/Vault.sol#L509-L521>
<https://github.com/GenerationSoftware/pt-v5-vault/blob/b1deb5d494c25f885c34c83f014c8a855c5e2749/src/Vault.sol#L407-L415>

### Impact

When the `Vault.withdraw()` function is called, a maximum of `type(uint96).max` shares are burnt subsequently: `Vault.withdraw()`-> `Vault._withdraw()`-> `Vault._burn` burns `uint96(_shares)`, see [Vault.sol line 1139](<https://github.com/GenerationSoftware/pt-v5-vault/blob/b1deb5d494c25f885c34c83f014c8a855c5e2749/src/Vault.sol#L1138-L1139>).

A malicious user can exploit this in the following way:

1. A malicious user deposits, for example, two times the value of `type(uint96).max` underlying assets into the Vault; calling the function `Vault.deposit()` two times. They can't deposit more in a single transaction because `type(uint96).max` is the maximum value to deposit.

2. Then, the malicious user calls `Vault.withdraw()` with a higher value of assets to withdraw more than `type(uint96).max`. For example, they withdraw (`2 * type(uint96).max`), which is the total amount of assets they deposited before.

3. Now what happens, is the Vault.sol contract only burns `type(uint96).max` shares for the user, but transfers `2 * type(uint96).max` underlying assets to the malicious user, which is the total amount they deposited before.

4. This happens because `Vault._burn()` only burns `uint96(shares)` shares of t

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-07-pooltogether)

---

### Example 9: Unsafe type-casting

**Source**: Spearbit
**Protocol**: Primitive
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
See below

## Description
Throughout the contract weve encountered various unsafe type-castings.

- **invariant**: Within the `_swap` function, the next invariant is an `int256` variable and is calculated within the `checkInvariant` function implemented in the `RMM01Portfolio`. This variable then is dangerously typecasted to `int128` and assigned to an `int256` variable in the iteration struct (L539). The down-casting from `int256` to `int128` assumes that the `nextInvariantWad` fits in an `int128`; in case it wont fit, it will overflow. The updated iteration object is passed to the `_feeSavingEffects` function, which based on the RMM implementation can lead to bad consequences.
  - `iteration.nextInvariant`
  - `_getLatestInvariantAndVirtualPrice`
  - `getNetBalance`

During account settlement, `getNetBalance` is called to compute the difference between the "physical reserves" (contract balance) and the internal reserves: `net = int256(physicalBalance) - int256(internalBalance)`. If the `internalBalance > int256.max`, it overflows into a negative value and the attacker is credited the entire physical balance + overflow upon settlement (and doesnt have to pay anything in settle). This might happen if an attacker allocates or swaps in very high amounts before settlement is called. Consider doing a safe typecast here as a legitimate possible revert would cause less issues than an actual overflow.
  - `getNetBalance`

### Encoding / Decoding

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Primitive-Spearbit-Security-Review.pdf)

---

### Example 10: M-6: Unsafe downcasting arithmetic operation in UserManager related contract and in UToken.sol

**Source**: Sherlock
**Protocol**: Union Finance
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-10-union-finance-judging/issues/96 

## Found by 
8olidity, ctf\_sec, Lambda

## Summary

The value is unsafely downcasted and truncated from uint256 to uint96 or uint128 in UserManager related contract and in UToken.sol.

## Vulnerability Detail

value can unsafely downcasted. let us look at it cast by cast.

In UserManagerDAI.sol 

```solidity
  function stakeWithPermit(
      uint256 amount,
      uint256 nonce,
      uint256 expiry,
      uint8 v,
      bytes32 r,
      bytes32 s
  ) external whenNotPaused {
      IDai erc20Token = IDai(stakingToken);
      erc20Token.permit(msg.sender, address(this), nonce, expiry, true, v, r, s);

      stake(uint96(amount));
  }
```
as we can see, the user's staking amount is downcasted from uint256 to uint96.

the same issue exists in UserManagerERC20.sol

In the context of UToken.sol, a bigger issue comes.

User invokes the borrow function in UToken.sol

```solidity
   function borrow(address to, uint256 amount) external override onlyMember(msg.sender) whenNotPaused nonReentrant {
```

and

```solidity
  // Withdraw the borrowed amount of tokens from the assetManager and send them to the borrower
  if (!assetManagerContract.withdraw(underlying, to, amount)) revert WithdrawFailed();

  // Call update locked on the userManager to lock this borrowers stakers. This function
  // will revert if the account does not have enough vouchers to cover the borrow amount. ie
  // the borrower is tryin

*[Content truncated...]*

---

### Example 11: M-7: Unsafe casting of user amount from `uint256` to `uint128`

**Source**: Sherlock
**Protocol**: Harpie
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-harpie-judging/tree/main/018-M 

## Found by 
Lambda, Tomo, hickuphh3, IllIllI, defsec, sirhashalot

## Summary

The unsafe casting of the recovered amount from `uint256` to `uint128` means the users funds will be lost.

## Vulnerability Detail

`logIncomingERC20()` has the recovered amount as type `uint256`, but `amountStored` is of type `uint128`. There is an unsafe casting when incrementing `amountStored`:

```solidity
_erc20WithdrawalAllowances[_originalAddress][_erc20Address].amountStored += uint128(_amount);
```

It is thus possible for the amount recorded to be less than the actual amount recovered.

## Impact

Loss of funds.

## Proof of Concept

The user's balance is `type(uint128).max = 2**128`, but the incremented amount will be zero.

## Recommendation

`amountStored` should be of type `uint256`. Alternatively, use [OpenZeppelins SafeCast library](https://docs.openzeppelin.com/contracts/4.x/api/utils#SafeCast) when casting from `uint256` to `uint128`.

## Lead Senior Watson
Not sure, any tokens which would have a token supply over `type(uint128).max` but I guess it's best to be proactive. The proposed fix does create some issues. Instead of having less tokens transferred to the vault, the contract will revert and prevent the transfer entirely. Arguably more funds would be at risk, so you may as well use `uint256` then or accept the risk and keep the slot packing.

## Harpie Team
Decided to accept the risk of reve

*[Content truncated...]*

---

### Example 12: M-7: Unsafe casting within _purchase function can result in overflow

**Source**: Sherlock
**Protocol**: Axis Finance
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-03-axis-finance-judging/issues/204 

## Found by 
FindEverythingX
## Summary
Unsafe casting within _purchase function can result in overflow

## Vulnerability Detail
Contract: FPAM.sol

The _purchase function is invoked whenever a user wants to buy some tokens from an FPAM auction. 

Note how the amount_ parameter is from type uint96:

[https://github.com/sherlock-audit/2024-03-axis-finance/blob/main/moonraker/src/modules/auctions/FPAM.sol#L128](https://github.com/sherlock-audit/2024-03-axis-finance/blob/main/moonraker/src/modules/auctions/FPAM.sol#L128)

The payout is then calculated as follows:

amount * 10^baseTokenDecimals / price

[https://github.com/sherlock-audit/2024-03-axis-finance/blob/main/moonraker/src/modules/auctions/FPAM.sol#L135](https://github.com/sherlock-audit/2024-03-axis-finance/blob/main/moonraker/src/modules/auctions/FPAM.sol#L135)

The crux: The quote token can be with 6 decimals and the base token with 18 decimals.

This would then potentially result in an overflow and the payout is falsified. 

Consider the following PoC:

amount = 1_000_000_000e6 (fees can be deducted or not, this does not matter for this PoC)

baseTokenDecimals = 18

price = 1e4

This price basically means, a user will receive 1e18 BASE tokens for 1e4 (0.01) QUOTE tokens, respectively a user must provide 1e4 (0.01) QUOTE tokens to receive 1e18 BASE tokens

The calculation would be as follows:

1_000_000_000e6 * 1e18 / 1e4 = 1e29

while

*[Content truncated...]*

---

### Example 13: M-1: Unsafe type casting of `poolValue` can malfunction the whole market

**Source**: Sherlock
**Protocol**: Float Capital
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-float-capital-judging/issues/45 

## Found by 
WATCHPUG

## Summary

When `poolValue` is a negative number due to loss in `valueChange` and `funding`, the unsafe type casting from `int256` to `uint256` will result in a huge number close to `2**255` which will revert `_rebalancePoolsAndExecuteBatchedActions()` due to overflow when multiplied by 1e18 at L163.

## Vulnerability Detail

If the funding rate is 100% per year and the `EPOCH_LENGTH` is 4 days, the funding fee for each epoch can be as much as ~1% on the effectiveValue.

Plus, the loss from `valueChange` is capped at 99%, but combining both can still result in a negative `poolValue` at L146.

At L163 `uint256 price = uint256(poolValue).div(tokenSupply);` the type casting from `int256` to `uint256` will result in a huge number close to `2**255`.

`MathUintFloat.div()` will overflow when a number as large as `2**255` is multiplied by 1e18.

## Impact

`_rebalancePoolsAndExecuteBatchedActions` will revert and cause the malfunction of the whole market.

## Code Snippet

https://github.com/sherlock-audit/2022-11-float-capital/blob/main/contracts/market/template/MarketCore.sol#L118-L185

## Tool used

Manual Review

## Recommendation

Consider adding a new function to properly handle the bankruptcy of a specific pool.

## Discussion

**JasoonS**

We seed the pools initially with sufficient un-extractable capital such that this shouldn't be an issue (it should never get close 

*[Content truncated...]*

---

### Example 14: [M-05] Unsafe casting from int128 can cause wrong accounting of locked amounts

**Source**: Code4rena
**Protocol**: FIAT DAO
**Impact**: MEDIUM

**Details**:

_Submitted by CertoraInc, also found by 0x1f8b, carlitox477, cRat1st0s, DecorativePineapple, joestakey, ladboy233, reassor, and rvierdiiev_

<https://github.com/code-423n4/2022-08-fiatdao/blob/fece3bdb79ccacb501099c24b60312cd0b2e4bb2/contracts/VotingEscrow.sol#L418><br>

The unsafe casting to int128 variable can cause its value to be different from the correct value. For example in the createLock function, the addition to the locked amount variable is done by `locked_.amount += int128(int256(_value))`. In that case, if `_value` is greater than `type(int128).max` which is `2**127 - 1`, then the accounting will be wrong and the amount that will be added to `locked_.amount` will be less than the amount of token that will be transferred from the user. Then the user won't be able to withdraw the tokens that he transferred, and they'll be stuck in the contract forever.

### Proof of Concept

1.  Alice tries to lock `2**128` tokens. She calls `createLock(2**128, unlockTime)` with the time she wants to lock for.
2.  The addition of the given value is done by `locked_.amount += int128(int256(_value))`, which actually does nothing to the `locked_.amount` variable and it remains 0. That's because when casting `int128(int256(2**128))` truncates to 0, and that leaves the locked amount unchanged but the tokens are transferred.

### Tools Used

Manual auditing - VS Code and me :)

### Recommended Mitigation Steps

Make sure that the values fit in the variables you are trying to assign them 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-08-fiatdao)

---

## Statistics

- Total findings analyzed: 14
- Examples shown: 14
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

