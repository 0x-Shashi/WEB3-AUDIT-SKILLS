# SafeTransfer Security Patterns

## Overview

**Frequency**: 14 occurrences (0.03% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 5 | 9 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Cyfrin

---

## Detection Checklist

- [ ] Check for safetransfer vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-01] Unchecked ERC20 transfers can cause lock up

**Source**: Code4rena
**Protocol**: Reality Cards
**Impact**: HIGH

**Details**:

_Submitted by [axic](https://twitter.com/alexberegszaszi), also found by [gpersoon](https://twitter.com/gpersoon), [pauliax](https://twitter.com/SolidityDev), [Jmukesh](https://twitter.com/MukeshJ_eth), [a_delamo](https://twitter.com/a_delamo), [s1m0](https://twitter.com/_smonica_), [cmichel](https://twitter.com/cmichelio), and [shw](https://github.com/x9453)_

Some major tokens went live before ERC20 was finalized, resulting in a discrepancy whether the transfer functions should (A) return a boolean or (B) revert/fail on error. The current best practice is that they should revert, but return “true” on success. However, not every token claiming ERC20-compatibility is doing this — some only return true/false; some revert, but do not return anything on success. This is a well known issue, heavily discussed since mid-2018.

Today many tools, including OpenZeppelin, offer [a wrapper for “safe ERC20 transfer”](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/utils/SafeERC20.sol):

RealityCards is not using such a wrapper, but instead tries to ensure successful transfers via the `balancedBooks` modifier:

```solidity
modifier balancedBooks {
    _;
    // using >= not == in case anyone sends tokens direct to contract
    require(
        erc20.balanceOf(address(this)) >=
            totalDeposits + marketBalance + totalMarketPots,
        "Books are unbalanced!"
    );
}
```

This modifier is present on most functions, but is missing on `topu

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-06-realitycards)

---

### Example 2: [M-02] Use `safeTransferFrom` Instead of `transferFrom` for ERC721

**Source**: Code4rena
**Protocol**: Golom
**Impact**: MEDIUM

**Details**:

[GolomTrader.sol#L236](https://github.com/code-423n4/2022-07-golom/blob/7bbb55fca61e6bae29e57133c1e45806cbb17aa4/contracts/core/GolomTrader.sol#L236)<br>

Use of `transferFrom` method for ERC721 transfer is discouraged and recommended to use safeTransferFrom whenever possible by OpenZeppelin.<br>
This is because `transferFrom()` cannot check whether the receiving address know how to handle ERC721 tokens.

In the function shown at below PoC, ERC721 token is sent to `msg.sender` with the `transferFrom` method.<br>
If this `msg.sender` is a contract and is not aware of incoming ERC721 tokens, the sent token could be locked up in the contract forever.

Reference: <https://docs.openzeppelin.com/contracts/3.x/api/token/erc721>

### Proof of Concept
```
GolomTrader.sol:236:            ERC721(o.collection).transferFrom(o.signer, receiver, o.tokenId);
```

### Recommended Mitigation Steps

I recommend to call the `safeTransferFrom()` method instead of `transferFrom()` for NFT transfers.

**[0xsaruman (Golom) confirmed, but disagreed with severity](https://github.com/code-423n4/2022-07-golom-findings/issues/342)**

**[0xsaruman (Golom) resolved and commented](https://github.com/code-423n4/2022-07-golom-findings/issues/342#issuecomment-1236301290):**
 > Resolved https://github.com/golom-protocol/contracts/commit/366c0455547041003c28f21b9afba48dc33dc5c7#diff-63895480b947c0761eff64ee21deb26847f597ebee3c024fb5aa3124ff78f6ccR238



***

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-golom)

---

### Example 3: H-1: Use safeTransfer/safeTransferFrom consistently instead of transfer/transferFrom

**Source**: Sherlock
**Protocol**: Cooler
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-cooler-judging/issues/335 

## Found by 
tsvetanovv, 0x52, polthedev, wagmi, enckrish, ak1, IllIllI, yongkiws, ctrlc03, zaskoh, Trumpero, TrungOre, Breeje, imare, jonatascm, cccz, Metadev, Nyx, neumo, Atarpara, serial-coder, yixxas, Tricko, 8olidity, Qeew, ahmedovv, libratus, usmannk, MohanVarma, psy4n0n, 0x4non, kiki\_dev, peanuts, 0xhacksmithh, eyexploit, 0xSmartContract, supernova, Zarf, thekmj, ltyu, ck, sach1r0, hansfriese, John, HollaDieWaldfee, HonorLt, rvierdiiev, zaevlad, 0xAgro, Avci, gjaldon, Madalad, ch0bu, bin2chen, Bahurum, seyni, 0xadrii, Deivitto

## Summary
Use safeTransfer/safeTransferFrom consistently instead of transfer/transferFrom
## Vulnerability Detail
Some tokens do not revert on failure, but instead return false (e.g. [ZRX](https://etherscan.io/address/0xe41d2489571d322189246dafa5ebde1f4699f498#code)).
https://github.com/d-xo/weird-erc20/#no-revert-on-failure
tranfser/transferfrom is directly used to send tokens in many places in the contract and the return value is not checked.
If the token send fails, it will cause a lot of serious problems.
For example, in the clear function, if debt token is ZRX, the lender can clear request without providing any debt token.
```solidity
    function clear (uint256 reqID) external returns (uint256 loanID) {
        Request storage req = requests[reqID];

        factory.newEvent(reqID, CoolerFactory.Events.Clear);

        if (!req.active) 
            revert Deact

*[Content truncated...]*

---

### Example 4: [H-03] Result of transfer / transferFrom not checked

**Source**: Code4rena
**Protocol**: Spartan Protocol
**Impact**: HIGH

**Details**:

## Handle

gpersoon


## Vulnerability details

## Impact
A call to transferFrom or transfer is frequently done without checking the results.
For certain ERC20 tokens, if insufficient tokens are present, no revert occurs but a result of "false" is returned.
So its important to check this. If you don't you could mint tokens without have received sufficient tokens to do so. So you could loose funds.

Its also a best practice to check this.
See below for example where the result isn't checked.

Note, in some occasions the result is checked (see below for examples).

## Proof of Concept
Highest risk:
.\Dao.sol:                iBEP20(_token).transferFrom(msg.sender, address(this), _amount); // Transfer user's assets to Dao contract
.\Pool.sol:               iBEP20(TOKEN).transfer(member, outputToken); // Transfer the TOKENs to user
.\Pool.sol:               iBEP20(token).transfer(member, outputAmount); // Transfer the swap output to the selected user
.\poolFactory.sol:   iBEP20(_token).transferFrom(msg.sender, _pool, _amount);
.\Router.sol:           iBEP20(_fromToken).transfer(fromPool, iBEP20(_fromToken).balanceOf(address(this))); // Transfer TOKENs from ROUTER to fromPool
.\Router.sol:           iBEP20(_token).transfer(_pool, iBEP20(_token).balanceOf(address(this))); // Transfer TOKEN to pool
.\Router.sol:           iBEP20(_token).transferFrom(msg.sender, _pool, _amount); // Transfer TOKEN to pool
.\Router.sol:           iBEP20(_token).transfer(_recipient, _amount); // Transfer

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-07-spartan)

---

### Example 5: [H-01] Unsafe handling of underlying tokens

**Source**: Code4rena
**Protocol**: Swivel
**Impact**: HIGH

**Details**:

_Submitted by 0xsanson, also found by 0xRajeev, cmichel, defsec, GalloDaSballo, JMukesh, leastwood, loop, nikitastupin, pants, and pauliax_.

#### Impact

Not every ERC20 token follows OpenZeppelin's recommendation. It's possible (inside ERC20 standard) that a `transferFrom` doesn't revert upon failure but returns `false`.

The code doesn't check these return values. For example `uToken.transferFrom(msg.sender, o.maker, a);` in `initiateVaultFillingZcTokenInitiate` can be exploited by the msg.sender to initiate a trade without sending any underlying.

#### Proof of Concept

`grep 'transfer' Swivel.sol`

#### Tools Used

editor

#### Recommended Mitigation Steps

Consider using [OpenZeppelin's library](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/utils/SafeERC20.sol) with *safe* versions of transfer functions.

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-09-swivel)

---

### Example 6: Use safe transfer for ERC20 tokens

**Source**: Cyfrin
**Protocol**: Swapexchange
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Description:** The protocol intends to support all ERC20 tokens but the implementation uses the original transfer functions.
Some tokens (like USDT) do not implement the EIP20 standard correctly and their transfer/transferFrom function return void instead of a success boolean. Calling these functions with the correct EIP20 function signatures will revert.

```solidity
TransferUtils.sol
34:     function _transferERC20(address token, address to, uint256 amount) internal {
35:         IERC20 erc20 = IERC20(token);
36:         require(erc20 != IERC20(address(0)), "Token Address is not an ERC20");
37:         uint256 initialBalance = erc20.balanceOf(to);
38:         require(erc20.transfer(to, amount), "ERC20 Transfer failed");//@audit-issue will revert for USDT
39:         uint256 balance = erc20.balanceOf(to);
40:         require(balance >= (initialBalance + amount), "ERC20 Balance check failed");
41:     }
```

**Impact:** Tokens that do not correctly implement the EIP20 like USDT, will be unusable in the protocol as they revert the transaction because of the missing return value.

**Recommended Mitigation:** We recommend using OpenZeppelin's SafeERC20 versions with the safeTransfer and safeTransferFrom functions that handle the return value check as well as non-standard-compliant tokens.

**Protocol:** Fixed in commit [564f711](https://github.com/SwapExchangeio/Contracts/commit/564f711c6f915f5a7696739266a1f8059ee9a172)

**Cyfrin:** Verified.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-19-cyfrin-swapexchange.md)

---

### Example 7: [H-01] Unsafe usage of ERC20 transfer and transferFrom 

**Source**: Code4rena
**Protocol**: FIAT DAO
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-08-fiatdao/blob/fece3bdb79ccacb501099c24b60312cd0b2e4bb2/contracts/VotingEscrow.sol#L425-L428
https://github.com/code-423n4/2022-08-fiatdao/blob/fece3bdb79ccacb501099c24b60312cd0b2e4bb2/contracts/VotingEscrow.sol#L485-L488
https://github.com/code-423n4/2022-08-fiatdao/blob/fece3bdb79ccacb501099c24b60312cd0b2e4bb2/contracts/VotingEscrow.sol#L546
https://github.com/code-423n4/2022-08-fiatdao/blob/fece3bdb79ccacb501099c24b60312cd0b2e4bb2/contracts/VotingEscrow.sol#L657
https://github.com/code-423n4/2022-08-fiatdao/blob/fece3bdb79ccacb501099c24b60312cd0b2e4bb2/contracts/VotingEscrow.sol#L676


## Vulnerability details

## Impact
Some ERC20 tokens functions don't return a boolean, for example USDT, BNB, OMG. So the `VotingEscrow` contract simply won't work with tokens like that as the `token`. 

## Proof of Concept
The USDT's `transfer` and `transferFrom` functions doesn't return a bool, so the call to these functions will revert although the user has enough balance and the `VotingEscrow` contract won't work, assuming that token is USDT.

## Tools Used
Manual auditing - VS Code, some hardhat tests and me :)

## Recommended Mitigation Steps
Use the OpenZepplin's `safeTransfer` and `safeTransferFrom` functions

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-08-fiatdao)

---

### Example 8: M-2: Users might lose funds as `claimERC20Prize()` doesn't revert for no-revert-on-transfer tokens

**Source**: Sherlock
**Protocol**: Footium
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-footium-judging/issues/86 

## Found by 
0xAsen, 0xGoodess, 0xGusMcCrae, 0xPkhatri, 0xRobocop, 0xStalin, 0xeix, 0xmuxyz, 0xnirlin, 14si2o\_Flint, 8olidity, ACai7, AlexCzm, BAHOZ, Bauchibred, Bauer, Cryptor, DevABDee, Diana, GimelSec, J4de, Koolex, MiloTruck, PRAISE, PTolev, Phantasmagoria, Piyushshukla, PokemonAuditSimulator, Polaris\_tow, Proxy, Quantish, R-Nemes, SanketKogekar, Sulpiride, TheNaubit, Tricko, \_\_141345\_\_, abiih, alliums8520, ast3ros, berlin-101, cergyk, ctf\_sec, cuthalion0x, dacian, ddimitrov22, deadrxsezzz, djxploit, favelanky, georgits, holyhansss, innertia, jasonxiale, josephdara, jprod15, kiki\_dev, l3r0ux, lewisbroadhurst, nzm\_, oot2k, oualidpro, peanuts, ravikiran.web3, sach1r0, santipu\_, sashik\_eth, shaka, shame, thekmj, tibthecat, tsvetanovv, whoismatthewmc1, wzrdk3lly, yy
## Summary

Users can call `claimERC20Prize()` without actually receiving tokens if a no-revert-on-failure token is used, causing a portion of their claimable tokens to become unclaimable.

## Vulnerability Detail

In the `FootiumPrizeDistributor` contract, whitelisted users can call `claimERC20Prize()` to claim ERC20 tokens. The function adds the amount of tokens claimed to the user's total claim amount, and then transfers the tokens to the user:

[FootiumPrizeDistributor.sol#L128-L131](https://github.com/sherlock-audit/2023-04-footium/blob/main/footium-eth-shareable/contracts/FootiumPrizeDistributor.sol#L128-L131)

```solidi

*[Content truncated...]*

---

### Example 9: [M-02] `_payoutToken[s]()` is not compatible with tokens with missing return value

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: MEDIUM

**Details**:

[PA1D.sol#L317](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/src/enforcer/PA1D.sol#L317)<br>
[PA1D.sol#L340](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/src/enforcer/PA1D.sol#L340)<br>

Payout is blocked and tokens are stuck in contract.

### Proof of Concept

`PA1D._payoutToken()` and `PA1D._payoutTokens()` call `ERC20.transfer()` in a require-statement to send tokens to a list of payout recipients.<br>
Some tokens do not return a bool (e.g. USDT, BNB, OMG) on ERC20 methods. But since the require-statement expects a `bool`, for such a token a `void` return will also cause a revert, despite an otherwise successful transfer. That is, the token payout will always revert for such tokens.

### Recommended Mitigation Steps

Use [OpenZeppelin's SafeERC20](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/utils/SafeERC20.sol), which handles the return value check as well as non-standard-compliant tokens.

**[alexanderattar (Holograph) commented](https://github.com/code-423n4/2022-10-holograph-findings/issues/456#issuecomment-1306632476):**
 > Low priority, but can be updated to ensure compatibility with all ERC20 tokens.

**[alexanderattar (Holograph) linked a PR](https://github.com/code-423n4/2022-10-holograph-findings/issues/456#issuecomment-1306632476):**
 > [Feature/holo 612 royalty smart contract improvements](https://github.com/holographxyz/

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 10: M-7: Code does not handle ERC20 tokens with special `transfer` implementation

**Source**: Sherlock
**Protocol**: Sense
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-sense-judging/issues/10 

## Found by 
cryptphi, pashov

## Summary
Calls to ERC20::transfer method should always be checked

## Vulnerability Detail
Some ERC20 tokens do not revert on failure in `transfer` but instead return `false` as a return value (for example [ZRX](https://etherscan.io/address/0xe41d2489571d322189246dafa5ebde1f4699f498#code)). Because of this it has become a common practice to use OpenZeppelin's SafeERC20 to handle such weird tokens. If `transfer` fails, but does not revert it can leave tokens stuck in the contract - for example in `eject` in `AutoRoller` we have such a non-checked `transfer`, but if it failed the tokens would get stuck, before the shares used for `eject` were already burned.

## Impact
The impact is potentially permanently lost (stuck) value for users of the protocol, but it needs a special ERC20 token to be used as `underlying` or to be sent in contract by mistake, hence Medium severity.

## Code Snippet
https://github.com/sherlock-audit/2022-11-sense/blob/main/contracts/src/AutoRoller.sol#L656
https://github.com/sherlock-audit/2022-11-sense/blob/main/contracts/src/AutoRoller.sol#L659
https://github.com/sherlock-audit/2022-11-sense/blob/main/contracts/src/AutoRoller.sol#L715

## Tool used

Manual Review

## Recommendation
Use OpenZeppelin's SafeERC20 library to handle such tokens

## Discussion

**jparklev**

We will add the safe transfer functions to the remaining locations

**jparklev

*[Content truncated...]*

---

### Example 11: [M-07] Using `transferFrom` on ERC721 tokens

**Source**: Code4rena
**Protocol**: PoolTogether
**Impact**: MEDIUM

**Details**:

_Submitted by shw_

In the function `awardExternalERC721` of contract `PrizePool`, when awarding external ERC721 tokens to the winners, the `transferFrom` keyword is used instead of `safeTransferFrom`. If any winner is a contract and is not aware of incoming ERC721 tokens, the sent tokens could be locked.

Recommend consider changing `transferFrom` to `safeTransferFrom` at line 602. However, it could introduce a DoS attack vector if any winner maliciously rejects the received ERC721 tokens to make the others unable to get their awards. Possible mitigations are to use a `try/catch` statement to handle error cases separately or provide a function for the pool owner to remove malicious winners manually if this happens.

**[asselstine (PoolTogether) confirmed and disagreed with severity](https://github.com/code-423n4/2021-06-pooltogether-findings/issues/115#issuecomment-868021913):**
 > This issue poses no risk to the Prize Pool, so it's more of a `1 (Low Risk` IMO.
>
> This is just about triggering a callback on the ERC721 recipient.  We omitted it originally because we didn't want a revert on the callback to DoS the prize pool.
>
> However, to respect the interface it makes sense to implement it fully.  That being said, if it does throw we must ignore it to prevent DoS attacks.

**[dmvt (judge) commented](https://github.com/code-423n4/2021-06-pooltogether-findings/issues/115#issuecomment-907507608):**
 > I agree with the medium risk rating provided by the warden.

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-06-pooltogether)

---

### Example 12: [M-03] Use safeTransfer()/safeTransferFrom() instead of transfer()/transferFrom()

**Source**: Code4rena
**Protocol**: Rubicon
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-05-rubicon/blob/8c312a63a91193c6a192a9aab44ff980fbfd7741/contracts/RubiconRouter.sol#L251


## Vulnerability details

## Impact

It is a good idea to add a `require()` statement that checks the return value of ERC20 token transfers or to use something like OpenZeppelin’s `safeTransfer()`/`safeTransferFrom()` unless one is sure the given token reverts in case of a failure. Failure to do so will cause silent failures of transfers and affect token accounting in contract.

However, using `require()` to check transfer return values could lead to issues with non-compliant ERC20 tokens which do not return a boolean value. Therefore, it's highly advised to use OpenZeppelin’s `safeTransfer()`/`safeTransferFrom()`.

## Proof of Concept

**RubiconRouter.sol**

[L251](https://github.com/code-423n4/2022-05-rubicon/blob/8c312a63a91193c6a192a9aab44ff980fbfd7741/contracts/RubiconRouter.sol#L251): `ERC20(route[route.length - 1]).transfer(to, currentAmount);`\
[L303](https://github.com/code-423n4/2022-05-rubicon/blob/8c312a63a91193c6a192a9aab44ff980fbfd7741/contracts/RubiconRouter.sol#L303): `ERC20(buy_gem).transfer(msg.sender, fill);`\
[L320](https://github.com/code-423n4/2022-05-rubicon/blob/8c312a63a91193c6a192a9aab44ff980fbfd7741/contracts/RubiconRouter.sol#L320): `ERC20(buy_gem).transfer(msg.sender, fill);`\
[L348](https://github.com/code-423n4/2022-05-rubicon/blob/8c312a63a91193c6a192a9aab44ff980fbfd7741/contracts/RubiconRouter.sol#L34

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-rubicon)

---

### Example 13: [M-06] `SafeERC20.sol` is imported but not used in the `transferBribes()` function

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: MEDIUM

**Details**:

_Submitted by jayjonah8, also found by cccz, cmichel, Dravee, gzeon, hyh, IllIllI, leastwood, NoamYakov, and Omik_

In BribeVault.sol the transferBribes() function uses token.transfer() instead of token.safeTransfer.
Tokens that don’t correctly implement the latest EIP20 spec, like USDT, will be unusable in the protocol as they revert the transaction because of the missing return value.  The fact that the SafeERC20.sol library is imported at the top of the BribeVault.sol implies that safeTransfer should be being used but may have been forgotten.

### Proof of Concept

[BribeVault.sol#L296](https://github.com/code-423n4/2022-02-redacted-cartel/blob/main/contracts/BribeVault.sol#L296)<br>

### Recommended Mitigation Steps

It's recommended to use OpenZeppelin’s SafeERC20 versions with the safeTransfer and safeTransferFrom functions that handle the return value check as well as non-standard-compliant tokens.

**[kphed (Redacted Cartel) confirmed and commented](https://github.com/code-423n4/2022-02-redacted-cartel-findings/issues/4#issuecomment-1040506429):**
 > Good catch!
> 
> Thanks again for participating in our contest jayjonah8, looking forward to more feedback/suggestions/comments.

**[Alex the Entreprenerd (judge) decreased severity to Medium and commented](https://github.com/code-423n4/2022-02-redacted-cartel-findings/issues/4#issuecomment-1059786452):**
 > Agree with the finding, because this is contingent on the specific token failing. I believe Medium severity to be m

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-02-redacted-cartel)

---

### Example 14: M-1: Use safeTransferFrom() instead of transferFrom().

**Source**: Sherlock
**Protocol**: DODO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-dodo-judging/issues/47 

## Found by 
sach1r0, Nyx, yixxas, 0x4non, Tomo

## Summary

The ERC20.transfer() and ERC20.transferFrom() functions return a boolean value indicating success. This parameter needs to be checked for success. Some tokens do not revert if the transfer failed but return false instead.

## Vulnerability Detail
Some tokens (like USDT) don't correctly implement the EIP20 standard and their transfer/ transferFrom function return void instead of a success boolean. Calling these functions with the correct EIP20 function signatures will always revert.
## Impact
Tokens that don't actually perform the transfer and return false are still counted as a correct transfer and tokens that don't correctly implement the latest EIP20 spec, like USDT, will be unusable in the protocol as they revert the transaction because of the missing return value.
## Code Snippet
https://github.com/sherlock-audit/2022-11-dodo/blob/main/contracts/SmartRoute/DODORouteProxy.sol#L420

https://github.com/sherlock-audit/2022-11-dodo/blob/main/contracts/SmartRoute/DODORouteProxy.sol#L423
## Tool used

Manual Review

## Recommendation
Recommend using OpenZeppelin's SafeERC20 versions with the safeTransfer and safeTransferFrom functions that handle the return value check as well as non-standard-compliant tokens.

## Discussion

**Evert0x**

We think a medium is still valid, although no direct loss of funds, a failed token transfer should be catche

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 14
- Examples shown: 14
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

