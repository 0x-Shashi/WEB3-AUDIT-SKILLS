# transferFrom vs safeTransferFrom Security Patterns

## Overview

**Frequency**: 14 occurrences (0.03% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 13 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Pashov Audit Group, Cyfrin

---

## Detection Checklist

- [ ] Check for transferfrom vs safetransferfrom vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [M-02] Use `safeTransferFrom` Instead of `transferFrom` for ERC721

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

### Example 2: H-1: Use safeTransfer/safeTransferFrom consistently instead of transfer/transferFrom

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

### Example 3: Use safe transfer for ERC20 tokens

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

### Example 4: [M-03] Use a safe transfer helper library for ERC20 transfers

**Source**: Code4rena
**Protocol**: Juicebox
**Impact**: MEDIUM

**Details**:

_Submitted by horsefacts, also found by 0x1f8b, 0x29A, 0x52, 0xf15ers, AlleyCat, apostle0x01, berndartmueller, cccz, Ch&#95;301, Chom, cloudjunky, codexploder, cryptphi, delfin454000, durianSausage, fatherOfBlocks, Franfran, hake, hansfriese, hyh, IllIllI, jonatascm, Kaiziron, Limbooo, m&#95;Rassska, Meera, oyc&#95;109, peritoflores, rajatbeladiya, rbserver, Ruhum, Sm4rty, svskaushik, and zzzitron_

`JBERC20PaymentTerminal#_transferFrom` calls `IERC20#transfer` and `transferFrom` directly. There are two issues with using this interface directly:

1.  `JBERC20PaymentTerminal#_transferFrom` function does not check the return value of these calls. Tokens that return `false` rather than revert to indicate failed transfers may silently fail rather than reverting as expected.

2.  Since the IERC20 interface requires a boolean return value, attempting to transfer ERC20s with [missing return values](https://github.com/d-xo/weird-erc20#missing-return-values) will revert. This means Juicebox payment terminals cannot support a number of popular ERC20s, including USDT and BNB.

[`JBERC20PaymentTerminal#_transferFrom`](https://github.com/jbx-protocol/juice-contracts-v2-code4rena/blob/828bf2f3e719873daa08081cfa0d0a6deaa5ace5/contracts/JBERC20PaymentTerminal.sol#L81-L89):

```solidity
  function _transferFrom(
    address _from,
    address payable _to,
    uint256 _amount
  ) internal override {
    _from == address(this)
      ? IERC20(token).transfer(_to, _amount)
      : IERC20(token).t

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-juicebox)

---

### Example 5: [M-09] Use safeTransferFrom instead of transferFrom for ERC721 transfers

**Source**: Code4rena
**Protocol**: Cally
**Impact**: MEDIUM

**Details**:

_Submitted by hickuphh3, also found by antonttc, berndartmueller, catchup, cccz, dipp, FSchmoede, GimelSec, hake, jah, jayjonah8, joestakey, kebabsec, Kenshin, Kumpa, MiloTruck, minhquanym, peritoflores, rfa, shenwilly, WatchPug, and ynnad_

<https://github.com/code-423n4/2022-05-cally/blob/1849f9ee12434038aa80753266ce6a2f2b082c59/contracts/src/Cally.sol#L199>

<https://github.com/code-423n4/2022-05-cally/blob/1849f9ee12434038aa80753266ce6a2f2b082c59/contracts/src/Cally.sol#L295>

<https://github.com/code-423n4/2022-05-cally/blob/1849f9ee12434038aa80753266ce6a2f2b082c59/contracts/src/Cally.sol#L344>

### Details & Impact

The `transferFrom()` method is used instead of `safeTransferFrom()`, presumably to save gas. I however argue that this isn’t recommended because:

*   [OpenZeppelin’s documentation](https://docs.openzeppelin.com/contracts/4.x/api/token/erc721#IERC721-transferFrom-address-address-uint256-) discourages the use of `transferFrom()`, use `safeTransferFrom()` whenever possible
*   Given that any NFT can be used for the call option, there are a few NFTs (here’s an [example](https://github.com/sz-piotr/eth-card-game/blob/master/src/ethereum/contracts/ERC721Market.sol#L20-L31)) that have logic in the `onERC721Received()` function, which is only triggered in the `safeTransferFrom()` function and not in `transferFrom()`

### Recommended Mitigation Steps

Call the `safeTransferFrom()` method instead of `transferFrom()` for NFT transfers. Note that the `CallyNft` contrac

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-cally)

---

### Example 6: [M-04] Incorrect usage of safeTransferFrom traps fees in Papr Controller

**Source**: Code4rena
**Protocol**: Backed Protocol
**Impact**: MEDIUM

**Details**:

Because the Papr Controller never gives approval for ERC20 transfers, calls to `safeTransferFrom` on the Papr token will revert with insufficient approval. This will trap proceeds from auctions in the contract and prevent the owner/ DAO from collecting fees, motivating the rating of high severity. The root cause of this issue is misusing `safeTransferFrom` to transfer tokens directly out of the contract instead of using `transfer` directly. The contract will hold the token balance and thus does not need approval to transfer tokens, nor can it approve token transfers in the current implementation.

### Proof of Concept

Comment out [this token approval](https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/test/paprController/OwnerFunctions.ft.sol#L67) as the controller contract does not implement functionality to call approve. It doesn't make sense to "prank" a contract account in this context because it deviates from the runtime behavior of the deployed contract. That is, it's impossible for the Papr Controller to approve token transfers. Run `forge test -m testSendPaprFromAuctionFeesWorksIfOwner` and observe that it fails because of insufficient approvals. Replace [the call to `safeTransferFrom`](https://github.com/with-backed/papr/blob/9528f2711ff0c1522076b9f93fba13f88d5bd5e6/src/PaprController.sol#L383) with a call to `transfer(to, amount)` and rerun the test. It will now pass and correctly achieve the intended behavior.

### Tools Used

Foundr

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-backed)

---

### Example 7: [M-01] Unhandled return values of transfer and transferFrom

**Source**: Code4rena
**Protocol**: Inverse Finance
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L205
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L280
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L399
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L537
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L570
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L602


## Vulnerability details

## Impact
ERC20 implementations are not always consistent. Some implementations of transfer and transferFrom could return ‘false’ on failure instead of reverting. It is safer to wrap such calls into require() statements to these failures.


## Proof of Concept
Provide direct links to all referenced code in GitHub. Add screenshots, logs, or any other relevant proof that illustrates the concept.
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L205
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L280
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L399
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L537
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L570
https://github.com/code-423n4/2022-10-inverse/blob/main/src/Market.sol#L602
## Tools Used
Read the codes

## Recommended Mitigation Steps
Check the return value and revert on 0/false or use OpenZeppelin’s SafeERC20 wrappe

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-inverse)

---

### Example 8: [M-02] `_payoutToken[s]()` is not compatible with tokens with missing return value

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

### Example 9: M-3: Using `ERC721.transferFrom()` instead of `safeTransferFrom()` may cause the user's NFT to be frozen in a contract that does not support ERC721

**Source**: Sherlock
**Protocol**: FrankenDAO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-frankendao-judging/issues/55 

## Found by 
saian, rvierdiiev, WATCHPUG, Tomo, Bnke0x0, Nyx

## Summary

There are certain smart contracts that do not support ERC721, using `transferFrom()` may result in the NFT being sent to such contracts.

## Vulnerability Detail

In `unstake()`, `_to` is param from user's input.

However, if `_to` is a contract address that does not support ERC721, the NFT can be frozen in that contract.

As per the documentation of EIP-721:

> A wallet/broker/auction application MUST implement the wallet interface if it will accept safe transfers.

Ref: https://eips.ethereum.org/EIPS/eip-721

## Impact

The NFT may get stuck in the contract that does support ERC721.

## Code Snippet

https://github.com/sherlock-audit/2022-11-frankendao/blob/main/src/Staking.sol#L463-L489

## Tool used

Manual Review

## Recommendation

Consider using `safeTransferFrom()` instead of `transferFrom()`.

## Discussion

**zobront**

Fixed: https://github.com/Solidity-Guild/FrankenDAO/pull/10

---

### Example 10: M-2: Unsafe ERC20 methods

**Source**: Sherlock
**Protocol**: Telcoin
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-telcoin-judging/issues/82 

## Found by 
0x4non, 0xAgro, yixxas, 0xheynacho, Bnke0x0, WATCHPUG, aphak5010, rotcivegaf, Mukund, hickuphh3, pashov, hyh, Deivitto, rvierdiiev, eierina

## Summary

Using unsafe ERC20 methods can revert the transaction for certain tokens.

## Vulnerability Detail

There are many [Weird ERC20 Tokens](https://www.hacknote.co/17c261f7d8fWbdml/doc/182a568ab5cUOpDM) that won't work correctly using the standard `IERC20` interface.

For example, `IERC20(token).transferFrom()` and `IERC20(token).transfer()` will fail for some tokens as they may not conform to the standard IERC20 interface. And if `_aggregator` does not always consume all the allowance given at L72, the transaction will also revert on the next call, because there are certain tokens that do not allow approval of a non-zero number when the current allowance is not zero (eg, USDT).

## Impact

The contract will malfunction for certain tokens.

## Code Snippet

https://github.com/sherlock-audit/2022-11-telcoin/blob/main/contracts/fee-buyback/FeeBuyback.sol#L94-L97

https://github.com/sherlock-audit/2022-11-telcoin/blob/main/contracts/fee-buyback/FeeBuyback.sol#L47-L82

## Tool used

Manual Review

## Recommendation

Consider using `SafeERC20` for `transferFrom`, `transfer` and `approve`.

## Discussion

**amshirif**

https://github.com/telcoin/telcoin-staking/pull/6

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

### Example 12: [M-03] ERC20 tokens without return value will DoS reward claiming

**Source**: Pashov Audit Group
**Protocol**: Interpol_2024-12-24
**Impact**: MEDIUM

**Details**:

## Severity

**Impact:** Medium

**Likelihood:** Medium

## Description

Several functions throughout the application use the `transfer` function to transfer ERC20 tokens. However, some tokens do not return a `bool` on transfer, and since the ERC20 interface expects the `bool` return value, calling `transfer` on tokens that do not return a `bool` would revert. The following functions suffer from this issue:

- `withdrawERC20` in `HoneyLocker`
- `unstake` in `BeradromeAdapter`
- `unstake` in `BGTStationAdapter`
- `unstake` in `InfraredAdapter`
- `unstake` in `KodiakAdapter`

The following functions also call `transfer` on ERC20, but the call is wrapped in a try-catch block. However, such a call would still revert:

- `claim` in `BeradromeAdapter`
- `claim` in `InfraredAdapter`
- `claim` in `KodiakAdapter`

The impact is rated as medium since the issue can be resolved through a contract upgrade, though users would face a temporary freeze of their assets until the fix is deployed. The likelihood is high given that numerous widely-used tokens in the ecosystem don't strictly follow the ERC20 standard regarding return values.

## Recommendations

Consider using the `SafeTransfer` library for transferring ERC20 tokens. This can still make some transfers revert the whole transaction, therefore consider adding a function to pull tokens out separately.

Alternatively, consider implementing the safe transfer functionality in the adapters on your own and making it not revert on failure, 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/Interpol-security-review_2024-12-24.md)

---

### Example 13: [M-03] Use safeTransfer()/safeTransferFrom() instead of transfer()/transferFrom()

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

### Example 14: [M-03] safeTransferFrom is recommended instead of transfer (1)

**Source**: Code4rena
**Protocol**: FactoryDAO
**Impact**: MEDIUM

**Details**:

_Submitted by MaratCerby, also found by berndartmueller, broccolirob, CertoraInc, cryptphi, danb, gzeon, horsefacts, hyh, joestakey, leastwood, throttle, VAD37, wuwe1, and z3s_

ERC20 standard allows transferF function of some contracts to return bool or return nothing.<br>
Some tokens such as USDT return nothing.<br>
This could lead to funds stuck in the contract without possibility to retrieve them.<br>
Using safeTransferFrom of SafeERC20.sol is recommended instead.<br>

### Proof of Concept

<https://github.com/OpenZeppelin/openzeppelin-contracts/blob/4a9cc8b4918ef3736229a5cc5a310bdc17bf759f/contracts/token/ERC20/utils/SafeERC20.sol>

**[illuzen (FactoryDAO) commented](https://github.com/code-423n4/2022-05-factorydao-findings/issues/22#issuecomment-1121974704):**
 > We support ERC20 contracts, not SafeERC20. Contracts that do not conform to the standard are not supported.

**[illuzen (FactoryDAO) confirmed and resolved](https://github.com/code-423n4/2022-05-factorydao-findings/issues/22#issuecomment-1145530282):**
 > https://github.com/code-423n4/2022-05-factorydao/pull/2



***

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-factorydao)

---

## Statistics

- Total findings analyzed: 14
- Examples shown: 14
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
