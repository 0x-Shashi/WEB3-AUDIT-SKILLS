# call vs transfer Security Patterns

## Overview

**Frequency**: 15 occurrences (0.03% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 13 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Cyfrin

---

## Detection Checklist

- [ ] Check for call vs transfer vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-01] Withdrawals can be locked forever if recipient is a contract

**Source**: Code4rena
**Protocol**: Renzo
**Impact**: HIGH

**Details**:

The [`WithdrawQueue`](https://github.com/code-423n4/2024-04-renzo/blob/519e518f2d8dec9acf6482b84a181e403070d22d/contracts/Withdraw/WithdrawQueue.sol#L303) contract allows users to request withdrawals of their ezETH tokens in exchange for a selected asset, such as ETH or an ERC20 token. After a cooldown period, users can call the [`claim()`](https://github.com/code-423n4/2024-04-renzo/blob/519e518f2d8dec9acf6482b84a181e403070d22d/contracts/Withdraw/WithdrawQueue.sol#L279) function to receive their withdrawn assets.

When the selected asset is ETH, the `claim()` function sends the ETH using the low-level `transfer()` function:

```solidity
payable(msg.sender).transfer(_withdrawRequest.amountToRedeem);
```

However, `transfer()` only forwards 2300 gas, which is not enough for the recipient to execute any non-trivial logic in a `receive()` or fallback function. For instance, it is not enough for Safes (such as [this one](https://etherscan.io/address/0xd1e6626310fd54eceb5b9a51da2ec329d6d4b68a) in use by the protocol) to receive funds, which require `>` 6k gas for the call to reach the implementation contract and emit an event:

*Note: to view the provided image, please see the original submission [here](https://github.com/code-423n4/2024-04-renzo-findings/issues/612).*

In this case, the impact is higher than that reported by [4naly3er](https://github.com/code-423n4/2024-04-renzo/blob/main/4naly3er-report.md#m-4-call-should-be-used-instead-of-transfer-on-an-address-payable) becaus

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-04-renzo)

---

### Example 2: [M-10] address.call{value:x}() should be used instead of payable.transfer()

**Source**: Code4rena
**Protocol**: Debt DAO
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/debtdao/Line-of-Credit/blob/e8aa08b44f6132a5ed901f8daa231700c5afeb3a/contracts/utils/LineLib.sol#L48


## Vulnerability details

## Impact

When withdrawing and refund  ETH, the  contract uses Solidity’s `transfer()` function. 

Using Solidity's `transfer()` function has some notable shortcomings when the withdrawer is a smart contract, which can render ETH deposits impossible to withdraw. Specifically, the withdrawal will inevitably fail when:
* The withdrawer smart contract does not implement a payable fallback function.
* The withdrawer smart contract implements a payable fallback function which uses more than 2300 gas units.
* The withdrawer smart contract implements a payable fallback function which needs less than 2300 gas units but is called through a proxy that raises the call’s gas usage above 2300.

Risks of reentrancy stemming from the use of this function can be mitigated by tightly following the "Check-Effects-Interactions" pattern and using OpenZeppelin Contract’s ReentrancyGuard contract. 

## Proof of Concept

```solidity
// Line-of-Credit/contracts/utils/LineLib.sol
48:    payable(receiver).transfer(amount);
```


#### References:

The issues with `transfer()` are outlined [here](https://consensys.net/diligence/blog/2019/09/stop-using-soliditys-transfer-now/
)

For further reference on why using Solidity’s `transfer()` is no longer recommended, refer to these [articles](https://blog.openzeppelin.com/reentrancy-after-istanb

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-debtdao)

---

### Example 3: [M-11] Use of `payable.transfer()` may lock user funds

**Source**: Code4rena
**Protocol**: Fractional
**Impact**: MEDIUM

**Details**:

_Submitted by IllIllI, also found by 0x1f8b, 0x29A, Amithuddar, Avci, bardamu, BowTiedWardens, c3phas, cccz, codexploder, cryptphi, hake, horsefacts, hyh, Kthere, Limbooo, MEP, oyc&#95;109, pashov, peritoflores, Ruhum, scaraven, simon135, slywaters, sseefried, StyxRave, tofunmi, TomJ, Treasure-Seeker, TrungOre, Tutturu, Waze, and xiaoming90_

<https://github.com/code-423n4/2022-07-fractional/blob/e2c5a962a94106f9495eb96769d7f60f7d5b14c9/src/modules/Migration.sol#L172>

<https://github.com/code-423n4/2022-07-fractional/blob/e2c5a962a94106f9495eb96769d7f60f7d5b14c9/src/modules/Migration.sol#L325>

### Impact

The use of `payable.transfer()` is heavily frowned upon because it can lead to the locking of funds. The `transfer()` call requires that the recipient has a `payable` callback, only provides 2300 gas for its operation. This means the following cases can cause the transfer to fail:

*   The contract does not have a `payable` callback
*   The contract's `payable` callback spends more than 2300 gas (which is only enough to emit something)
*   The contract is called through a proxy which itself uses up the 2300 gas

If a user falls into one of the above categories, they'll be unable to receive funds from the vault in a migration wrapper. Inaccessible funds means loss of funds, which is Medium severity.

### Proof of Concept

Both `leave()`:

```solidity
File: src/modules/Migration.sol   #1

159           uint256 ethAmount = userProposalEth[_proposalId][msg.sender];
160        

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-fractional)

---

### Example 4: [M-01] Use `call()` rather than `transfer()` on address payable

**Source**: Code4rena
**Protocol**: Golom
**Impact**: MEDIUM

**Details**:

[L154](https://github.com/code-423n4/2022-07-golom/blob/main/contracts/core/GolomTrader.sol#L154) in [GolomTrader.sol](https://github.com/code-423n4/2022-07-golom/blob/main/contracts/core/GolomTrader.sol) uses `.transfer()` to send ether to other addresses. There are a number of issues with using `.transfer()`, as it can fail for a number of reasons (specified in the Proof of Concept).

### Proof of Concept

1.  The destination is a smart contract that doesn’t implement a `payable` function or it implements a `payable` function but that function uses more than 2300 gas units.
2.  The destination is a smart contract that doesn’t implement a `payable` `fallback` function or it implements a `payable` `fallback` function but that function uses more than 2300 gas units.
3.  The destination is a smart contract but that smart contract is called via an intermediate proxy contract increasing the case requirements to more than 2300 gas units. A further example of unknown destination complexity is that of a multisig wallet that as part of its operation uses more than 2300 gas units.
4.  Future changes or forks in Ethereum result in higher gas fees than transfer provides. The `.transfer()` creates a hard dependency on 2300 gas units being appropriate now and into the future.

### Tools Used

Vim

### Recommended Remediation Steps

Instead use the `.call()` function to transfer ether and avoid some of the limitations of `.transfer()`. This would be accomplished by changing `payEther()` to

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-golom)

---

### Example 5: [M-01] Use call() instead of transfer() when transferring ETH in RubiconRouter

**Source**: Code4rena
**Protocol**: Rubicon
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-05-rubicon/blob/main/contracts/RubiconRouter.sol#L356
https://github.com/code-423n4/2022-05-rubicon/blob/main/contracts/RubiconRouter.sol#L374
https://github.com/code-423n4/2022-05-rubicon/blob/main/contracts/RubiconRouter.sol#L434
https://github.com/code-423n4/2022-05-rubicon/blob/main/contracts/RubiconRouter.sol#L451
https://github.com/code-423n4/2022-05-rubicon/blob/main/contracts/RubiconRouter.sol#L491
https://github.com/code-423n4/2022-05-rubicon/blob/main/contracts/RubiconRouter.sol#L548


## Vulnerability details

## Impact
When transferring ETH, use `call()` instead of `transfer()`.

The `transfer()` function only allows the recipient to use 2300 gas. If the recipient uses more than that, transfers will fail. In the future gas costs might change increasing the likelihood of that happening.

Keep in mind that `call()` introduces the risk of reentrancy. But, as long as the router follows the checks effects interactions pattern it should be fine. It's not supposed to hold any tokens anyway.

## Proof of Concept
See the linked code snippets above.

## Tools Used
none

## Recommended Mitigation Steps
Replace `transfer()` calls with `call()`. Keep in mind to check whether the call was successful by validating the return value:

```sol
(bool success, ) = msg.sender.call{value: amount}("");
require(success, "Transfer failed.")
```

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-rubicon)

---

### Example 6: [H-01] OpenLevV1Lib’s and LPool’s doTransferOut functions call native payable.transfer, which can be unusable for smart contract calls

**Source**: Code4rena
**Protocol**: OpenLeverage
**Impact**: HIGH

**Details**:

## Handle

hyh


## Vulnerability details

## Impact

When OpenLev operations use a wrapped native token, the whole user withdraw is being handled with a `payable.transfer()` call.

This is unsafe as `transfer` has hard coded gas budget and can fail when the user is a smart contract. This way any programmatical usage of OpenLevV1 and LPool is at risk.

Whenever the user either fails to implement the payable fallback function or cumulative gas cost of the function sequence invoked on a native token transfer exceeds 2300 gas consumption limit the native tokens sent end up undelivered and the corresponding user funds return functionality will fail each time.

As OpenLevV1 `closeTrade` is affected this includes user's principal funds freeze scenario, so marking the issue as a high severity one.

## Proof of Concept

OpenLevV1Lib and LPool have `doTransferOut` function that calls native token payable.transfer:

OpenLevV1Lib.doTransferOut

https://github.com/code-423n4/2022-01-openleverage/blob/main/openleverage-contracts/contracts/OpenLevV1Lib.sol#L253


LPool.doTransferOut

https://github.com/code-423n4/2022-01-openleverage/blob/main/openleverage-contracts/contracts/liquidity/LPool.sol#L297


LPool.doTransferOut is used in LPool redeem and borrow, while OpenLevV1Lib.doTransferOut is used in OpenLevV1 trade manipulation logic:

closeTrade

https://github.com/code-423n4/2022-01-openleverage/blob/main/openleverage-contracts/contracts/OpenLevV1.sol#L204

https://github.com/code-423n4

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-openleverage)

---

### Example 7: Use call instead of transfer

**Source**: Cyfrin
**Protocol**: Woosh Deposit Vault
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Description:** In both of the withdraw functions, `transfer()` is used for native ETH withdrawal.
The transfer() and send() functions forward a fixed amount of 2300 gas. Historically, it has often been recommended to use these functions for value transfers to guard against reentrancy attacks. However, the gas cost of EVM instructions may change significantly during hard forks which may break already deployed contract systems that make fixed assumptions about gas costs. For example. EIP 1884 broke several existing smart contracts due to a cost increase of the SLOAD instruction.

**Impact:** The use of the deprecated transfer() function for an address will inevitably make the transaction fail when:
- The claimer smart contract does not implement a payable function.
- The claimer smart contract does implement a payable fallback which uses more than 2300 gas unit.
- The claimer smart contract implements a payable fallback function that needs less than 2300 gas units but is called through proxy, raising the call's gas usage above 2300.

Additionally, using higher than 2300 gas might be mandatory for some multisig wallets.

**Recommended Mitigation:** Use call() instead of transfer().

**Protocol:**
Agree, transfer was causing issues with smart contract wallets.

**Cyfrin:** Verified in commit [7726ae7](https://github.com/HyperGood/woosh-contracts/commit/7726ae72118cfdf91ceb9129e36662f69f4d42de).

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-06-Woosh Deposit Vault.md)

---

### Example 8: [M-01] Swap.sol implements potentially dangerous transfer 

**Source**: Code4rena
**Protocol**: Tally
**Impact**: MEDIUM

**Details**:

## Handle

elprofesor


## Vulnerability details

## Impact
The use of `  .transfer()`  in `  Swap.sol`   may have unintended outcomes on the eth being sent to the receiver. Eth may be irretrievable or undelivered if the `msg.sender`   or `  feeRecipient`   is a smart contract. Funds can potentially be lost if;

1. The smart contract fails to implement the payable fallback function 
2. The fallback function uses more than 2300 gas units

The latter situation may occur in the instance of gas cost changes. The impact would mean that any contracts receiving funds would potentially be unable to retrieve funds from the swap.

## Proof of Concept
This issue directly impacts the following lines of code: [L257](https://github.com/code-423n4/2021-10-tally/blob/c585c214edb58486e0564cb53d87e4831959c08b/contracts/swap/Swap.sol#L257), [L173](https://github.com/code-423n4/2021-10-tally/blob/c585c214edb58486e0564cb53d87e4831959c08b/contracts/swap/Swap.sol#L173), [L158](https://github.com/code-423n4/2021-10-tally/blob/c585c214edb58486e0564cb53d87e4831959c08b/contracts/swap/Swap.sol#L158)

Examples of similar issues ranked as medium can be found [here](https://github.com/code-423n4/2021-08-notional-findings/issues/15) and [here, just search for 'M04'](https://blog.openzeppelin.com/opyn-gamma-protocol-audit/). A detailed explanation of why relying on `payable().transfer()` may result in unexpected loss of eth can be found [here](https://consensys.net/diligence/blog/2019/09/stop-using-soliditys

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-10-tally)

---

### Example 9: [M-02] Use of `payable.transfer()` Might Render ETH Impossible to Withdraw

**Source**: Code4rena
**Protocol**: Escher
**Impact**: MEDIUM

**Details**:

<https://github.com/code-423n4/2022-12-escher/blob/main/src/minters/LPDA.sol#L105>

<https://github.com/code-423n4/2022-12-escher/blob/main/src/minters/LPDA.sol#L85-L86>

<https://github.com/code-423n4/2022-12-escher/blob/main/src/minters/FixedPrice.sol#L109>

<https://github.com/code-423n4/2022-12-escher/blob/main/src/minters/OpenEdition.sol#L92>

### Impact

The protocol uses Solidity’s `transfer()` when transferring ETH to the recipients. This has some notable shortcomings when the recipient is a smart contract, which can render ETH impossible to transfer. Specifically, the transfer will inevitably fail when the smart contract:

*   does not implement a payable fallback function, or
*   implements a payable fallback function which would incur more than 2300 gas units, or
*   implements a payable fallback function incurring less than 2300 gas units but is called through a proxy that raises the call’s gas usage above 2300.

### Proof of Concept

[File: LPDA.sol](https://github.com/code-423n4/2022-12-escher/blob/main/src/minters/LPDA.sol)

    85:            ISaleFactory(factory).feeReceiver().transfer(fee);
    86:            temp.saleReceiver.transfer(totalSale - fee);

    105:        payable(msg.sender).transfer(owed);

[File: FixedPrice.sol#L109](https://github.com/code-423n4/2022-12-escher/blob/main/src/minters/FixedPrice.sol#L109)

    109:        ISaleFactory(factory).feeReceiver().transfer(address(this).balance / 20);

[File: OpenEdition.sol#L92](https://github.com/c

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-escher)

---

### Example 10: [M-11] Usage of deprecated transfer to send ETH

**Source**: Code4rena
**Protocol**: Backd
**Impact**: MEDIUM

**Details**:

_Submitted by peritoflores, also found by JC and StyxRave_

<https://github.com/code-423n4/2022-05-backd/blob/2a5664d35cde5b036074edef3c1369b984d10010/protocol/contracts/swappers/SwapperRouter.sol#L140>

<https://github.com/code-423n4/2022-05-backd/blob/2a5664d35cde5b036074edef3c1369b984d10010/protocol/contracts/swappers/SwapperRouter.sol#L280>

### Impact

Usage of deprecated transfer Swap can revert.

### Proof of Concept

The original `transfer` used to send eth uses a fixed stipend 2300 gas.   This was used to prevent reentrancy.   However this limit your protocol to interact with others contracts that need more than that to process the transaction.

A good article about that:
<https://consensys.net/diligence/blog/2019/09/stop-using-soliditys-transfer-now/>.

### Recommended Mitigation Steps

Used call instead.  For example

        (bool success, ) = msg.sender.call{amount}("");
        require(success, "Transfer failed.");

**[chase-manning (Backd) confirmed](https://github.com/code-423n4/2022-05-backd-findings/issues/180)** 

**[Alex the Entreprenerd (judge) commented](https://github.com/code-423n4/2022-05-backd-findings/issues/180#issuecomment-1159810449):**
 > While submission is lazy in that it doesn't show the ways in which it could revert, (for example most of the times even a transfer to a gnosis-safe will not revert as the gas stipend is sufficient)
> 
> It's true that `transfer`s gas stipend may run out, causing reverts
> 
> For this reason I agree with Med Sev

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-backd)

---

### Example 11: [M-02] instead of `call()` , `transfer()` is used to withdraw the ether

**Source**: Code4rena
**Protocol**: LarvaLabs Meebits
**Impact**: MEDIUM

**Details**:

## Handle

JMukesh


## Vulnerability details

## Impact

function withdraw(uint amount) external {
        require(amount <= ethBalance[msg.sender]);
        ethBalance[msg.sender] = ethBalance[msg.sender].sub(amount);
        msg.sender.transfer(amount);
        emit Withdraw(msg.sender, amount);
    }

To withdraw eth it uses transfer(), this trnansaction will fail inevitably when : - 

1. The withdrwer smart contract does not implement a payable function.

2. Withdrawer smart contract does implement a payable fallback which uses more than 2300 gas unit

3. Thw withdrawer smart contract implements a payable fallback function whicn needs less than 2300 gas unit but is called through proxy that raise the call's gas usage above 2300

https://consensys.net/diligence/blog/2019/09/stop-using-soliditys-transfer-now/




## Proof of Concept

   https://github.com/code-423n4/2021-04-redacted/blob/main/Beebots.sol#L649

## Tools Used

no tool used

## Recommended Mitigation Steps

use call() to send eth

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-04-meebits)

---

### Example 12: [M-04] Send ether with call instead of transfer

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: MEDIUM

**Details**:

_Submitted by kenta, also found by Dravee, hyh, Jujic, leastwood, and z3s_

Use call instead of transfer to send ether. And return value must be checked if sending ether is successful or not.
Sending ether with the transfer is no longer recommended.

### Proof of Concept

[RewardDistributor.sol#L181](https://github.com/code-423n4/2022-02-redacted-cartel/blob/main/contracts/RewardDistributor.sol#L181)

### Recommended Mitigation Steps

(bool result, ) = payable(\_account).call{value: \_amount}("");
require(result, "Failed to send Ether");

**[kphed (Redacted Cartel) confirmed](https://github.com/code-423n4/2022-02-redacted-cartel-findings/issues/2)**


**[Alex the Entreprenerd (judge) commented](https://github.com/code-423n4/2022-02-redacted-cartel-findings/issues/2#issuecomment-1059781616):**
 > I believe the function would actually work with most Smart Contract Wallets and proxies. However this could change in the future.
> 
> Agree with the finding.



***

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-02-redacted-cartel)

---

### Example 13: [M-03] `transfer()` depends on gas consts

**Source**: Code4rena
**Protocol**: ENS
**Impact**: MEDIUM

**Details**:

[ETHRegistrarController.sol#L183-L185](https://github.com/code-423n4/2022-07-ens/blob/ff6e59b9415d0ead7daf31c2ed06e86d9061ae22/contracts/ethregistrar/ETHRegistrarController.sol#L183-L185)<br>
[ETHRegistrarController.sol#L204](https://github.com/code-423n4/2022-07-ens/blob/ff6e59b9415d0ead7daf31c2ed06e86d9061ae22/contracts/ethregistrar/ETHRegistrarController.sol#L204)<br>

`transfer()` forwards 2300 gas only, which may not be enough in future if the recipient is a contract and gas costs change. it could break existing contracts functionality.

### Proof of Concept

`.transfer` or `.send` method, only 2300 gas will be “forwarded” to fallback function. Specifically, the SLOAD instruction, will go from costing 200 gas to 800 gas.

If any smart contract has a functionality of register ens and it has fallback function which is making some state change in contract on ether receive, it could use more than 2300 gas and revert every transaction.

For reference, check out:
* <https://docs.soliditylang.org/en/v0.8.15/security-considerations.html?highlight=transfer#sending-and-receiving-ether>
* <https://consensys.net/diligence/blog/2019/09/stop-using-soliditys-transfer-now/>

### Recommended Mitigation Steps

Use `.call` insted `.transfer`

     (bool success, ) = msg.sender.call.value(amount)("");
     require(success, "Transfer failed.");

**[jefflau (ENS) confirmed, but disagreed with severity and commented](https://github.com/code-423n4/2022-07-ens-findings/issues/133#issuecomment-11

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-07-ens)

---

### Example 14: M-5: `call()` should be used instead of `transfer()` on an address payable

**Source**: Sherlock
**Protocol**: DODO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-dodo-judging/issues/5 

## Found by 
ak1, Nyx, sach1r0, pashov, 0xNazgul, yixxas, 0x4non, virtualfact, Bnke0x0, Tomo, rvierdiiev, 8olidity, ElKu, defsec

## Summary

## Vulnerability Detail
The `transfer()` and `send()` functions forward a fixed amount of 2300 gas. Historically, it has often been recommended to use these functions for value transfers to guard against reentrancy attacks. However, the gas cost of EVM instructions may change significantly during hard forks which may break already deployed contract systems that make fixed assumptions about gas costs. For example. EIP 1884 broke several existing smart contracts due to a cost increase of the SLOAD instruction.

## Impact
The use of the deprecated transfer() function for an address will inevitably make the transaction fail when:

- The claimer smart contract does not implement a payable function.
- The claimer smart contract does implement a payable fallback which uses more than 2300 gas unit.
- The claimer smart contract implements a payable fallback function that needs less than 2300 gas units but is called through proxy, raising the call's gas usage above 2300.
- Additionally, using higher than 2300 gas might be mandatory for some multisig wallets.


## Code Snippet
[DODORouteProxy.sol#L152](https://github.com/sherlock-audit/2022-11-dodo/blob/main/contracts/SmartRoute/DODORouteProxy.sol#L152) `payable(routeFeeReceiver).transfer(restAmount);`
[DODORouteProxy.sol#L4

*[Content truncated...]*

---

### Example 15: M-4: Usage of deprecated transfer() can result in revert.

**Source**: Sherlock
**Protocol**: Harpie
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-harpie-judging/tree/main/007-M 

## Found by 
Lambda, cccz, yixxas, Waze, IEatBabyCarrots, pashov, 0xSmartContract, JohnSmith, Tomo, CodingNameKiki, sach1r0, IllIllI, csanuragjain, gogo

## Summary
The function withdrawPayments() is used by the Owners to withdraw the fees.

## Vulnerability Detail
transfer() uses a fixed amount of gas, which was used to prevent reentrancy. However this limit your protocol to interact with others contracts that need more than that to process the transaction.

Specifically, the withdrawal will inevitably fail when:
1.The withdrawer smart contract does not implement a payable fallback function.
2.The withdrawer smart contract implements a payable fallback function which uses more than 2300 gas units.
3.The withdrawer smart contract implements a payable fallback function which needs less than 2300 gas units but is called through a proxy that raises the call’s gas usage above 2300.

## Impact
transfer() uses a fixed amount of gas, which can result in revert.
https://consensys.net/diligence/blog/2019/09/stop-using-soliditys-transfer-now/

## Code Snippet
https://github.com/Harpieio/contracts/blob/97083d7ce8ae9d85e29a139b1e981464ff92b89e/contracts/Vault.sol#L159
https://github.com/Harpieio/contracts/blob/97083d7ce8ae9d85e29a139b1e981464ff92b89e/contracts/Vault.sol#L156-L160

## Tool used

Manual Review

## Recommendation
Use call instead of transfer(). Example:
(bool succeeded, ) = _to.call{value: _a

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 15
- Examples shown: 15
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
