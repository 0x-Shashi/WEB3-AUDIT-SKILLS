# Blacklisted Security Patterns

## Overview

**Frequency**: 16 occurrences (0.03% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 5 | 11 | 0 | 0 |

**Common Sources**: Sherlock, Code4rena, Spearbit, Cyfrin, ConsenSys

---

## Detection Checklist

- [ ] Check for blacklisted vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: OrderBook Denial of Service leveraging blacklistable tokens like USDC

**Source**: Spearbit
**Protocol**: CLOBER
**Impact**: HIGH

**Details**:

## Severity: Critical Risk

## Context
- **Audit Commit**: `OrderBook.sol#L649-L666`
- **Dev Commit**: `OrderBook.sol#L687-L706`

## Description
The issue was spotted while analyzing additional impact and fix for 67. Proof of concept checked with the original audit commit: `28062f477f571b38fe4f8455170bd11094a71862` and the newest available commit from the dev branch: `2ed4370b5de9cec5c455f5485358db194f093b01`.

Due to the architectural decision that implements the orders queue as a cyclic buffer, the `OrderBook` starts to overwrite stale orders after reaching `MAX_ORDERS` (~32k) for a given price point. If an order was never claimed, or it is broken and cannot be claimed, it becomes impossible to place a new order in the queue. This issue arises because it is not possible to finalize the stale order and deliver the underlying assets, which is necessary when placing a new order and replacing a stale order.

Effectively, this issue can be used to block the main functionality of the `OrderBook`, so placing new orders for a given price point. Only a single broken order per price-point is enough to trigger this condition. The issue will not be immediately visible as it requires the cyclic buffer to make a full circle and encounter the broken order.

The proof of concept in `SecurityAuditTests.sol` attachment implements a simple scenario where a USDC-like mock token is used:

1. Mallory creates one ASK order at some price point (to sell X base tokens for Y quoteTokens).
2. Mallory 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Clober-Spearbit-Security-Review.pdf)

---

### Example 2: [H-02] DoS: Blacklisted user may prevent withdrawExcessRewards()

**Source**: Code4rena
**Protocol**: FactoryDAO
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-05-factorydao/blob/db415804c06143d8af6880bc4cda7222e5463c0e/contracts/PermissionlessBasicPoolFactory.sol#L242-L256
https://github.com/code-423n4/2022-05-factorydao/blob/db415804c06143d8af6880bc4cda7222e5463c0e/contracts/PermissionlessBasicPoolFactory.sol#L224-L234


## Vulnerability details

## Impact

If one user becomes blacklisted or otherwise cannot be transferred funds in any of the rewards tokens or the deposit token then they will not be able to call `withdraw()` for that token.

The impact of one user not being able to call `withdraw()` is that the owner will now never be able to call `withdrawExcessRewards()` and therefore lock not only the users rewards and deposit but also and excess rewards attributed to the owner.

Thus, one malicious user may deliberately get them selves blacklisted to prevent the owner from claiming the final rewards. Since the attacker may do this with negligible balance in their `deposit()` this attack is very cheap.

## Proof of Concept

It is possible for `IERC20(pool.rewardTokens[i]).transfer(receipt.owner, transferAmount);` to fail for numerous reasons. Such as if a user has been blacklisted (in certain ERC20 tokens) or if a token is paused or there is an attack and the token is stuck.

This will prevent `withdraw()` from being called.

```solidity
        for (uint i = 0; i < rewards.length; i++) {
            pool.rewardsWeiClaimed[i] += rewards[i];
            pool.rewardFunding[i] -

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-factorydao)

---

### Example 3: H-4: Lender force Loan become default

**Source**: Sherlock
**Protocol**: Cooler
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-01-cooler-judging/issues/23 

## Found by 
hansfriese, 0x52, wagmi, IllIllI, bin2chen, Zarf, dipp, libratus, simon135, Trumpero, zaskoh, TrungOre, cccz

## Summary
in ```repay()``` directly transfer the debt token to Lender, but did not consider that Lender can not accept the token (in contract blacklist), resulting in repay() always revert, and finally the Loan can only expire, Loan be default

## Vulnerability Detail
The only way for the borrower to get the collateral token back is to repay the amount owed via repay(). Currently in the repay() method transfers the debt token directly to the Lender.
This has a problem:
 if the Lender is blacklisted by the debt token now, the debtToken.transferFrom() method will fail and the repay() method will always fail and finally the Loan will default.
Example:
Assume collateral token = ETH,debt token = USDC, owner = alice
1.alice call request() to loan 2000 usdc , duration = 1 mon
2.bob call clear(): loanID =1
3.bob transfer loan[1].lender = jack by Cooler.approve/transfer  
  Note: jack has been in USDC's blacklist for some reason before
or bob in USDC's blacklist for some reason now, it doesn't need transfer 'lender')
4.Sometime before the expiration date, alice call repay(id=1) , it will always revert, Because usdc.transfer(jack) will revert
5.after 1 mon, loan[1] default, jack call defaulted() get collateral token

```solidity
    function repay (uint256 loanID, uint256 repaid) external

*[Content truncated...]*

---

### Example 4: H-2: Netting and withdraw auction can be frozen permanently

**Source**: Sherlock
**Protocol**: Opyn Crab Netting
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-opyn-judging/issues/219 

## Found by 
joestakey, bin2chen, hyh, libratus, KingNFT, Zarf, yixxas, cccz

## Summary

An attacker can permanently block the auctions by using a blocked address to fail USDC transfers, which are now required for the auction to proceed.

## Vulnerability Detail

Say Bob knows that one of his addresses is blocked by USDC. He has/can obtain CRAB, which he can transfer to this address.

As withdraw queue requires each transfer call to be successful, this will permanently freezes the functionality, i.e. all future auctions will be blocked.

Knowing that, Bob will block the auctions when it's beneficial to him the most.

## Impact

netAtPrice() and withdrawAuction() will be blocked as long as Bob's withdrawal is queued. There is no way for the owner to manually alter this state.

As auction timing can have material impact on the beneficiaries, the inability to perform netting and withdraw auction will lead to losses for them as Bob will choose the moment to execute the attack to benefit himself at the expense of the participants.

Setting the severity to be high as this is permanent freeze of the core functionality fully controllable by the attacker only.

## Code Snippet

netAtPrice() will be reverting at Bob's withdrawal:

https://github.com/sherlock-audit/2022-11-opyn/blob/main/crab-netting/src/CrabNetting.sol#L389-L419

```solidity
        // process withdraws and send usdc
        i = withdrawsIndex

*[Content truncated...]*

---

### Example 5: Atomic fees delivery susceptible to funds lockout

**Source**: Spearbit
**Protocol**: CLOBER
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Context
- OrderBook.sol#L791-L798 
- OrderBook.sol#L804-L805

## Description
The `collectFees` function delivers the `quoteToken` part of fees as well as the `baseToken` part of fees atomically and simultaneously to both the DAO and the host. In case a single address is blacklisted (e.g., via USDC blacklist feature) or a token in a pair is maliciously configured, it is possible for transfers to one of the addresses to revert, blocking fees delivery.

```solidity
function collectFees() external nonReentrant { // @audit delivers both tokens atomically
    require(msg.sender == _host(), Errors.ACCESS);
    if (_baseFeeBalance > 1) {
        _collectFees(_baseToken, _baseFeeBalance - 1);
        _baseFeeBalance = 1;
    }
    if (_quoteFeeBalance > 1) {
        _collectFees(_quoteToken, _quoteFeeBalance - 1);
        _quoteFeeBalance = 1;
    }
}
```

```solidity
function _collectFees(IERC20 token, uint256 amount) internal { // @audit delivers to both wallets
    uint256 daoFeeAmount = (amount * _DAO_FEE) / _FEE_PRECISION;
    uint256 hostFeeAmount = amount - daoFeeAmount;
    _transferToken(token, _daoTreasury(), daoFeeAmount);
    _transferToken(token, _host(), hostFeeAmount);
}
```

There are multiple scenarios where this situation can occur. For instance, a malicious host might block the function for the DAO to prevent collecting at least the guaranteed valuable `quoteToken`, or a hacked DAO could swap the treasury to an invalid address and renoun

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Clober-Spearbit-Security-Review.pdf)

---

### Example 6: [M-02] Attacker contract can avoid being blocked by BlockList.sol

**Source**: Code4rena
**Protocol**: FIAT DAO
**Impact**: MEDIUM

**Details**:

_Submitted by JohnSmith, also found by ayeslick, reassor, rokinot, and scaraven_

To block an address it must pass the `isContract(address)` check:<br>
<https://github.com/code-423n4/2022-08-fiatdao/blob/main/contracts/features/Blocklist.sol#L25>

    contracts/features/Blocklist.sol
    25:         require(_isContract(addr), "Only contracts");

Which just checks code length at the address provided.

    contracts/features/Blocklist.sol
    37:     function _isContract(address addr) internal view returns (bool) {
    38:         uint256 size;
    39:         assembly {
    40:             size := extcodesize(addr)
    41:         }
    42:         return size > 0;
    43:     }

Attacker can interact with the system and selfdestruct his contract, and with help of CREATE2 recreate it at same address when he needs to interact with the system again.

### Proof of concept

Below is a simple example of salted contract creation, which you can test against `_isContract(address)` function.

```solidity
pragma solidity 0.8.15;

contract BlockList {
    function _isContract(address addr) external view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(addr)
        }
        return size > 0;
    }
}

contract AttackerContract {
  function destroy() external {
    selfdestruct(payable(0));
  }
}

contract AttackerFactory {
    function deploy() external returns (address) {
        return address(new AttackerContract{salt: bytes32("123")}());
    }


*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-08-fiatdao)

---

### Example 7: H-1: Bypass the blacklist restriction because the blacklist check is not done when minting or burning

**Source**: Sherlock
**Protocol**: Dinari
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2023-06-dinari-judging/issues/64 

## Found by 
ctf\_sec, dirk\_y, p-tsanev, toshii
## Summary

Bypass the blacklist restriction because the blacklist check is not done when minting or burning

## Vulnerability Detail

In the whitepaper:

> the protocol emphasis that they implement a blacklist feature for enforcing OFAC, AML and other account security requirements
A blacklisted will not able to send or receive tokens

the protocol want to use the whitelist feature to be compliant to not let the blacklisted address send or receive dSahres

For this reason, before token transfer, the protocol check if address from or address to is blacklisted and the blacklisted address can still create buy order or sell order

```solidity
   function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
        // Restrictions ignored for minting and burning
        // If transferRestrictor is not set, no restrictions are applied

        // @audit
        // why don't you not apply mint and burn in blacklist?
        if (from == address(0) || to == address(0) || address(transferRestrictor) == address(0)) {
            return;
        }

        // Check transfer restrictions
        transferRestrictor.requireNotRestricted(from, to);
    }
```

this is calling

```solidity
function requireNotRestricted(address from, address to) external view virtual {
	// Check if either account is restricted
	if (blacklist[from] || blackl

*[Content truncated...]*

---

### Example 8: [M-15]  Blocklisting in payment ERC20 can cause rented NFT to be stuck in Safe

**Source**: Code4rena
**Protocol**: reNFT
**Impact**: MEDIUM

**Details**:

When a rental is stopped, [`Stop.stopRent()`](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/policies/Stop.sol#L265) transfers the rented NFT back from the renter's Safe to the lender's wallet and transfers the ERC20 payments from the payment escrow contract to the respective recipients (depending on the type of rental, those can be the renter, the lender, or both).

To transfer the ERC20 payments, [`PaymentEscrow.settlePayment()`](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L320) is called.

`PaymentEscrow.settlePayment()` will use [`_safeTransfer()`](https://github.com/re-nft/smart-contracts/blob/3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291/src/modules/PaymentEscrow.sol#L100) (via `_settlePayment()` and `_settlePaymentProRata()` or `_settlePaymentInFull()`) to transfer the ERC20 payments to the recipients:

*   If the rental was a BASE order, the payment is sent to the lender.
*   If the rental was a PAY order and the rental period is over, the payment is sent to the renter.
*   If the rental was a PAY order and the rental period is not over, the payment is split between the lender and the renter.

If either the payment recipient or the payment escrow contract are blocklisted in the payment ERC20, the transfer will fail and `_safeTransfer()` will revert. In this case the rental is not stopped, the rented NFT will still be in the renter's Safe, and the payment w

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2024-01-renft)

---

### Example 9: Commented-out blacklist check allows restricted transfers

**Source**: Cyfrin
**Protocol**: Yieldfi
**Impact**: MEDIUM

**Details**:

**Description:** In [`PerpetualBond::_update`](https://github.com/YieldFiLabs/contracts/blob/40caad6c60625d750cc5c3a5a7df92b96a93a2fb/contracts/core/PerpetualBond.sol#L508-L510), the line intended to restrict transfers between non-blacklisted users is currently commented out:

```solidity
function _update(address from, address to, uint256 amount) internal virtual override {
    // Placeholder for Blacklist check
    // require(!IBlackList(administrator).isBlackListed(from) && !IBlackList(administrator).isBlackListed(to), "blacklisted");
```

This effectively disables blacklist enforcement on transfers of `PerpetualBond` tokens.

**Impact:** Blacklisted addresses can freely hold and transfer `PerpetualBond` tokens, bypassing any intended access control or compliance restrictions.

**Recommended Mitigation:** Uncomment the blacklist check in `_update` to enforce transfer restrictions for blacklisted users.

**YieldFi:** Fixed in commit [`a820743`](https://github.com/YieldFiLabs/contracts/commit/a82074332cc1f57eba398100c3a43e8a70a4c8ce)

**Cyfrin:** Verified. Line doing the blacklist check is now uncommented.

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2025-04-24-cyfrin-yieldfi-v2.0.md)

---

### Example 10: M-6: If the recipient is added to the USDC blacklist, then cancel() does not work

**Source**: Sherlock
**Protocol**: NounsDAO
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-nounsdao-judging/issues/37 

## Found by 
Zarf, joestakey, cccz, bin2chen

## Summary
cancel() will send the vested USDC to the recipient, if the recipient is added to the USDC blacklist, then cancel() will not work

## Vulnerability Detail
When cancel() is called, it sends the vested USDC to the recipient and cancels future payments.
Consider a scenario where if the payer intends to call cancel() to cancel the payment stream, a malicious recipient can block the address from receiving USDC by adding it to the USDC blacklist (e.g. by doing something malicious with that address, etc.), which prevents the payer from canceling the payment stream and withdrawing future payments 
```solidity
    function cancel() external onlyPayerOrRecipient {
        address payer_ = payer();
        address recipient_ = recipient();
        IERC20 token_ = token();

        uint256 recipientBalance = balanceOf(recipient_);

        // This zeroing is important because without it, it's possible for recipient to obtain additional funds
        // from this contract if anyone (e.g. payer) sends it tokens after cancellation.
        // Thanks to this state update, `balanceOf(recipient_)` will only return zero in future calls.
        remainingBalance = 0;

        if (recipientBalance > 0) token_.safeTransfer(recipient_, recipientBalance);
```
## Impact
A malicious recipient may prevent the payer from canceling the payment stream and withdrawing futu

*[Content truncated...]*

---

### Example 11: transferFrom() Lacks notBlackListed Modifier on the Spender msg.sender ✓ Fixed

**Source**: ConsenSys
**Protocol**: USDKG
**Impact**: MEDIUM

**Details**:

#### Resolution

Fixed in [commit 0d22c5326e21541df0c718db98004d5a475aa2ea](https://github.com/USDkg/USDkg/commit/0d22c5326e21541df0c718db98004d5a475aa2ea) by putting the `notBlackListed` modifier on `msg.sender` in the `transferFrom()` function as well.


#### Description

The USDKG token has functionality to blacklist users from using it. For example, a `notBlackListed` modifier exists to verify that a user does not belong to a blacklisted list:

**contracts/USDKG.sol:L86-L92**

```
/**
 * @dev Modifier to make a function callable only when sender is not blacklisted.
 */
modifier notBlackListed(address sender) {
    require(!isBlackListed[sender], "user blacklisted");
    _;
}

```

This is present on functions `transfer()` and `transferFrom()` where it is checking the `msg.sender` and `_from` addresses respectively:

**contracts/USDKG.sol:L103**

```
function transfer(address _to, uint256 _value) public whenNotPaused notBlackListed(msg.sender) returns (bool) {

```

**contracts/USDKG.sol:L122**

```
function transferFrom(address _from, address _to, uint256 _value) public whenNotPaused notBlackListed(_from) returns (bool) {

```

However, in the case of `transferFrom()` it would also be valuable to check blacklisting against the spender, i.e. `msg.sender` as well. That is because a malicious or a compromised spender who received approval from a victim may be identified as an attacker prior to them executing, or perhaps continuing the execution of, exploits. For example, one

*[Content truncated...]*

**Reference**: [View Original Finding](https://diligence.consensys.io/audits/2025/01/usdkg/)

---

### Example 12: M-1: Blacklisted accounts can still transact.

**Source**: Sherlock
**Protocol**: Telcoin Platform Audit Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-02-telcoin-platform-audit-update-judging/issues/4 

## Found by 
0xkmg, Krace, Tendency, ZanyBonzy, ZdravkoHr., blutorque, bughuntoor, cawfree, merlin, neocrao, sa9933, smbv-1923, turvec
## Summary

Accounts that have been blacklisted by the [`BLACKLISTER_ROLE`](https://github.com/sherlock-audit/2024-02-telcoin-platform-audit-update/blob/21920190e0772afa18e7f856a036fea3ef5b9635/telcoin-contracts/contracts/util/abstract/Blacklist.sol#L32) continue to transact normally.

## Vulnerability Detail

Currently, the only real effect of blacklisting an account is the seizure of [`Stablecoin`](https://github.com/sherlock-audit/2024-02-telcoin-platform-audit-update/blob/main/telcoin-contracts/contracts/stablecoin/Stablecoin.sol) funds:

```solidity
/**
 * @notice Overrides Blacklist function to transfer balance of a blacklisted user to the caller.
 * @dev This function is called internally when an account is blacklisted.
 * @param user The blacklisted user whose balance will be transferred.
 */
function _onceBlacklisted(address user) internal override {
  _transfer(user, _msgSender(), balanceOf(user));
}
```

However, following a call to [`addBlackList(address)`](https://github.com/sherlock-audit/2024-02-telcoin-platform-audit-update/blob/21920190e0772afa18e7f856a036fea3ef5b9635/telcoin-contracts/contracts/util/abstract/Blacklist.sol#L72C14-L72C26), the blacklisted account may continue to transact using [`Stablecoin`](https://github.com/she

*[Content truncated...]*

---

### Example 13: Blacklisted STADIUM_ADDRESS address cause fund stuck in the contract forever

**Source**: Codehawks
**Protocol**: Sparkn
**Impact**: MEDIUM

**Details**:

### Relevant GitHub Links
<a data-meta="codehawks-github-link" href="https://github.com/Cyfrin/2023-08-sparkn/tree/main/src/Distributor.sol#L164">https://github.com/Cyfrin/2023-08-sparkn/tree/main/src/Distributor.sol#L164</a>


## Summary
The vulnerability relates to the immutability of `STADIUM_ADDRESS`. If this address is blacklisted by the token used for rewards, the system becomes unable to make transfers, leading to funds being stuck in the contract indefinitely.

## Vulnerability Details
1. Owner calls `setContest` with the correct `salt`.
2. The Organizer sends USDC as rewards to a pre-determined Proxy address.
3. `STADIUM_ADDRESS` is blacklisted by the USDC operator.
4. When the contest is closed, the Organizer calls `deployProxyAndDistribute` with the registered `contestId` and `implementation` to deploy a proxy and distribute rewards. However, the call to `Distributor._commissionTransfer` reverts at Line 164 due to the blacklisting.
5. USDC held at the Proxy contract becomes stuck forever.

```solidity
// Findings are labeled with '<= FOUND'
// File: src/Distributor.sol
116:    function _distribute(address token, address[] memory winners, uint256[] memory percentages, bytes memory data)
117:        ...
154:        _commissionTransfer(erc20);// <= FOUND
155:        ...
156:    }
				...
163:    function _commissionTransfer(IERC20 token) internal {
164:        token.safeTransfer(STADIUM_ADDRESS, token.balanceOf(address(this)));// <= FOUND: Blacklisted STADIUM_ADDRESS 

*[Content truncated...]*

---

### Example 14: M-3: Blocklisted address can be used to lock the option token minter's fund

**Source**: Sherlock
**Protocol**: Bond Options
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-bond-judging/issues/81 

## Found by 
Vagner, berndartmueller, bin2chen, caventa, ctf\_sec
## Summary

Blocklisted address can be used to lock the option token minter's fund

## Vulnerability Detail

When deploy a token via the teller contract, the contract validate that [receiver address is not address(0)](https://github.com/sherlock-audit/2023-06-bond/blob/fce1809f83728561dc75078d41ead6d60e15d065/options/src/fixed-strike/FixedStrikeOptionTeller.sol#L139)

However, a malicious option token creator can save a seemingly favorable strike price and pick a blocklisted address and set the blocklisted address as receiver

https://github.com/d-xo/weird-erc20#tokens-with-blocklists

> Some tokens (e.g. USDC, USDT) have a contract level admin controlled address blocklist. If an address is blocked, then transfers to and from that address are forbidden.

> Malicious or compromised token owners can trap funds in a contract by adding the contract address to the blocklist. This could potentially be the result of regulatory action against the contract itself, against a single user of the contract (e.g. a Uniswap LP), or could also be a part of an extortion attempt against users of the blocked contract.

then user would see the favorable strike price and mint the option token using payout token for call option or use quote token for put option

However, they can never exercise their option because the transaction would revert when [transferri

*[Content truncated...]*

---

### Example 15: M-4: Blacklisted creditor can block all repayment besides emergency closure

**Source**: Sherlock
**Protocol**: Real Wagmi #2
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-10-real-wagmi-judging/issues/83 

## Found by 
0x52, ArmedGoose, Bauer, tsvetanovv

After liquidity is restored to the LP, accumulated fees are sent directly from the vault to the creditor. Some tokens, such as USDC and USDT, have blacklists the prevent users from sending or receiving tokens. If the creditor is blacklisted for the hold token then the fee transfer will always revert. This forces the borrower to defualt. LPs can recover their funds but only after the user has defaulted and they request emergency closure.

## Vulnerability Detail

https://github.com/sherlock-audit/2023-10-real-wagmi/blob/main/wagmi-leverage/contracts/abstract/LiquidityManager.sol#L306-L315

            address creditor = underlyingPositionManager.ownerOf(loan.tokenId);
            // Increase liquidity and transfer liquidity owner reward
            _increaseLiquidity(cache.saleToken, cache.holdToken, loan, amount0, amount1);
            uint256 liquidityOwnerReward = FullMath.mulDiv(
                params.totalfeesOwed,
                cache.holdTokenDebt,
                params.totalBorrowedAmount
            ) / Constants.COLLATERAL_BALANCE_PRECISION;

            Vault(VAULT_ADDRESS).transferToken(cache.holdToken, creditor, liquidityOwnerReward);

The following code is executed for each loan when attempting to repay. Here we see that each creditor is directly transferred their tokens from the vault. If the creditor is blacklisted for holdToken,

*[Content truncated...]*

---

### Example 16: [M-07] Liquidation failure for traders on USDC blacklist

**Source**: Pashov Audit Group
**Protocol**: GainsNetwork-February
**Impact**: MEDIUM

**Details**:

## Severity

**Impact:** High

**Likelihood:** Low

## Description

During the process of liquidating an account, the associated trade is unregistered, and any remaining collateral is returned to the trader. In case liquidation happens, the `tradeValueCollateral` is 0.

        function _unregisterTrade(
            ITradingStorage.Trade memory _trade,
            bool _marketOrder,
            int256 _percentProfit,
            uint256 _closingFeeCollateral,
            uint256 _triggerFeeCollateral
        ) internal returns (uint256 tradeValueCollateral) {
            ...
                if (tradeValueCollateral > collateralLeftInStorage) {
                    vault.sendAssets(tradeValueCollateral - collateralLeftInStorage, _trade.user);
                    _transferCollateralToAddress(_trade.collateralIndex, _trade.user, collateralLeftInStorage);
                } else {
                    _sendToVault(_trade.collateralIndex, collateralLeftInStorage - tradeValueCollateral, _trade.user);
                    _transferCollateralToAddress(_trade.collateralIndex, _trade.user, tradeValueCollateral);
                }

                // 4.2 If collateral in vault, just send collateral to trader from vault
            } else {
                vault.sendAssets(tradeValueCollateral, _trade.user);
            }
        }

However, this process is failed if the trader has been blacklisted by the USDC contract. Specifically, the liquidation attempt fails when trying to transfer a `t

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/GainsNetwork-security-review-February.md)

---

## Statistics

- Total findings analyzed: 16
- Examples shown: 16
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
