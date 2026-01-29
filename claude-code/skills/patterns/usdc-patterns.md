# USDC Security Patterns

## Overview

**Frequency**: 6 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 5 | 0 | 0 |

**Common Sources**: Sherlock, Codehawks

---

## Detection Checklist

- [ ] Check for usdc vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: H-2: Netting and withdraw auction can be frozen permanently

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

### Example 2: M-6: If the recipient is added to the USDC blacklist, then cancel() does not work

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

### Example 3: Blacklisted STADIUM_ADDRESS address cause fund stuck in the contract forever

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

### Example 4: M-3: WithdrawPeriphery#_convertToToken slippage control is broken for any token other than USDC

**Source**: Sherlock
**Protocol**: Rage Trade
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-10-rage-trade-judging/issues/55 

## Found by 
0x52

## Summary

WithdrawPeriphery allows the user to redeem junior share vaults to any token available on GMX, applying a fixed slippage threshold to all redeems. The slippage calculation always returns the number of tokens to 6 decimals. This works fine for USDC but for other tokens like WETH or WBTC that are 18 decimals the slippage protection is completely ineffective and can lead to loss of funds for users that are withdrawing.

## Vulnerability Detail

    function _convertToToken(address token, address receiver) internal returns (uint256 amountOut) {
        // this value should be whatever glp is received by calling withdraw/redeem to junior vault
        uint256 outputGlp = fsGlp.balanceOf(address(this));

        // using min price of glp because giving in glp
        uint256 glpPrice = _getGlpPrice(false);

        // using max price of token because taking token out of gmx
        uint256 tokenPrice = gmxVault.getMaxPrice(token);

        // apply slippage threshold on top of estimated output amount
        uint256 minTokenOut = outputGlp.mulDiv(glpPrice * (MAX_BPS - slippageThreshold), tokenPrice * MAX_BPS);

        // will revert if atleast minTokenOut is not received
        amountOut = rewardRouter.unstakeAndRedeemGlp(address(token), outputGlp, minTokenOut, receiver);
    }

WithdrawPeriphery allows the user to redeem junior share vaults to any token available on GM

*[Content truncated...]*

---

### Example 5: M-4: Blacklisted creditor can block all repayment besides emergency closure

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

### Example 6: M-4: Protocol won't work with `USDC` even though it is a token specifically mentioned in the docs

**Source**: Sherlock
**Protocol**: Float Capital
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-float-capital-judging/issues/21 

## Found by 
pashov, ctf\_sec, 0x52

## Summary
The protocol has requirements for values (for example 1e18) that would be too big if used with a 6 decimals token like `USDC` - `USDC` is mentioned as a token that will be used in the docs
## Vulnerability Detail
For the mint functionality, a user has to transfer at least 1e18 tokens so that he can mint pool tokens - `if (amount < 1e18) revert InvalidActionAmount(amount);`. If the `paymentToken` used was `USDC` (as pointed out in docs), this would mean he would have to contribute at least 1e12 USDC tokens (more than a billion) which would be pretty much impossible to do. There is also another such check in `MarketExtended::addPoolToExistingMarket` with `require(initialActualLiquidityForNewPool >= 1e12, "Insufficient market seed");` - both need huge amounts when using a low decimals token like USDC that has 6 decimals.

## Impact
The protocol just wouldn't work at all in its current state when using a lower decimals token. Since such a token was mentioned in the docs I set this as a High severity issue.

## Code Snippet
https://github.com/sherlock-audit/2022-11-float-capital/blob/main/contracts/market/template/MarketExtended.sol#L125
https://github.com/sherlock-audit/2022-11-float-capital/blob/main/contracts/market/template/MarketCore.sol#L265
## Tool used

Manual Review

## Recommendation
Drastically lower  the `require` checks so they can work w

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 6
- Examples shown: 6
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
