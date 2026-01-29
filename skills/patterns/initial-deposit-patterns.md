# Initial Deposit Security Patterns

## Overview

**Frequency**: 9 occurrences (0.02% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 5 | 3 | 1 | 0 |

**Common Sources**: Sherlock, Pashov Audit Group, Cyfrin

---

## Detection Checklist

- [ ] Check for initial deposit vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: H-1: Attacker can manipulate the pricePerShare to profit from future users' deposits

**Source**: Sherlock
**Protocol**: Mycelium
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-10-mycelium-judging/tree/main/001-H 

## Found by 
Ruhum, ctf\_sec, cccz, joestakey, ellahi, \_\_141345\_\_, 8olidity, hansfriese, minhquanym, 0x52, caventa, rvierdiiev, Sm4rty, rbserver, IllIllI, sorrynotsorry, JohnSmith, defsec, WATCHPUG, berndartmueller, ak1

## Summary

By manipulating and inflating the pricePerShare to a super high value, the attacker can cause all future depositors to lose a significant portion of their deposits to the attacker due to precision loss.

## Vulnerability Detail

A malicious early user can `deposit()` with `1 wei` of `LINK` token as the first depositor of the Vault, and get `(1 * STARTING_SHARES_PER_LINK) wei` of shares.

Then the attacker can send `STARTING_SHARES_PER_LINK - 1` of `LINK` tokens and inflate the price per share from `1 / STARTING_SHARES_PER_LINK` to 1.0000 .

Then the attacker call `withdraw()` to withdraw `STARTING_SHARES_PER_LINK - 1` shares, and send `1e22` of `LINK` token and inflate the price per share from 1.000 to 1.000e22.

As a result, the future user who deposits `9999e18` will only receive `0` (from `9999e18 * 1 / 10000e18`) of shares token.

They will immediately lose all of their deposits.

## Impact

Users may suffer a significant portion or even 100% of the funds they deposited to the Vault.

## Code Snippet

https://github.com/sherlock-audit/2022-10-mycelium/blob/main/mylink-contracts/src/Vault.sol#L131-142

```solidity
    function deposit(uint256 _amount) exter

*[Content truncated...]*

---

### Example 2: H-1: A malicious early user/attacker can manipulate the LToken's pricePerShare to take an unfair share of future users' deposits

**Source**: Sherlock
**Protocol**: Sentiment
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-08-sentiment-judging/tree/main/004-H 
## Found by 
kankodu, JohnSmith, PwnPatrol, WATCHPUG, berndartmueller, hyh, \_\_141345\_\_, IllIllI, TomJ

## Summary

A well known attack vector for almost all shares based liquidity pool contracts, where an early user can manipulate the price per share and profit from late users' deposits because of the precision loss caused by the rather large value of price per share.

## Vulnerability Detail

A malicious early user can `deposit()` with `1 wei` of `asset` token as the first depositor of the LToken, and get `1 wei` of shares.

Then the attacker can send `10000e18 - 1` of `asset` tokens and inflate the price per share from 1.0000 to an extreme value of 1.0000e22 ( from `(1 + 10000e18 - 1) / 1`) .

As a result, the future user who deposits `19999e18` will only receive `1 wei` (from `19999e18 * 1 / 10000e18`) of shares token.

They will immediately lose `9999e18` or half of their deposits if they `redeem()` right after the `deposit()`.

## Impact

The attacker can profit from future users' deposits. While the late users will lose part of their funds to the attacker.

## Code Snippet

https://github.com/sentimentxyz/protocol/blob/4e45871e4540df0f189f6c89deb8d34f24930120/src/tokens/utils/ERC4626.sol#L48-L60

```solidity
function deposit(uint256 assets, address receiver) public virtual returns (uint256 shares) {
    beforeDeposit(assets, shares);

    // Check for rounding error since we round d

*[Content truncated...]*

---

### Example 3: M-12: Vault Share/Strategy Token Calculation Can Be Broken By First User/Attacker

**Source**: Sherlock
**Protocol**: Notional
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-09-notional-judging/issues/70 

## Found by 
xiaoming90

## Summary

A well-known attack vector for almost all shares-based liquidity pool contracts, where an early user can manipulate the price per share and profit from late users' deposits because of the precision loss caused by the rather large value of price per share.

## Vulnerability Detail

> Note: This issue affects MetaStable2 and Boosted3 balancer leverage vaults

For simplicity's sake, we will simplify the strategy token minting formula as follows. Also, assume that the 1 vault share is equivalent to 1 strategy token for this particular strategy vault, therefore, we will use the term `vault share` and `strategy token` interchangeably here.

```solidity
strategyToken = (totalBPTHeld == 0) ?  bptClaim : (bptClaim * totalStrategyToken) / totalBPTHeld
```

The vault minting formula is taken from the following:

https://github.com/sherlock-audit/2022-09-notional/blob/main/leveraged-vaults/contracts/vaults/balancer/internal/strategy/StrategyUtils.sol#L27

```solidity
File: StrategyUtils.sol
26:     /// @notice Converts BPT to strategy tokens
27:     function _convertBPTClaimToStrategyTokens(StrategyContext memory context, uint256 bptClaim)
28:         internal pure returns (uint256 strategyTokenAmount) {
29:         if (context.totalBPTHeld == 0) {
30:             // Strategy tokens are in 8 decimal precision, BPT is in 18. Scale the minted amount down.
31:             retu

*[Content truncated...]*

---

### Example 4: H-1: Public vault : Initial depositor can manipulate the price per share value and future depositors are forced to deposit huge value in vault.

**Source**: Sherlock
**Protocol**: Sense
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-sense-judging/issues/50 

## Found by 
ak1

## Summary
Most of the share based vault implementation will face this issue.
The vault is based on the ERC4626 where the shares are calculated based on the deposit value.
By depositing large amount as initial deposit, initial depositor can influence the future depositors value.

## Vulnerability Detail

Shares are minted based on the deposit value.
https://github.com/sherlock-audit/2022-11-sense/blob/main/contracts/src/RollerPeriphery.sol#L59-L79
Public vault is based on the ERC4626 where the shares are calculated based on the deposit value.

By depositing large amount as initial deposit, first depositor can take advantage over other depositors.

I am sharing reference for this type of issue that already reported and acknowledged. This explain how the share price could be manipulated to  large value.

https://github.com/sherlock-audit/2022-08-sentiment-judging#issue-h-1-a-malicious-early-userattacker-can-manipulate-the-ltokens-pricepershare-to-take-an-unfair-share-of-future-users-deposits:~:text=Issue%20H%2D1%3A%20A%20malicious%20early%20user/attacker%20can%20manipulate%20the%20LToken%27s%20pricePerShare%20to%20take%20an%20unfair%20share%20of%20future%20users%27%20deposits

ERC4626 implementation
    function mint(uint256 shares, address receiver) public virtual returns (uint256 assets) {
        assets = previewMint(shares); // No need to check for rounding error, previewMint round

*[Content truncated...]*

---

### Example 5: H-3: Early depositors to BufferBinaryPool can manipulate exchange rates to steal funds from later depositors

**Source**: Sherlock
**Protocol**: Buffer Finance
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-buffer-judging/issues/81 

## Found by 
dipp, gandu, rvierdiiev, Ruhum, hansfriese, cccz, 0x52, ctf\_sec, joestakey

## Summary

To calculate the exchange rate for shares in BufferBinaryPool it divides the total supply of shares by the totalTokenXBalance of the vault. The first deposit can mint a very small number of shares then donate tokenX to the vault to grossly manipulate the share price. When later depositor deposit into the vault they will lose value due to precision loss and the adversary will profit.

## Vulnerability Detail

    function totalTokenXBalance()
        public
        view
        override
        returns (uint256 balance)
    {
        return tokenX.balanceOf(address(this)) - lockedPremium;
    }

Share exchange rate is calculated using the total supply of shares and the totalTokenXBalance, which leaves it vulnerable to exchange rate manipulation. As an example, assume tokenX == USDC. An adversary can mint a single share, then donate 1e8 USDC. Minting the first share established a 1:1 ratio but then donating 1e8 changed the ratio to 1:1e8. Now any deposit lower than 1e8 (100 USDC) will suffer from precision loss and the attackers share will benefit from it.

## Impact

Adversary can effectively steal funds from later users through precision loss

## Code Snippet

https://github.com/sherlock-audit/2022-11-buffer/blob/main/contracts/contracts/core/BufferBinaryPool.sol#L405-L412

## Tool used

Manual Revie

*[Content truncated...]*

---

### Example 6: Inflation attack can cause early users to lose their deposit

**Source**: Cyfrin
**Protocol**: Stakepet
**Impact**: HIGH

**Details**:

**Severity:** High

**Description:** A malicious `StakePet` contract creator can steal funds from depositors by launching a typical inflation attack. To execute the attack, the creator can first deposit `1 wei` to get `1 wei` of ownership. Creator can subsequently send a big amount of collateral directly to the `StakePet` contract - this will hugely inflate the value of the single share.

Now, all subsequent pet owners who deposit their collateral will get no ownership in return. The `StakePet::ownershipToMint` function uses `StakePet::totalValue` to calculate the ownership of a new depositor. While the total ownership represented by `s_totalOwnership` remains the same `1 wei`, the `totalValueBefore` is a huge number, thanks to a large direct deposit done by the creator. This ensures that the 1 wei of share represents a huge value of collateral & causes the ownership of new depositors to round to 0.

**Impact:** Potential complete loss of funds for new depositors, given they receive no ownership in exchange for their deposited tokens.

**Proof of Concept:**
- Bob, a malicious actor, initiates the StakePet contract.
- By calling `StakePet::create`, Bob creates a pet depositing a mere `1 wei`, which grants him `1 wei` of ownership.
- Bob then directly transfers a significant amount, like 10 ether, to the `StakePet` contract.
- Consequently, a single `1 wei` share becomes equivalent to `10 ether`.
- An innocent user, Pete, tries to create a pet by calling `StakePet::create` and 

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-19-cyfrin-stakepet.md)

---

### Example 7: M-5: First user can inflate `pointsPerShare` and cause `_correctPoints()` to revert due to overflow

**Source**: Sherlock
**Protocol**: Merit Circle
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-10-merit-circle-judging/issues/103 

## Found by 
WATCHPUG, bin2chen

## Summary

`pointsPerShare` can be manipulated by the first user and cause `_correctPoints()` to revert later.

## Vulnerability Detail

`POINTS_MULTIPLIER` is an unusually large number as a precision fix for `pointsPerShare`: `type(uint128).max ~= 3.4e38`.

This makes it possible for the first user to manipulate the `pointsPerShare` to near `type(int256).max` and a later regular user can trigger the overflow of `_shares * _shares * ` in `_correctPoints()`.

### PoC

1. `deposit(1 wei)` lock for 10 mins, `mint()` 1 wei of shares;
2. `distributeRewards(1000e18)`, `pointsPerShare += 1000e18 * type(uint128).max / 1` == 3e59;
3. the victim `deposit(100e18)` for 1 year, `mint()` 150e18 shares;
3. `_shares * pointsPerShare == -150e18 * 3e59 == -4.5e+79` which exceeds `type(int256).min`, thus the transaction will revert.

The attacker can also manipulate `pointsPerShare` to a slightly smaller number, so that `_shares * pointsPerShare` will only overflow after a certain amount of deposits.

## Impact

By manipulating the `pointPerShare` precisely, the attacker can make it possible for the system to run normally for a little while and only to explode after a certain amount of deposits, as the `pointsPerShare` will be too large by then and all the `_mint` and `_burn` will revert due to overflow in `_correctPoints()`.

The users who deposited before will be unable to wit

*[Content truncated...]*

---

### Example 8: M-4: Frontrun `deposit()` can cause the depositor to lose all the funds

**Source**: Sherlock
**Protocol**: Mycelium
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-10-mycelium-judging/tree/main/029-M 

## Found by 
ctf\_sec, Lambda, CRYP70, 8olidity, bin2chen, hansfriese, innertia, dipp, rbserver, CodingNameKiki, WATCHPUG

## Summary

The attacker can frontrun the first depositor's `deposit()` transaction and transfer LINK tokens to the Vault contract directly and cause the depositor (and all the future depositors) to lose all the funds.

## Vulnerability Detail

In `onTokenTransfer()`, if there are some existing balance in the Vault contract, say 1 wei of LINK token, `supplyBeforeTransfer` will be `1`, since `totalShares == 0`, `newShares` will always be `0`.

The same applies for `deposit()`.

## Impact

The depositor who got frontrun by the attacker will lose all their funds. And all the future depositors.

## Code Snippet

https://github.com/sherlock-audit/2022-10-mycelium/blob/main/mylink-contracts/src/Vault.sol#L252-L276

https://github.com/sherlock-audit/2022-10-mycelium/blob/main/mylink-contracts/src/Vault.sol#L131-L142

https://github.com/sherlock-audit/2022-10-mycelium/blob/main/mylink-contracts/src/Vault.sol#L614-L620


## Tool used

Manual Review

## Recommendation

It should check if `totalShares == 0` to decide whether this is the first mint.

---

### Example 9: [L-04] Frontrunnable Initialization

**Source**: Pashov Audit Group
**Protocol**: Enclave_2025-10-25
**Impact**: LOW

**Details**:

_Acknowledged_

The `initialize` instruction creates the global `fund_pool` PDA (`seed = b"fund_pool"`) and sets `initial_admin` to an arbitrary public key supplied by the caller. There is no access control restricting who may invoke this first-use initializer. An attacker can front-run deployment, initialize the pool, and seize control over all admin- and signer-gated operations for the lifetime of the program (until redeploy).

**Recommendations**

Implement a robust access control mechanism that ensures only a trusted entity, such as the program's deployer or a predefined address, can call the `initialize` function. This restriction can be enforced by verifying the caller's identity or using a specific signature during initialization.

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/Enclave-security-review_2025-10-25.md)

---

## Statistics

- Total findings analyzed: 9
- Examples shown: 9
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
