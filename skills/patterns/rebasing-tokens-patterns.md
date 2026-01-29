# Rebasing Tokens Security Patterns

## Overview

**Frequency**: 4 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 3 | 0 | 0 |

**Common Sources**: Code4rena, Cyfrin

---

## Detection Checklist

- [ ] Check for rebasing tokens vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-05] Aave's share tokens are rebasing breaking current strategy code

**Source**: Code4rena
**Protocol**: Sublime
**Impact**: HIGH

**Details**:

_Submitted by cmichel, also found by WatchPug and leastwood_

When depositing into Aave through the `AaveYield.lockTokens` contract strategy, one receives the `sharesReceived` amount corresponding to the diff of `aToken` balance, which is just always the deposited amount as aave is a rebasing token and `1.0 aToken = 1.0 underlying` at each deposit / withdrawal.

Note that this `sharesReceived` (the underlying deposit amount) is cached in a `balanceInShares` map in `SavingsAccount.deposit` which makes this share *static* and not dynamically rebasing anymore:

```solidity
function deposit(
    uint256 _amount,
    address _token,
    address _strategy,
    address _to
) external payable override nonReentrant returns (uint256) {
    require(_to != address(0), 'SavingsAccount::deposit receiver address should not be zero address');
    uint256 _sharesReceived = _deposit(_amount, _token, _strategy);
    balanceInShares[_to][_token][_strategy] = balanceInShares[_to][_token][_strategy].add(_sharesReceived);
    emit Deposited(_to, _sharesReceived, _token, _strategy);
    return _sharesReceived;
}

function getTokensForShares(uint256 shares, address asset) public view override returns (uint256 amount) {
    if (shares == 0) return 0;
    address aToken = liquidityToken(asset);

    (, , , , , , , uint256 liquidityIndex, , ) = IProtocolDataProvider(protocolDataProvider).getReserveData(asset);

    // @audit-info tries to do (user shares / total shares) * underlying amount where underly

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2021-12-sublime)

---

### Example 2: [M-02] The recipient receives free collateral token if an ERC20 token that deducts a fee on transfer used as baseToken

**Source**: Code4rena
**Protocol**: prePO
**Impact**: MEDIUM

**Details**:

<https://github.com/prepo-io/prepo-monorepo/blob/feat/2022-12-prepo/apps/smart-contracts/core/contracts/Collateral.sol#L45-L61>

<https://github.com/prepo-io/prepo-monorepo/blob/feat/2022-12-prepo/apps/smart-contracts/core/contracts/Collateral.sol#L64-L78>

<https://github.com/prepo-io/prepo-monorepo/blob/feat/2022-12-prepo/apps/smart-contracts/core/contracts/DepositHook.sol#L49-L50>

<https://github.com/prepo-io/prepo-monorepo/blob/feat/2022-12-prepo/apps/smart-contracts/core/contracts/WithdrawHook.sol#L76-L77>

### Impact

*   There are some ERC20 tokens that deduct a fee on every transfer call. If these tokens are used as baseToken then:
    1.  When depositing into the **Collateral** contract, the recipient will receive collateral token more than what they should receive.

    2.  The **DepositRecord** contract will track wrong user deposit amounts and wrong globalNetDepositAmount as the added amount to both will be always more than what was actually deposited.

    3.  When withdrawing from the **Collateral** contract, the user will receive less baseToken amount than what they should receive.

    4.  The treasury will receive less fee and the user will receive more `PPO` tokens that occur in **DepositHook**  and **WithdrawHook**.

### Proof of Concept

Given:
* baseToken is an ERC20 token that deduct a fee on every transfer call.
* **FoT** is the deducted fee on transfer.

1.  The user deposits baseToken to the **Collateral** contract by calling `deposit` function passi

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-12-prepo)

---

### Example 3: Non-standard ERC20 tokens are not supported

**Source**: Cyfrin
**Protocol**: Woosh Deposit Vault
**Impact**: MEDIUM

**Details**:

**Severity:** Medium

**Description:** The protocol implemented a function `deposit()` to allow users to deposit.
```solidity
DepositVault.sol
37:     function deposit(uint256 amount, address tokenAddress) public payable {
38:         require(amount > 0 || msg.value > 0, "Deposit amount must be greater than 0");
39:         if(msg.value > 0) {
40:             require(tokenAddress == address(0), "Token address must be 0x0 for ETH deposits");
41:             uint256 depositIndex = deposits.length;
42:             deposits.push(Deposit(payable(msg.sender), msg.value, tokenAddress));
43:             emit DepositMade(msg.sender, depositIndex, msg.value, tokenAddress);
44:         } else {
45:             require(tokenAddress != address(0), "Token address must not be 0x0 for token deposits");
46:             IERC20 token = IERC20(tokenAddress);
47:             token.safeTransferFrom(msg.sender, address(this), amount);
48:             uint256 depositIndex = deposits.length;
49:             deposits.push(Deposit(payable(msg.sender), amount, tokenAddress));//@audit-issue fee-on-transfer, rebalancing tokens will cause problems
50:             emit DepositMade(msg.sender, depositIndex, amount, tokenAddress);
51:
52:         }
53:     }
```
Looking at the line L49, we can see that the protocol assumes `amount` of tokens were transferred.
But this does not hold true for some non-standard ERC20 tokens like fee-on-transfer tokens or rebalancing tokens.
(Refer to [here](https://github.com/d-

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/solodit/solodit_content/blob/main/reports/Cyfrin/2023-09-06-Woosh Deposit Vault.md)

---

### Example 4: [M-15] Lack of timelock on `rigidRedemption`, enables to steal yield from other users

**Source**: Code4rena
**Protocol**: Lybra Finance
**Impact**: MEDIUM

**Details**:

The withdraw function of the `LybraEUSDVaultBase` vaults, uses a time softlock to prevent users from hopping in and out of the protocol; to gain access to the yield generated by other users and then leave right away (by charging a small percentage from the withdrawn amount).

The same measure isn't applied to `rigidRedemptions`, which enable a user to withdraw most of the underlying assets at any time after deposit. This enables a user to deposit into the pool right before a rebase is about to happen, get access to the yield generated by other users and leave by calling `rigidRedemption` and withdraw on the tokens left by `rigidRedemption` (the amount charged on the leftovers assets, can be outbalanced by the yield).

Therefore, a malicious user to get access to yield that they didn't generate, effectively stealing it from others. The amount that the user will get access to will vary based on the deposited amounts.

### Proof of Concept

This issue involves 3 functions:

- `withdraw(address onBehalfOf, uint256 amount)` from the `LybraEUSDVaultBase` [contract](https://github.com/code-423n4/2023-06-lybra/blob/7b73ef2fbb542b569e182d9abf79be643ca883ee/contracts/lybra/pools/base/LybraEUSDVaultBase.sol#L98), which internally calls `checkWithdrawal(address user, uint256 amount)` to check that 3 days has passed after deposit and charges the user otherways:

    ```
    withdrawal = block.timestamp - 3 days >= depositedTime[user] ? amount : (amount * 999) / 1000;
    ```

- `rigidRede

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-lybra)

---

## Statistics

- Total findings analyzed: 4
- Examples shown: 4
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
