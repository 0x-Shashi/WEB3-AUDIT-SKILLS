---
name: Token Integration Analyzer
description: Comprehensive analyzer for weird ERC20 behaviors and token integration security
version: 1.0.0
author: Web3 Security Plugin
tags: [erc20, token, integration, security, defi, weird-tokens]
---

# Token Integration Analyzer Skill

Comprehensive analyzer for detecting and handling non-standard ERC20 token behaviors. Covers 30+ known "weird" token behaviors that can break DeFi protocol integrations.

## Capabilities

- **Weird Token Detection**: Identify non-standard ERC20 behaviors
- **Integration Analysis**: Check protocol compatibility with token types
- **Transfer Hook Analysis**: Detect fee-on-transfer, rebasing, hooks
- **Approval Analysis**: Allowance race conditions, non-standard approvals
- **Balance Analysis**: Rebasing, reflection, deflationary mechanics

---

## Token Behavior Categories

### Category 1: Transfer Behaviors

| ID | Behavior | Impact | Common Tokens |
|----|----------|--------|---------------|
| T-01 | Fee-on-Transfer | Amount received ≠ amount sent | SAFEMOON, SHIB variants |
| T-02 | Rebasing (Up) | Balances increase automatically | stETH, AMPL (positive) |
| T-03 | Rebasing (Down) | Balances decrease automatically | AMPL (negative) |
| T-04 | Transfer Hooks | Arbitrary code execution | ERC777, some ERC20 |
| T-05 | Blacklist | Transfers blocked for addresses | USDC, USDT |
| T-06 | Whitelist | Only approved addresses can transfer | Some regulated tokens |
| T-07 | Pausable | All transfers can be paused | USDC, many tokens |
| T-08 | Max Transfer | Limit on transfer amount | Anti-whale tokens |
| T-09 | Cooldown | Time between transfers required | Some DeFi tokens |
| T-10 | Burn on Transfer | Tokens burned during transfer | Deflationary tokens |

### Category 2: Balance Behaviors

| ID | Behavior | Impact | Common Tokens |
|----|----------|--------|---------------|
| B-01 | Reflection | Balance changes based on total tx | RFI, SAFEMOON |
| B-02 | Elastic Supply | Total supply changes | AMPL, OHM |
| B-03 | Balance Caching Issues | stale balanceOf | Some rebasing |
| B-04 | Virtual Balance | Displayed ≠ actual | Some yield tokens |
| B-05 | Shares vs Assets | Underlying value differs | Wrapped tokens |

### Category 3: Approval Behaviors

| ID | Behavior | Impact | Common Tokens |
|----|----------|--------|---------------|
| A-01 | Race Condition | Front-run allowance change | All standard ERC20 |
| A-02 | Non-zero to Non-zero Block | Must set 0 first | USDT |
| A-03 | Approval Required for Self | approve(self) needed | Rare |
| A-04 | Infinite Approval Drain | Over-approval risk | All tokens |
| A-05 | Missing Approval Events | Off-chain tracking fails | Non-compliant |

### Category 4: Return Value Behaviors

| ID | Behavior | Impact | Common Tokens |
|----|----------|--------|---------------|
| R-01 | No Return Value | transfer/approve return void | USDT, BNB |
| R-02 | False Return | Returns false instead of revert | Some tokens |
| R-03 | Non-standard Returns | Unexpected return types | Non-compliant |

### Category 5: Special Behaviors

| ID | Behavior | Impact | Common Tokens |
|----|----------|--------|---------------|
| S-01 | Upgradeable | Logic can change | USDC, many tokens |
| S-02 | Multiple Entry Points | address() differs | Proxied tokens |
| S-03 | Flash Mintable | Temporary supply increase | Some DeFi tokens |
| S-04 | ERC777 Hooks | Re-entrancy via hooks | ERC777 tokens |
| S-05 | Permit (ERC2612) | Off-chain approvals | DAI, USDC |
| S-06 | Low Decimals | Precision issues | USDC (6), WBTC (8) |
| S-07 | High Decimals | Overflow risk | Some tokens (24+) |
| S-08 | No Decimals | decimals() missing | Non-compliant |
| S-09 | Revert on Zero Transfer | transfer(0) reverts | Some tokens |
| S-10 | Large Total Supply | 2^256 supply issues | Meme tokens |

---

## Detection Patterns

### Fee-on-Transfer Detection

```solidity
// Before integration, test for fee-on-transfer:
function checkFeeOnTransfer(IERC20 token) external {
    uint256 balanceBefore = token.balanceOf(address(this));
    token.transferFrom(msg.sender, address(this), amount);
    uint256 balanceAfter = token.balanceOf(address(this));
    uint256 received = balanceAfter - balanceBefore;
    
    // If received < amount, token has fee-on-transfer
    require(received == amount, "Fee-on-transfer detected");
}
```

### Safe Integration Patterns

```solidity
// ✅ Fee-on-transfer safe pattern
function deposit(IERC20 token, uint256 amount) external {
    uint256 balanceBefore = token.balanceOf(address(this));
    token.safeTransferFrom(msg.sender, address(this), amount);
    uint256 received = token.balanceOf(address(this)) - balanceBefore;
    
    // Use 'received' not 'amount' for accounting
    userDeposits[msg.sender] += received;
}

// ✅ Rebasing token safe pattern
function getActualBalance(address token, address account) internal view returns (uint256) {
    // For share-based tokens, convert shares to assets
    if (isShareBasedToken[token]) {
        return IShareToken(token).convertToAssets(shares[account]);
    }
    return IERC20(token).balanceOf(account);
}

// ✅ Return value safe pattern (using SafeERC20)
using SafeERC20 for IERC20;

function safeTransfer(IERC20 token, address to, uint256 amount) internal {
    token.safeTransfer(to, amount);  // Handles no-return and false-return
}
```

---

## Integration Checklists

### DeFi Protocol Checklist

```markdown
## Token Integration Review

### Transfer Safety
- [ ] Using SafeERC20 for all transfers?
- [ ] Measuring actual received amount for deposits?
- [ ] Not caching balanceOf for rebasing tokens?
- [ ] Handling potential transfer failures?

### Approval Safety  
- [ ] Using safeApprove or forceApprove?
- [ ] Setting approval to 0 before non-zero (USDT)?
- [ ] Not over-approving (infinite approvals)?

### Balance Accounting
- [ ] Using pull pattern (transferFrom) over push (transfer)?
- [ ] Accounting for fee-on-transfer in all paths?
- [ ] Handling rebasing token balance changes?
- [ ] Shares vs assets properly converted?

### Reentrancy Protection
- [ ] Protected against ERC777 hooks?
- [ ] Protected against other callback mechanisms?
- [ ] Check-effects-interactions pattern used?

### Edge Cases
- [ ] Zero transfer handling?
- [ ] Max uint256 amount handling?
- [ ] Low decimals precision handling?
- [ ] Contract paused/blacklisted handling?
```

### Lending Protocol Specific

```markdown
## Lending Token Integration

### Collateral Tokens
- [ ] Can rebasing tokens be used as collateral?
- [ ] Fee-on-transfer impact on collateral ratio?
- [ ] Blacklist impact on liquidations?

### Debt Tokens
- [ ] Interest calculation with weird tokens?
- [ ] Repayment with fee-on-transfer tokens?

### Oracle Integration
- [ ] Price oracle handles token mechanics?
- [ ] Rebasing impact on price?
```

### DEX/AMM Specific

```markdown
## DEX Token Integration

### Liquidity Provision
- [ ] LP token math accounts for fees?
- [ ] Rebasing impact on reserves?
- [ ] Balance changes between swaps handled?

### Swap Logic
- [ ] Fee-on-transfer in swap amount calculation?
- [ ] Slippage accounts for token fees?
- [ ] Reserve sync after rebasing?
```

---

## Token Type Quick Reference

### Stablecoins

| Token | Behaviors | Caution Level |
|-------|-----------|---------------|
| USDT | No return, pausable, blacklist, non-zero approval | ⚠️ High |
| USDC | Pausable, blacklist, upgradeable, permit | ⚠️ High |
| DAI | Permit, standard | ✅ Low |
| FRAX | Rebasing possible, permit | ⚠️ Medium |
| BUSD | Pausable, blacklist | ⚠️ Medium |

### Wrapped/Yield Tokens

| Token | Behaviors | Caution Level |
|-------|-----------|---------------|
| WETH | Standard, but deposit/withdraw | ✅ Low |
| wstETH | Share-based (not rebasing) | ⚠️ Medium |
| stETH | Rebasing | 🔴 High |
| aTokens | Rebasing (Aave) | 🔴 High |
| cTokens | Share-based (Compound) | ⚠️ Medium |

### Exotic Tokens

| Token | Behaviors | Caution Level |
|-------|-----------|---------------|
| AMPL | Rebasing (elastic supply) | 🔴 Critical |
| OHM | Rebasing, staking mechanics | 🔴 Critical |
| RFI/SAFEMOON | Reflection, fee-on-transfer | 🔴 Critical |
| ERC777 | Transfer hooks, reentrancy | 🔴 Critical |

---

## Code Patterns

### Universal Safe Transfer

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

library TokenHelper {
    using SafeERC20 for IERC20;
    
    /// @notice Transfer tokens accounting for fee-on-transfer
    /// @return received Actual amount received
    function safeTransferFromWithFeeAccounting(
        IERC20 token,
        address from,
        address to,
        uint256 amount
    ) internal returns (uint256 received) {
        uint256 balanceBefore = token.balanceOf(to);
        token.safeTransferFrom(from, to, amount);
        received = token.balanceOf(to) - balanceBefore;
    }
    
    /// @notice Safe approve that handles USDT-style tokens
    function safeApproveWithReset(
        IERC20 token,
        address spender,
        uint256 amount
    ) internal {
        // Reset to 0 first for USDT-style tokens
        if (token.allowance(address(this), spender) > 0) {
            token.safeApprove(spender, 0);
        }
        token.safeApprove(spender, amount);
    }
}
```

### Rebasing Token Handler

```solidity
/// @notice Wrapper for rebasing tokens using shares
contract RebasingTokenWrapper {
    IERC20 public underlying;
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    
    function deposit(uint256 amount) external {
        uint256 balanceBefore = underlying.balanceOf(address(this));
        underlying.transferFrom(msg.sender, address(this), amount);
        uint256 received = underlying.balanceOf(address(this)) - balanceBefore;
        
        // Calculate shares
        uint256 sharesToMint;
        if (totalShares == 0) {
            sharesToMint = received;
        } else {
            sharesToMint = (received * totalShares) / balanceBefore;
        }
        
        shares[msg.sender] += sharesToMint;
        totalShares += sharesToMint;
    }
    
    function getUnderlyingBalance(address account) public view returns (uint256) {
        if (totalShares == 0) return 0;
        return (shares[account] * underlying.balanceOf(address(this))) / totalShares;
    }
}
```

---

## Resources

- [weird-tokens-list.md](resources/weird-tokens-list.md) - Comprehensive list of weird tokens
- [integration-patterns.md](resources/integration-patterns.md) - Safe integration patterns

## Workflows

- [token-analysis.md](workflows/token-analysis.md) - Token integration audit workflow

---

## Integration with Cyfrin Solodit

```markdown
## Search Queries for Token Issues

- "fee on transfer" - Fee-on-transfer bugs
- "rebasing" - Rebasing token issues
- "erc777" - ERC777 reentrancy
- "usdt approve" - USDT approval issues
- "safeERC20" - Missing SafeERC20
- "transfer return" - Return value issues
```

