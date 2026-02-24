---
id: PLAY-LIDO
title: Lido Secure Integration Guide
protocol: lido
version: core
category: staking
chains: [ethereum]
integration_type: [staking, withdrawals, accounting, wrapping]
common_mistakes: [rebasing-miscalculation, share-inflation, withdrawal-queue-assumptions, steth-eth-peg-assumption]
secure_patterns: [share-accounting, rebasing-guards, withdrawal-validation, wsteth-usage]
difficulty: advanced
prerequisites: [staking-basics, token-accounting, rebasing-tokens]
audit_checklist_items: 10
last_updated: 2026-02-24
---

# Lido Secure Integration Guide

> **Attack Surface:** See [attack-trees/liquid-staking-attack-tree.md](../attack-trees/liquid-staking-attack-tree.md)

## Overview

Lido is the largest liquid staking protocol, holding over 30% of all staked ETH. It issues stETH (a rebasing token) and wstETH (a non-rebasing wrapped version). Integrating with Lido requires understanding rebasing mechanics, share-based accounting, the stETH/ETH exchange rate, and withdrawal queue behavior. Getting any of these wrong leads to accounting errors, fund loss, or economic exploits.

---

## 1. Understanding stETH vs wstETH

### 1.1 stETH: The Rebasing Token

stETH automatically updates all holder balances once per day when the oracle reports staking rewards. This means:

```
stETH Rebasing Behavior:
========================

Day 1: You hold 100 stETH, total supply = 1,000,000 stETH
Day 2: Oracle reports 0.01% rewards
        Your balance is now 100.01 stETH (automatically)
        Total supply is now 1,000,100 stETH
        
You did NOTHING - your balance() increased on its own.

Internal Representation:
  stETH does NOT store balances as absolute amounts.
  It stores SHARES.
  
  Your shares: 100
  Total shares: 1,000,000
  Total pooled ETH: 1,000,000 ETH
  
  Your balance = (your_shares * total_pooled_eth) / total_shares
               = (100 * 1,000,000) / 1,000,000
               = 100 stETH
  
  After rewards (total_pooled_eth becomes 1,000,100):
  Your balance = (100 * 1,000,100) / 1,000,000
               = 100.01 stETH
```

### 1.2 wstETH: The Non-Rebasing Wrapper

```
wstETH wraps stETH shares directly:

Wrapping:
  100 stETH (at rate 1.05 ETH/share) -> 95.238 wstETH
  
  wstETH amount = stETH_amount / stETH_per_share
  wstETH amount = 100 / 1.05 = 95.238

Unwrapping:
  95.238 wstETH -> 100.01 stETH (after rewards)
  
  stETH amount = wstETH_amount * stETH_per_share
  stETH amount = 95.238 * 1.05005 = 100.01

KEY INSIGHT:
- wstETH balance NEVER changes
- wstETH VALUE increases over time (it's worth more stETH)
- Use wstETH for DeFi integrations (vaults, lending, etc.)
- Use stETH for user-facing displays (shows growing balance)
```

---

## 2. Critical Integration Vulnerabilities

### 2.1 Rebasing Balance Tracking (Most Common Bug)

```solidity
// BAD: Storing stETH balance as a fixed amount
contract UnsafeStaking {
    mapping(address => uint) public deposits; // [VULNERABLE]
    
    function deposit(uint amount) external {
        stETH.transferFrom(msg.sender, address(this), amount);
        deposits[msg.sender] = amount; // [VULNERABLE] Stores fixed amount
        // After rebase, actual balance changes but deposits mapping doesn't
    }
    
    function withdraw() external {
        uint amount = deposits[msg.sender];
        deposits[msg.sender] = 0;
        stETH.transfer(msg.sender, amount);
        // [VULNERABLE] If positive rebase occurred, unaccounted stETH
        // remains in the contract (stolen by last withdrawer)
        // If negative rebase (slashing), transfer may fail
    }
}

// GOOD: Using shares for accounting
contract SafeStaking {
    mapping(address => uint) public shares; // Store shares, not amounts
    
    function deposit(uint amount) external {
        // Get shares BEFORE transfer (transfer changes total pooled ETH)
        uint sharesBefore = stETH.sharesOf(address(this));
        
        stETH.transferFrom(msg.sender, address(this), amount);
        
        uint sharesAfter = stETH.sharesOf(address(this));
        uint sharesReceived = sharesAfter - sharesBefore;
        
        shares[msg.sender] += sharesReceived;
    }
    
    function withdraw() external {
        uint userShares = shares[msg.sender];
        require(userShares > 0, "No deposit");
        
        shares[msg.sender] = 0;
        
        // Convert shares to current stETH amount
        uint amount = stETH.getPooledEthByShares(userShares);
        
        stETH.transfer(msg.sender, amount);
    }
    
    function getBalance(address user) external view returns (uint) {
        return stETH.getPooledEthByShares(shares[user]);
    }
}
```

### 2.2 The stETH Transfer 1-2 Wei Issue

```solidity
// CRITICAL: stETH transfers can lose 1-2 wei due to shares rounding

// Example:
// User wants to transfer 1000000000000000000 (1 stETH)
// Internal: shares = stETH_amount * total_shares / total_pooled_eth
// Due to integer division, the received amount may be 1-2 wei less

// BAD: Strict equality check after stETH transfer
function depositExactly(uint amount) external {
    uint balanceBefore = stETH.balanceOf(address(this));
    stETH.transferFrom(msg.sender, address(this), amount);
    uint received = stETH.balanceOf(address(this)) - balanceBefore;
    
    require(received == amount, "Incorrect transfer amount");
    // [VULNERABLE] This will FREQUENTLY revert due to 1-2 wei rounding
}

// GOOD: Account for rounding
function depositSafe(uint amount) external {
    uint balanceBefore = stETH.balanceOf(address(this));
    stETH.transferFrom(msg.sender, address(this), amount);
    uint received = stETH.balanceOf(address(this)) - balanceBefore;
    
    // Allow 1-2 wei tolerance for stETH rounding
    require(received >= amount - 2, "Transfer amount too low");
}

// BEST: Use shares-based accounting instead
function depositBest(uint amount) external {
    uint sharesBefore = stETH.sharesOf(address(this));
    stETH.transferFrom(msg.sender, address(this), amount);
    uint sharesReceived = stETH.sharesOf(address(this)) - sharesBefore;
    // Track shares - no rounding issue
    userShares[msg.sender] += sharesReceived;
}
```

### 2.3 Assuming 1:1 stETH/ETH Peg

```solidity
// BAD: Assuming stETH == ETH
function getCollateralValue(uint stETHAmount) public pure returns (uint ethValue) {
    return stETHAmount; // [VULNERABLE] Assumes 1:1 peg
    // During market stress (June 2022), stETH traded at 0.93 ETH
    // Using 1:1 assumption overvalues collateral by 7%
}

// GOOD: Use oracle for stETH/ETH rate
function getCollateralValue(uint stETHAmount) public view returns (uint ethValue) {
    // Option 1: Chainlink stETH/ETH feed
    (, int price,,,) = stETHToETHFeed.latestRoundData();
    require(price > 0, "Invalid price");
    ethValue = (stETHAmount * uint(price)) / 1e18;
    
    // Option 2: Curve stETH/ETH pool TWAP (secondary check)
    uint curvePrice = curvePool.get_dy(1, 0, 1e18); // stETH -> ETH
    
    // Use the lower of the two (conservative)
    uint chainlinkValue = (stETHAmount * uint(price)) / 1e18;
    uint curveValue = (stETHAmount * curvePrice) / 1e18;
    ethValue = chainlinkValue < curveValue ? chainlinkValue : curveValue;
}
```

---

## 3. Withdrawal Queue Security

### 3.1 How Withdrawals Work

```
Lido Withdrawal Flow (Post-Shanghai):
======================================

1. User requests withdrawal via WithdrawalQueue contract
   -> Receives an NFT representing their place in queue
   -> stETH is locked (burned)
   
2. Queue processes when:
   - Validators exit and ETH is returned
   - Buffered ETH is available
   - Oracle reports finalization
   
3. User claims after their request is finalized
   -> Burns NFT
   -> Receives ETH

Timeline:
- Minimum: 1-5 days (if buffer has ETH)
- Typical: 3-7 days
- Maximum: 20+ days (during high demand/validator exit queue)

Key Properties:
- Requests are FIFO (first in, first out)
- Amount received may differ from requested (rebasing continues)
- Requests are denominated in stETH, not ETH
- NFT is transferable (can be sold on secondary market)
```

### 3.2 Withdrawal Integration Security

```solidity
// BAD: Assuming instant withdrawals
function requestAndExpectInstantWithdraw(uint amount) external {
    stETH.approve(address(withdrawalQueue), amount);
    uint[] memory requestIds = withdrawalQueue.requestWithdrawals(
        _amounts(amount),
        msg.sender
    );
    
    // [VULNERABLE] Trying to claim immediately - will revert
    withdrawalQueue.claimWithdrawal(requestIds[0]);
}

// GOOD: Proper two-step withdrawal
function requestWithdrawal(uint stETHAmount) external returns (uint requestId) {
    require(stETHAmount >= MIN_STETH_WITHDRAWAL, "Below minimum");
    require(stETHAmount <= MAX_STETH_WITHDRAWAL, "Above maximum");
    
    stETH.approve(address(withdrawalQueue), stETHAmount);
    
    uint[] memory amounts = new uint[](1);
    amounts[0] = stETHAmount;
    
    uint[] memory requestIds = withdrawalQueue.requestWithdrawals(amounts, address(this));
    requestId = requestIds[0];
    
    userWithdrawals[msg.sender].push(requestId);
    emit WithdrawalRequested(msg.sender, requestId, stETHAmount);
}

function claimWithdrawal(uint requestId) external {
    // Check request is finalized
    WithdrawalRequestStatus[] memory statuses = 
        withdrawalQueue.getWithdrawalStatus(new uint[](requestId));
    require(statuses[0].isFinalized, "Not yet finalized");
    require(statuses[0].owner == address(this), "Not owner");
    
    uint balanceBefore = address(this).balance;
    
    uint[] memory hints = withdrawalQueue.findCheckpointHints(
        _requestIds(requestId),
        1,
        withdrawalQueue.getLastCheckpointIndex()
    );
    
    withdrawalQueue.claimWithdrawalsTo(_requestIds(requestId), hints, msg.sender);
    
    uint ethReceived = address(this).balance - balanceBefore;
    emit WithdrawalClaimed(msg.sender, requestId, ethReceived);
}
```

---

## 4. Share Inflation Attack Prevention

### 4.1 The Vulnerability

```solidity
// Share inflation attack on stETH-like wrappers:
// 1. Attacker is first depositor, deposits 1 wei of stETH
// 2. Gets 1 share
// 3. Donates 1000 stETH directly to the contract
// 4. Now 1 share = 1000.000000000000000001 stETH
// 5. Next depositor deposits 999 stETH
//    shares = 999 * 1 / 1000.000000000000000001 = 0 shares (rounded down)
// 6. Attacker withdraws 1 share = all stETH in contract

// GOOD: Protection via virtual shares (ERC4626 style)
function convertToShares(uint assets) public view returns (uint shares) {
    uint totalAssets_ = totalAssets() + 1; // Virtual offset
    uint totalShares_ = totalSupply() + 1e18; // Virtual shares
    shares = (assets * totalShares_) / totalAssets_;
}
```

---

## 5. Slashing Risk

```
Lido Slashing Scenarios:
========================

Event                  | Impact on stETH    | Likelihood
-----------------------|--------------------|-----------
Single validator slash | ~0.001% balance    | Rare
Correlated slashing    | 1-10% balance      | Very rare
Mass slashing event    | 10%+ balance       | Extremely rare

Integration Impact:
- stETH balances DECREASE during slashing events
- Protocols assuming balance only goes up will break
- Collateral positions using stETH may become undercollateralized
- Withdrawal queue delays increase during slashing events

Defense:
- Never assume stETH balance only increases
- Handle negative rebases in accounting logic
- Set conservative LTV ratios for stETH collateral
- Monitor Lido oracle reports for slashing events
```

---

## 6. Integration Security Checklist

### Accounting
- [ ] Using share-based accounting (not balance-based) for stETH
- [ ] Handling 1-2 wei rounding on stETH transfers
- [ ] NOT assuming 1:1 stETH/ETH peg
- [ ] Accounting for both positive and negative rebases (slashing)
- [ ] Using wstETH instead of stETH for vault/lending integrations

### Oracle
- [ ] Using Chainlink stETH/ETH feed (not assuming 1:1)
- [ ] Staleness check on oracle data
- [ ] Secondary price source for validation (Curve pool)
- [ ] Handling stETH/ETH depeg scenarios gracefully

### Withdrawals
- [ ] Two-step withdrawal process (request + claim)
- [ ] No assumption of instant withdrawal
- [ ] Handling variable withdrawal delays
- [ ] NFT-based withdrawal tracking
- [ ] Minimum and maximum withdrawal amounts enforced

### Token Handling
- [ ] Using `transferShares` when available (Lido-specific)
- [ ] Proper approval handling for stETH
- [ ] Testing with both stETH and wstETH
- [ ] Handling ERC20 approval race condition

### Risk Management
- [ ] LTV ratios account for potential slashing
- [ ] Liquidation thresholds account for stETH/ETH depeg
- [ ] Emergency pause for extreme market conditions
- [ ] Share inflation attack prevention for wrapper contracts

---

## 7. Common Integration Mistakes Summary

| Mistake | Impact | Fix |
|---------|--------|-----|
| Storing stETH amounts instead of shares | Accounting drift, fund loss | Use `sharesOf()` and share-based accounting |
| Assuming 1:1 stETH/ETH | Overvalued collateral | Use Chainlink stETH/ETH oracle |
| Strict equality after stETH transfer | Frequent reverts | Allow 1-2 wei tolerance or use shares |
| Assuming balance only increases | Breaks on slashing | Handle negative rebases |
| Treating stETH like standard ERC20 | Silent accounting errors | Use wstETH for DeFi integrations |
| Assuming instant withdrawals | Stuck funds, poor UX | Implement two-step withdraw flow |

## Cross-References

- Pattern: [rebasing-token-patterns.md](../patterns/rebasing-token-patterns.md)
- Pattern: [share-inflation-patterns.md](../patterns/share-inflation-patterns.md)
- Pattern: [precision-loss-patterns.md](../patterns/precision-loss-patterns.md)
- Anti-Pattern: [oracle-anti-patterns.md](../anti-patterns/oracle-anti-patterns.md)
- Forensics: [steth-depeg-2022.md](../exploit-forensics/steth-depeg-2022.md)
- Checklist: [protocol-integration.md](../checklists/roles/protocol-integration.md)
