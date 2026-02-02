# Reentrancy Fix Verification

## Overview

Reentrancy fixes have a **40% failure rate** on first attempt. This guide ensures fixes are complete and don't introduce new issues.

---

## 1. Before/After Code Comparisons

### 1.1 Single-Function Reentrancy

**[VULNERABLE]:**
```solidity
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "Insufficient");
    
    // External call BEFORE state update
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
    
    balances[msg.sender] -= amount;  // Too late!
}
```

**[BAD FIX #1]: Only added ReentrancyGuard**
```solidity
function withdraw(uint256 amount) external nonReentrant {
    require(balances[msg.sender] >= amount, "Insufficient");
    
    // Still wrong order - guard helps but CEI is still needed
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
    
    balances[msg.sender] -= amount;
}
// Problem: Guard can be bypassed via cross-contract reentrancy
```

**[BAD FIX #2]: CEI but forgot success check**
```solidity
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "Insufficient");
    balances[msg.sender] -= amount;
    
    msg.sender.call{value: amount}("");  // No success check!
}
// Problem: Silent failure = funds lost
```

**[CORRECT FIX]:**
```solidity
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";

function withdraw(uint256 amount) external nonReentrant {
    // CHECKS
    require(balances[msg.sender] >= amount, "Insufficient");
    require(amount > 0, "Zero amount");
    
    // EFFECTS
    balances[msg.sender] -= amount;
    
    // INTERACTIONS
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
    
    emit Withdrawal(msg.sender, amount);
}
```

---

### 1.2 Cross-Function Reentrancy

**[VULNERABLE]:**
```solidity
contract Vault {
    mapping(address => uint256) public balances;
    
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }
    
    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        balances[to] += amount;  // Attacker can reenter via withdraw, then transfer
    }
}
```

**[BAD FIX]: Only fixed withdraw**
```solidity
function withdraw(uint256 amount) external nonReentrant {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
}
// transfer() still vulnerable to reentrancy from withdraw!
```

**[CORRECT FIX]: All state-reading functions protected**
```solidity
contract Vault is ReentrancyGuard {
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
    }
    
    function transfer(address to, uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
```

---

### 1.3 Read-Only Reentrancy

**[VULNERABLE]:**
```solidity
contract LPToken {
    function burn(uint256 shares) external {
        uint256 amount = shares * totalAssets() / totalSupply();
        _burn(msg.sender, shares);
        
        // External call that allows reentrancy
        asset.transfer(msg.sender, amount);  // <-- Reentry point
    }
    
    // Other protocol reads price during reentrancy
    function getSharePrice() external view returns (uint256) {
        return totalAssets() / totalSupply();  // Stale during reentry!
    }
}
```

**[CORRECT FIX]: Lock during state transition**
```solidity
contract LPToken is ReentrancyGuard {
    bool private _inBurn;
    
    function burn(uint256 shares) external nonReentrant {
        _inBurn = true;
        
        uint256 amount = shares * totalAssets() / totalSupply();
        _burn(msg.sender, shares);
        asset.transfer(msg.sender, amount);
        
        _inBurn = false;
    }
    
    function getSharePrice() external view returns (uint256) {
        require(!_inBurn, "Price unstable");
        return totalAssets() / totalSupply();
    }
}
```

---

## 2. Regression Test Templates

### 2.1 Basic Reentrancy Test

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/Vault.sol";

contract ReentrancyAttacker {
    Vault public vault;
    uint256 public attackCount;
    uint256 public maxAttacks = 5;
    
    constructor(address _vault) {
        vault = Vault(_vault);
    }
    
    function attack() external payable {
        vault.deposit{value: msg.value}();
        vault.withdraw(msg.value);
    }
    
    receive() external payable {
        if (attackCount < maxAttacks && address(vault).balance >= 1 ether) {
            attackCount++;
            vault.withdraw(1 ether);
        }
    }
}

contract ReentrancyFixTest is Test {
    Vault vault;
    ReentrancyAttacker attacker;
    
    function setUp() public {
        vault = new Vault();
        attacker = new ReentrancyAttacker(address(vault));
        
        // Seed vault with funds
        vm.deal(address(this), 10 ether);
        vault.deposit{value: 10 ether}();
    }
    
    /// @notice Original PoC - should FAIL after fix
    function test_ReentrancyAttack_ShouldRevert() public {
        vm.deal(address(attacker), 1 ether);
        
        uint256 vaultBalanceBefore = address(vault).balance;
        
        // This should revert or attacker should only get their deposit back
        vm.expectRevert(); // Expect revert after fix
        attacker.attack{value: 1 ether}();
        
        // Alternative: If using CEI without guard, verify no extra funds stolen
        // assertEq(address(vault).balance, vaultBalanceBefore - 1 ether);
    }
    
    /// @notice Verify normal withdrawals still work
    function test_NormalWithdrawal_StillWorks() public {
        address user = makeAddr("user");
        vm.deal(user, 5 ether);
        
        vm.startPrank(user);
        vault.deposit{value: 5 ether}();
        vault.withdraw(5 ether);
        vm.stopPrank();
        
        assertEq(user.balance, 5 ether);
        assertEq(vault.balances(user), 0);
    }
}
```

### 2.2 Cross-Function Reentrancy Test

```solidity
contract CrossFunctionAttacker {
    Vault public vault;
    address public accomplice;
    bool public attacked;
    
    constructor(address _vault) {
        vault = Vault(_vault);
    }
    
    function setAccomplice(address _accomplice) external {
        accomplice = _accomplice;
    }
    
    function attack() external payable {
        vault.deposit{value: msg.value}();
        vault.withdraw(msg.value);
    }
    
    receive() external payable {
        if (!attacked) {
            attacked = true;
            // During reentrancy, transfer balance to accomplice
            vault.transfer(accomplice, vault.balances(address(this)));
        }
    }
}

contract CrossFunctionTest is Test {
    function test_CrossFunctionReentrancy_ShouldFail() public {
        // ... setup ...
        
        // After fix: transfer should revert during withdraw's external call
        vm.expectRevert("ReentrancyGuard: reentrant call");
        attacker.attack{value: 1 ether}();
    }
}
```

---

## 3. Fix Gone Wrong Examples

### 3.1 [BAD] Added Guard to Wrong Function

```solidity
// Developer added nonReentrant to deposit instead of withdraw
function deposit() external payable nonReentrant {  // Wrong!
    balances[msg.sender] += msg.value;
}

function withdraw(uint256 amount) external {  // Still vulnerable!
    require(balances[msg.sender] >= amount);
    (bool success, ) = msg.sender.call{value: amount}("");
    balances[msg.sender] -= amount;
}
```

### 3.2 [BAD] CEI Pattern but Emitted Event Before Effect

```solidity
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    
    emit Withdrawal(msg.sender, amount);  // Event before effect
    
    // If event handler in another contract reads balances...
    balances[msg.sender] -= amount;
    
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
}
```

### 3.3 [BAD] Used transfer() Instead of call() - DoS Risk

```solidity
function withdraw(uint256 amount) external nonReentrant {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;
    
    payable(msg.sender).transfer(amount);  // 2300 gas limit = DoS for contracts
}
// NEW BUG: Contract recipients can't receive funds
```

### 3.4 [BAD] Forgot to Update All Clones/Proxies

```solidity
// Fixed in implementation but proxy still points to old logic
// Or: Fixed in VaultV1 but VaultV2 was copy-pasted from unfixed version
```

---

## 4. Verification Checklist

### Pre-Fix Analysis
- [ ] Identify ALL functions with external calls
- [ ] Map state variables read/written around external calls
- [ ] List all entry points that share state
- [ ] Check for proxy/clone patterns

### Fix Implementation
- [ ] CEI pattern followed in ALL functions with external calls
- [ ] ReentrancyGuard added to contract
- [ ] `nonReentrant` modifier on ALL functions sharing state
- [ ] Success of external calls checked
- [ ] Events emitted AFTER state changes

### Post-Fix Testing
- [ ] Original PoC now reverts
- [ ] Cross-function reentrancy tested
- [ ] Read-only reentrancy tested
- [ ] Normal user flows still work
- [ ] Gas costs acceptable
- [ ] Contract recipients can still interact

### Deployment
- [ ] All proxies upgraded
- [ ] All clones redeployed
- [ ] Integration tests pass
- [ ] Mainnet fork simulation successful

---

## 5. Quick Decision Tree

```
Is there an external call?
├─ No → Not vulnerable to reentrancy
└─ Yes → Is state read/written after call?
    ├─ No → Low risk (but add guard anyway)
    └─ Yes → VULNERABLE
        │
        ├─ Apply CEI pattern
        ├─ Add ReentrancyGuard
        ├─ Check all functions sharing state
        └─ Test with attacker contract
```

---

## Related

- [Reentrancy Anti-Patterns](../patterns/reentrancy-antipatterns.md)
- [Reentrancy Attack Tree](../attack-trees/reentrancy-attack-tree.md)
- [Fix Verification Methodology](../methodology/fix-verification-patterns.md)
