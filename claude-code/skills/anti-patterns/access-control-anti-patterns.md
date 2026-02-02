---
id: ACCESS-CONTROL-ANTI-PATTERNS
title: Access Control Anti-Patterns (What NOT to Do)
category: anti-pattern
triggers:
  - access control bad code
  - access control mistakes
  - wrong access control
related_skills:
  - patterns/access-control-patterns.md
  - attack-trees/lending-attack-tree.md
---

# Access Control Anti-Patterns

Examples of **BAD** code patterns for access control. These are real mistakes found in production.

---

## Anti-Pattern #1: Unprotected Initialize

> **Severity: Critical** | **Estimated Loss: $10M-$200M+** | **Fix Priority: Immediate**

### BAD CODE
```solidity
// ❌ VULNERABLE: Anyone can initialize
contract LendingPool {
    address public owner;
    bool public initialized;
    
    function initialize(address _owner) external {
        require(!initialized, "Already initialized");
        owner = _owner;
        initialized = true;
    }
    
    function emergencyWithdraw() external {
        require(msg.sender == owner);
        // withdraw all funds
    }
}
```

### Why It's Bad
- **Front-run deployment**: Attacker calls initialize() before deployer
- **No access control**: Anyone can call initialize
- **Ownership takeover**: Attacker becomes owner

### Exploited In
- **Parity Wallet** (2017, $150M frozen) - Unprotected init function
- **Many bridge exploits** - Init function front-run

### Attack PoC
```solidity
// Attacker monitors mempool
function frontRunInit(address targetContract) external {
    // See deployer's transaction in mempool
    // Front-run with higher gas
    LendingPool(targetContract).initialize(address(this));
    
    // Now attacker is owner
    LendingPool(targetContract).emergencyWithdraw();
    // Steal all funds
}
```

### Correct Pattern
```solidity
// ✅ GOOD: Protected initialization
contract LendingPool {
    address public immutable owner;
    
    constructor(address _owner) {
        owner = _owner;
    }
}

// Or for proxies:
function initialize(address _owner) external initializer {
    _transferOwnership(_owner);
}
```

---

## Anti-Pattern #2: Missing Function Modifiers

> **Severity: Critical** | **Estimated Loss: $10M-$600M+** | **Fix Priority: Immediate**

### BAD CODE
```solidity
// ❌ VULNERABLE: Missing onlyOwner
contract TokenVault {
    address public owner;
    
    function setOwner(address newOwner) external {
        // MISSING: onlyOwner modifier
        owner = newOwner;
    }
    
    function withdrawAll() external {
        // MISSING: onlyOwner modifier
        payable(owner).transfer(address(this).balance);
    }
}
```

### Why It's Bad
- **Anyone can call**: No access control on critical functions
- **Easy to miss**: Human error during development
- **Complete takeover**: Attacker becomes owner

### Exploited In
- **Poly Network** (2021, $610M) - Missing access control on keeper role
- **bZx** (2020) - Admin function callable by anyone

### Attack PoC
```solidity
function exploit() external {
    // 1. Call unprotected setOwner
    vault.setOwner(address(this));
    
    // 2. Now we're owner
    vault.withdrawAll();
    // Steal all funds
}
```

### Correct Pattern
```solidity
// ✅ GOOD: Proper modifiers
contract TokenVault is Ownable {
    function setOwner(address newOwner) external onlyOwner {
        _transferOwnership(newOwner);
    }
    
    function withdrawAll() external onlyOwner {
        payable(owner).transfer(address(this).balance);
    }
}
```

---

## Anti-Pattern #3: Using tx.origin for Auth

> **Severity: High** | **Estimated Loss: $1M-$15M** | **Fix Priority: High**

### BAD CODE
```solidity
// ❌ VULNERABLE: tx.origin instead of msg.sender
contract Wallet {
    address public owner;
    
    function withdraw(uint amount) external {
        require(tx.origin == owner, "Not owner");
        payable(msg.sender).transfer(amount);
    }
}
```

### Why It's Bad
- **Phishing attack**: Attacker tricks owner to call malicious contract
- **Bypasses proxies**: Any intermediate contract appears as owner
- **Solidity warning**: Official docs warn against tx.origin

### Exploited In
- **THORChain** (2021, $8M) - tx.origin used in access control

### Attack PoC
```solidity
// Attacker's malicious contract
contract Attack {
    Wallet target;
    
    constructor(address _target) {
        target = Wallet(_target);
    }
    
    // Owner calls this (tricked via phishing)
    function claimAirdrop() external {
        // tx.origin = owner (caller)
        // msg.sender = this contract
        
        // Call wallet.withdraw()
        target.withdraw(100 ether);
        // Money goes to this contract (msg.sender)
        // But tx.origin check passes (owner called us)
    }
}
```

### Correct Pattern
```solidity
// ✅ GOOD: Use msg.sender
function withdraw(uint amount) external {
    require(msg.sender == owner, "Not owner");
    payable(msg.sender).transfer(amount);
}
```

---

## Anti-Pattern #4: Inconsistent Access Control

> **Severity: Medium** | **Estimated Loss: $100K-$5M** | **Fix Priority: Medium**

### BAD CODE
```solidity
// ❌ VULNERABLE: Inconsistent modifiers
contract Protocol {
    address public admin;
    address public owner;
    
    function setFee(uint newFee) external {
        require(msg.sender == admin);
        fee = newFee;
    }
    
    function pause() external {
        require(msg.sender == owner);
        paused = true;
    }
    
    function emergencyWithdraw() external {
        // MISSING: Which role should call this?
        payable(admin).transfer(address(this).balance);
    }
}
```

### Why It's Bad
- **Confusing roles**: Admin vs owner vs operator unclear
- **Missing checks**: Some functions lack any control
- **Hard to audit**: Inconsistent patterns

### Attack PoC
```solidity
function exploit() external {
    // emergencyWithdraw has no modifier
    protocol.emergencyWithdraw();
    // Anyone can call, funds stolen
}
```

### Correct Pattern
```solidity
// ✅ GOOD: Consistent role-based access
contract Protocol is AccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    
    function setFee(uint newFee) external onlyRole(ADMIN_ROLE) {
        fee = newFee;
    }
    
    function pause() external onlyRole(PAUSER_ROLE) {
        paused = true;
    }
    
    function emergencyWithdraw() external onlyRole(DEFAULT_ADMIN_ROLE) {
        // Clearly requires highest privilege
    }
}
```

---

## Anti-Pattern #5: Hardcoded Addresses

> **Severity: High** | **Estimated Loss: $100M-$625M+** | **Fix Priority: High**

### BAD CODE
```solidity
// ❌ VULNERABLE: Hardcoded privileged address
contract Bridge {
    function validateMessage(bytes32 msgHash, bytes memory sig) public view {
        address signer = recoverSigner(msgHash, sig);
        
        // Hardcoded validator address
        require(
            signer == 0x1234567890123456789012345678901234567890,
            "Invalid validator"
        );
    }
}
```

### Why It's Bad
- **Cannot rotate**: If private key compromised, cannot update
- **Single point of failure**: One key controls everything
- **No governance**: Cannot vote to change validators

### Exploited In
- **Ronin Bridge** (2022, $625M) - Insufficient validator rotation after key compromise

### Attack PoC
```solidity
// If attacker gets private key (phishing, hack, etc.)
function exploit() external {
    // Attacker has private key for 0x1234...
    
    // Sign malicious message
    bytes32 msgHash = keccak256("mint 1000000 tokens");
    bytes memory sig = signMessage(msgHash, stolenPrivateKey);
    
    // Submit to bridge
    bridge.validateMessage(msgHash, sig);
    // Validation passes, malicious action executed
}
```

### Correct Pattern
```solidity
// ✅ GOOD: Configurable validators with rotation
contract Bridge is Ownable {
    mapping(address => bool) public validators;
    uint public requiredValidators;
    
    function addValidator(address validator) external onlyOwner {
        validators[validator] = true;
    }
    
    function removeValidator(address validator) external onlyOwner {
        validators[validator] = false;
    }
    
    function validateMessage(bytes32 msgHash, bytes[] memory sigs) public view {
        uint validSignatures = 0;
        for (uint i = 0; i < sigs.length; i++) {
            address signer = recoverSigner(msgHash, sigs[i]);
            if (validators[signer]) validSignatures++;
        }
        require(validSignatures >= requiredValidators, "Not enough validators");
    }
}
```

---

## Anti-Pattern #6: Centralized Admin with No Timelock

> **Severity: High** | **Estimated Loss: Rug Pull Risk** | **Fix Priority: High**

### BAD CODE
```solidity
// ❌ VULNERABLE: Instant admin actions
contract Vault is Ownable {
    uint public withdrawalFee = 1; // 1%
    
    function setWithdrawalFee(uint newFee) external onlyOwner {
        withdrawalFee = newFee; // Instant change
    }
    
    function withdraw(uint amount) external {
        uint fee = amount * withdrawalFee / 100;
        // ...
    }
}
```

### Why It's Bad
- **Rug pull risk**: Owner can set 100% fee and steal all withdrawals
- **No warning**: Users have no time to react
- **Trust required**: Fully centralized

### Attack PoC
```solidity
// Malicious/compromised owner
function rugPull() external onlyOwner {
    // 1. Set fee to 99%
    vault.setWithdrawalFee(99);
    
    // 2. Users withdraw (not knowing fee changed)
    // 3. 99% goes to owner's fee address
    
    // Instant theft of user funds
}
```

### Correct Pattern
```solidity
// ✅ GOOD: Timelock for critical changes
contract Vault is Ownable {
    uint public withdrawalFee = 1;
    uint public pendingFee;
    uint public feeUpdateTime;
    uint public constant TIMELOCK = 2 days;
    
    function proposeWithdrawalFee(uint newFee) external onlyOwner {
        require(newFee <= 10, "Fee too high"); // Max cap
        pendingFee = newFee;
        feeUpdateTime = block.timestamp + TIMELOCK;
        emit FeeProposed(newFee, feeUpdateTime);
    }
    
    function executeWithdrawalFee() external {
        require(block.timestamp >= feeUpdateTime, "Timelock active");
        withdrawalFee = pendingFee;
        emit FeeUpdated(withdrawalFee);
    }
}
```

---

## Anti-Pattern #7: Modifier Only Checks One Condition

> **Severity: Critical** | **Estimated Loss: $1M-$50M** | **Fix Priority: High**

### BAD CODE
```solidity
// ❌ VULNERABLE: Weak modifier
contract MultiSig {
    mapping(address => bool) public isSigner;
    
    modifier onlySigner() {
        require(isSigner[msg.sender], "Not signer");
        _; // Only checks if signer, not if enough signatures
    }
    
    function executeTransaction(address to, uint value) external onlySigner {
        // Missing: Check if enough signers approved
        payable(to).call{value: value}("");
    }
}
```

### Why It's Bad
- **Incomplete check**: One signer can execute alone
- **Defeats multisig**: Meant to require multiple signatures
- **Logic error**: Modifier too simple

### Attack PoC
```solidity
// Compromised signer
function exploit() external {
    // Only need 1 of 5 signers compromised
    multisig.executeTransaction(attacker, 1000 ether);
    // Should require 3-of-5, but only checked isSigner
}
```

### Correct Pattern
```solidity
// ✅ GOOD: Proper multi-sig verification
contract MultiSig {
    struct Transaction {
        address to;
        uint value;
        bytes data;
        uint approvals;
        mapping(address => bool) approved;
        bool executed;
    }
    
    mapping(uint => Transaction) public transactions;
    mapping(address => bool) public isSigner;
    uint public requiredApprovals;
    
    function approveTransaction(uint txId) external {
        require(isSigner[msg.sender], "Not signer");
        require(!transactions[txId].approved[msg.sender], "Already approved");
        
        transactions[txId].approved[msg.sender] = true;
        transactions[txId].approvals++;
    }
    
    function executeTransaction(uint txId) external {
        Transaction storage txn = transactions[txId];
        require(txn.approvals >= requiredApprovals, "Not enough approvals");
        require(!txn.executed, "Already executed");
        
        txn.executed = true;
        (bool success,) = txn.to.call{value: txn.value}(txn.data);
        require(success, "Execution failed");
    }
}
```

---

## Quick Reference: Access Control Anti-Patterns

| Anti-Pattern | Severity | Consequence | Fix |
|--------------|----------|-------------|-----|
| #1 Unprotected Init | Critical | Ownership takeover | Constructor or initializer modifier |
| #2 Missing Modifiers | Critical | Anyone can call admin functions | Add onlyOwner/onlyRole |
| #3 tx.origin Auth | High | Phishing attack | Use msg.sender |
| #4 Inconsistent Control | Medium | Confusing, bugs | Use AccessControl consistently |
| #5 Hardcoded Addresses | High | Cannot rotate if compromised | Configurable with governance |
| #6 No Timelock | High | Instant rug pull | Add timelock to critical changes |
| #7 Weak Modifiers | Critical | Incomplete checks | Verify full logic in modifier |

---

## See Also

- **Correct Patterns:** [patterns/access-control-patterns.md](../patterns/access-control-patterns.md)
- **Attack Trees:** [attack-trees/bridge-attack-tree.md](../attack-trees/bridge-attack-tree.md)
- **Exploits:** Check exploit-forensics/ for real-world examples
