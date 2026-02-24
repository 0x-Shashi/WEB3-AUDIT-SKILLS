---
id: METHOD-UPGRADE-MIGRATION
title: Upgrade & Migration Security Patterns
category: methodology
difficulty: advanced
triggers: [proxy vulnerability, upgrade security, storage collision, UUPS, transparent proxy, migration attack, initialization]
related_skills: [methodology/fork-audit.md, methodology/secure-pattern-reference.md, checklists/comprehensive-checklist.md]
tags: [proxy, upgrade, uups, storage, migration, initialization]
last_updated: 2026-02-24
---

# Upgrade & Migration Security Patterns

## Overview

Proxy patterns and contract upgrades are among the most dangerous areas in smart contract security. This guide covers storage collisions, initialization vulnerabilities, and migration attacks.

---

## 1. Proxy Pattern Vulnerabilities

### 1.1 Storage Collision

```solidity
// VULNERABLE: Implementation storage collides with proxy

// Proxy Contract
contract VulnerableProxy {
    address public implementation;  // Slot 0
    address public admin;           // Slot 1
    
    fallback() external payable {
        _delegate(implementation);
    }
}

// Implementation Contract  
contract ImplementationV1 {
    uint256 public value;     // Slot 0 - COLLIDES with implementation!
    address public owner;     // Slot 1 - COLLIDES with admin!
    
    function setValue(uint256 _value) external {
        value = _value;  // Actually overwrites proxy.implementation!
    }
}
```

### Fix: Use EIP-1967 Storage Slots

```solidity
// SAFE: Use pseudo-random storage slots
contract SafeProxy {
    // EIP-1967 implementation slot
    // bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)
    bytes32 internal constant IMPLEMENTATION_SLOT = 
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    
    // EIP-1967 admin slot
    bytes32 internal constant ADMIN_SLOT = 
        0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
    
    function _getImplementation() internal view returns (address impl) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            impl := sload(slot)
        }
    }
    
    function _setImplementation(address newImpl) internal {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, newImpl)
        }
    }
}
```

### 1.2 Function Selector Collision

```solidity
// VULNERABLE: Proxy function shadows implementation function
contract BadProxy {
    address public owner;  // Has selector 0x8da5cb5b
    
    fallback() external payable {
        _delegate(implementation);
    }
    
    function owner() public view returns (address) {
        return _owner;  // This always executes, never reaches implementation
    }
}

contract Implementation {
    // This owner() is NEVER callable through proxy!
    function owner() public view returns (address) {
        return implementationOwner;
    }
}
```

### Fix: Transparent Proxy Pattern

```solidity
// SAFE: Admin can only call admin functions, users only delegate
contract TransparentProxy {
    modifier ifAdmin() {
        if (msg.sender == _getAdmin()) {
            _;
        } else {
            _fallback();
        }
    }
    
    function upgradeTo(address newImpl) external ifAdmin {
        _setImplementation(newImpl);
    }
    
    function _fallback() internal {
        _delegate(_getImplementation());
    }
    
    fallback() external payable {
        _fallback();
    }
}
```

---

## 2. Initialization Vulnerabilities

### 2.1 Uninitialized Implementation

```solidity
// VULNERABLE: Implementation can be initialized by attacker
contract VulnerableImplementation is Initializable {
    address public owner;
    
    function initialize(address _owner) external initializer {
        owner = _owner;
    }
    
    function withdrawAll() external {
        require(msg.sender == owner);
        payable(owner).transfer(address(this).balance);
    }
}

// ATTACK:
// 1. Find implementation address (not proxy)
// 2. Call implementation.initialize(attacker)
// 3. Implementation's owner is now attacker
// 4. If any funds sent to implementation directly, attacker drains
```

### Fix: Disable Implementation Initialization

```solidity
// SAFE: Disable initializers in constructor
contract SafeImplementation is Initializable {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();  // Cannot initialize implementation directly
    }
    
    function initialize(address _owner) external initializer {
        owner = _owner;
    }
}
```

### 2.2 Re-initialization Attack

```solidity
// VULNERABLE: Missing initializer modifier
contract BadUpgrade {
    bool public initialized;
    address public owner;
    
    function initialize(address _owner) external {
        require(!initialized, "Already initialized");
        initialized = true;
        owner = _owner;
    }
}

// ATTACK on V2:
contract BadUpgradeV2 {
    bool public initialized;
    address public owner;
    uint256 public newVariable;
    
    // Forgot initializer protection!
    function initializeV2(uint256 _value) external {
        newVariable = _value;
        owner = msg.sender;  // Attacker can take over!
    }
}
```

### Fix: Use reinitializer

```solidity
// SAFE: Use OpenZeppelin's reinitializer
contract SafeUpgradeV2 is Initializable {
    bool public initialized;
    address public owner;
    uint256 public newVariable;
    
    function initializeV2(uint256 _value) external reinitializer(2) {
        newVariable = _value;
        // Cannot change owner - that was V1
    }
}
```

---

## 3. Storage Layout Issues

### 3.1 Storage Gap Missing

```solidity
// VULNERABLE: No gap for future variables
contract BaseV1 {
    address public owner;
    uint256 public value;
    // No gap!
}

contract DerivedV1 is BaseV1 {
    address public admin;  // Slot 2
}

// After upgrade:
contract BaseV2 {
    address public owner;
    uint256 public value;
    uint256 public newBaseVar;  // NEW - takes slot 2!
}

contract DerivedV2 is BaseV2 {
    address public admin;  // Now at slot 3, but storage still has old slot 2 value!
}
// admin now reads garbage (old slot 2 value)
```

### Fix: Storage Gaps

```solidity
// SAFE: Reserve slots for future use
contract BaseV1 {
    address public owner;
    uint256 public value;
    
    // Reserve 50 slots for future base contract variables
    uint256[50] private __gap;
}

contract BaseV2 {
    address public owner;
    uint256 public value;
    uint256 public newBaseVar;  // Uses one gap slot
    
    uint256[49] private __gap;  // Reduce gap by 1
}
```

### 3.2 Struct/Array Storage Changes

```solidity
// VULNERABLE: Changing struct layout
contract V1 {
    struct User {
        uint256 balance;
        uint256 lastUpdate;
    }
    mapping(address => User) public users;
}

contract V2 {
    struct User {
        uint256 balance;
        address referrer;      // INSERTED - shifts lastUpdate!
        uint256 lastUpdate;
    }
    mapping(address => User) public users;
    // All existing lastUpdate values now read as referrer (address)!
}
```

### Fix: Append-Only Structs

```solidity
// SAFE: Only append to structs
contract V2 {
    struct User {
        uint256 balance;
        uint256 lastUpdate;
        address referrer;  // APPENDED at end
    }
    mapping(address => User) public users;
}
```

### 3.3 Immutable/Constant Confusion

```solidity
// VULNERABLE: Immutables in upgradeable contracts
contract BadUpgradeable {
    // WRONG: Immutables are stored in bytecode, not storage
    // Each implementation has its own value!
    uint256 public immutable CREATION_TIME = block.timestamp;
    
    // This works differently per implementation
    function timeSinceCreation() external view returns (uint256) {
        return block.timestamp - CREATION_TIME;
    }
}

// SAFE: Use storage for upgradeable "constants"
contract SafeUpgradeable {
    uint256 public creationTime;
    
    function initialize() external initializer {
        creationTime = block.timestamp;
    }
}
```

---

## 4. UUPS-Specific Vulnerabilities

### 4.1 Bricked Proxy (Missing Upgrade Function)

```solidity
// VULNERABLE: Forgetting upgradeTo in new implementation
contract UUPSV1 is UUPSUpgradeable {
    function _authorizeUpgrade(address) internal override onlyOwner {}
    
    // Has upgradeToAndCall inherited from UUPSUpgradeable
}

contract UUPSV2 {  // FORGOT to inherit UUPSUpgradeable!
    // No upgrade function - PROXY IS NOW BRICKED
}

// After upgrading to V2, no way to upgrade again!
```

### Fix: Always Inherit UUPS

```solidity
// SAFE: Always inherit and verify
contract UUPSV2 is UUPSUpgradeable, OwnableUpgradeable {
    function _authorizeUpgrade(address newImpl) internal override onlyOwner {
        // Additional validation
        require(
            IUUPS(newImpl).proxiableUUID() == _IMPLEMENTATION_SLOT,
            "Not UUPS compatible"
        );
    }
}
```

### 4.2 UUPS Self-Destruct Attack

```solidity
// VULNERABLE: Implementation can be destroyed
contract UUPSImplementation is UUPSUpgradeable {
    function _authorizeUpgrade(address) internal override {}
    
    // If attacker calls implementation directly (not through proxy)
    // and initializes, then calls destroy...
    
    function destroy() external onlyOwner {
        selfdestruct(payable(owner));
        // Implementation destroyed!
        // All proxies now point to empty address!
    }
}
```

### Fix: Disable Direct Implementation Calls

```solidity
// SAFE: Check not delegatecall
contract SafeUUPS is UUPSUpgradeable {
    address private immutable __self = address(this);
    
    modifier onlyProxy() {
        require(address(this) != __self, "Must be called through proxy");
        _;
    }
    
    function destroy() external onlyOwner onlyProxy {
        // Can only be called through proxy, not on implementation
    }
}
```

---

## 5. Migration Attack Vectors

### 5.1 State Migration Manipulation

```solidity
// VULNERABLE: Unprotected migration function
contract V2 {
    mapping(address => uint256) public newBalances;
    bool public migrationComplete;
    
    // Anyone can call and manipulate!
    function migrateUser(address user, uint256 balance) external {
        require(!migrationComplete);
        newBalances[user] = balance;
    }
    
    function completeMigration() external {
        migrationComplete = true;
    }
}
```

### Fix: Merkle Proof Migration

```solidity
// SAFE: Verify migration data
contract V2 {
    bytes32 public migrationRoot;  // Set during upgrade
    mapping(address => bool) public migrated;
    
    function migrateUser(
        address user,
        uint256 balance,
        bytes32[] calldata proof
    ) external {
        require(!migrated[user], "Already migrated");
        
        bytes32 leaf = keccak256(abi.encodePacked(user, balance));
        require(MerkleProof.verify(proof, migrationRoot, leaf), "Invalid proof");
        
        migrated[user] = true;
        newBalances[user] = balance;
    }
}
```

### 5.2 Front-Running Upgrade

```solidity
// VULNERABLE: Upgrade without timelock
contract UnsafeGovernance {
    function upgrade(address newImpl) external onlyOwner {
        // Immediate upgrade - owner can rug
        proxy.upgradeTo(newImpl);
    }
}
```

### Fix: Timelocked Upgrades

```solidity
// SAFE: Timelock + announcement
contract SafeGovernance {
    uint256 public constant UPGRADE_DELAY = 2 days;
    
    address public pendingImplementation;
    uint256 public upgradeTimestamp;
    
    function proposeUpgrade(address newImpl) external onlyOwner {
        pendingImplementation = newImpl;
        upgradeTimestamp = block.timestamp + UPGRADE_DELAY;
        emit UpgradeProposed(newImpl, upgradeTimestamp);
    }
    
    function executeUpgrade() external {
        require(block.timestamp >= upgradeTimestamp, "Too early");
        require(pendingImplementation != address(0), "No pending upgrade");
        
        proxy.upgradeTo(pendingImplementation);
        pendingImplementation = address(0);
    }
    
    function cancelUpgrade() external onlyOwner {
        pendingImplementation = address(0);
        emit UpgradeCancelled();
    }
}
```

---

## 6. Upgrade Audit Checklist

### 6.1 Proxy Setup

```markdown
□ EIP-1967 storage slots used (no collision with implementation)
□ Admin cannot accidentally call implementation functions
□ Implementation address cannot be set to zero
□ Proxy cannot be initialized multiple times
□ Fallback properly delegates all calls
```

### 6.2 Implementation Security

```markdown
□ constructor calls _disableInitializers()
□ initialize() has initializer modifier
□ All state variables in correct inheritance order
□ Storage gaps present in all base contracts
□ No immutables that affect logic
□ UUPS: upgrade function present and protected
```

### 6.3 Storage Layout

```markdown
□ No variables reordered from previous version
□ No variables removed (only deprecated)
□ New variables only appended
□ Struct members only appended
□ Storage gaps reduced correctly
□ Mapping/array storage unchanged
```

### 6.4 Upgrade Process

```markdown
□ Timelock on upgrades
□ Multi-sig required for upgrades
□ Upgrade simulation tested
□ Storage layout verified (hardhat-upgrades)
□ Initialization parameters validated
□ Rollback plan documented
```

---

## 7. Testing Upgrade Safety

### 7.1 Storage Layout Test

```solidity
// test/UpgradeTest.t.sol
contract UpgradeTest is Test {
    function test_StorageLayoutPreserved() public {
        // Deploy V1
        ProxyAdmin admin = new ProxyAdmin();
        ImplementationV1 implV1 = new ImplementationV1();
        TransparentProxy proxy = new TransparentProxy(
            address(implV1),
            address(admin),
            abi.encodeCall(implV1.initialize, (owner))
        );
        
        ImplementationV1 v1 = ImplementationV1(address(proxy));
        
        // Set some state
        v1.setValue(12345);
        v1.setUser(user1, 100 ether);
        
        // Deploy and upgrade to V2
        ImplementationV2 implV2 = new ImplementationV2();
        admin.upgrade(proxy, address(implV2));
        
        ImplementationV2 v2 = ImplementationV2(address(proxy));
        
        // Verify state preserved
        assertEq(v2.value(), 12345, "Value corrupted");
        assertEq(v2.getUser(user1), 100 ether, "User balance corrupted");
        assertEq(v2.owner(), owner, "Owner corrupted");
    }
}
```

### 7.2 Initialization Test

```solidity
function test_CannotReinitialize() public {
    // After upgrade
    admin.upgrade(proxy, address(implV2));
    
    // Try to reinitialize
    vm.expectRevert("Initializable: contract is already initialized");
    ImplementationV2(address(proxy)).initialize(attacker);
}

function test_ImplementationCannotBeInitialized() public {
    // Try to initialize implementation directly
    vm.expectRevert("Initializable: contract is already initialized");
    implV2.initialize(attacker);
}
```

### 7.3 UUPS Upgrade Test

```solidity
function test_UUPSUpgradeWorks() public {
    // Only authorized can upgrade
    vm.prank(randomUser);
    vm.expectRevert("Ownable: caller is not the owner");
    UUPSProxy(address(proxy)).upgradeTo(address(implV2));
    
    // Owner can upgrade
    vm.prank(owner);
    UUPSProxy(address(proxy)).upgradeTo(address(implV2));
    
    // New implementation active
    assertEq(
        UUPSProxy(address(proxy)).implementation(),
        address(implV2)
    );
}
```

---

## 8. Tools for Upgrade Safety

### 8.1 OpenZeppelin Upgrades Plugin

```javascript
// hardhat.config.js
require('@openzeppelin/hardhat-upgrades');

// scripts/deploy.js
const { ethers, upgrades } = require("hardhat");

async function main() {
    const V1 = await ethers.getContractFactory("V1");
    const proxy = await upgrades.deployProxy(V1, [initArg]);
    
    // Later...
    const V2 = await ethers.getContractFactory("V2");
    await upgrades.upgradeProxy(proxy.address, V2);
    // Plugin automatically checks storage layout!
}
```

### 8.2 Storage Layout Verification

```bash
# Check storage layout compatibility
npx hardhat run scripts/validate-upgrade.js

# Output:
#  Storage layout compatible
#  No storage collisions
#  Gaps correctly adjusted
```

### 8.3 Slither Upgrade Checks

```bash
slither . --detect unprotected-upgrade
slither . --detect missing-inheritance
```

---

## 9. Real-World Upgrade Exploits

### 9.1 Wormhole Implementation Attack
```
- Uninitialized implementation
- Attacker initialized implementation
- Called selfdestruct via governance
- Impact: Could have bricked all proxies
```

### 9.2 Audius Governance Takeover
```
- Storage collision in upgrade
- New variable overwrote critical state
- Attacker gained control
- Impact: $6M stolen
```

### 9.3 Nomad Bridge Initialization
```
- Zero committedRoot set in upgrade
- Any message with zero proof accepted
- Impact: $190M drained
```

---

## Summary

| Vulnerability | Impact | Prevention |
|--------------|--------|------------|
| Storage Collision | State corruption | EIP-1967 slots |
| Uninitialized Impl | Implementation takeover | _disableInitializers() |
| Missing Gap | Future upgrade breaks | Always use __gap |
| UUPS No Upgrade | Bricked proxy | Always inherit UUPS |
| Front-run Upgrade | Rug pull | Timelock + multisig |
| Re-initialization | Access takeover | reinitializer(n) |

**Golden Rule**: Test every upgrade with actual production data. Simulate storage changes. Never rush upgrades.
