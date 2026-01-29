# Upgrade Safety Patterns

Comprehensive guide for analyzing upgrade safety in smart contract differential reviews.

---

## Proxy Patterns Overview

### 1. Transparent Proxy Pattern

```solidity
// TransparentUpgradeableProxy
contract TransparentProxy {
    // EIP-1967 slots
    bytes32 internal constant IMPLEMENTATION_SLOT = 
        bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
    bytes32 internal constant ADMIN_SLOT = 
        bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1);
    
    // Admin functions only callable by admin
    function upgradeTo(address newImplementation) external {
        require(msg.sender == _getAdmin());
        _setImplementation(newImplementation);
    }
    
    // Fallback delegates to implementation
    fallback() external payable {
        require(msg.sender != _getAdmin()); // Admin can't call impl
        _delegate(_getImplementation());
    }
}
```

**Upgrade Safety Checks:**
- [ ] Admin is secure (multisig/timelock)
- [ ] Storage layout compatible
- [ ] Initializers protected with `reinitializer`

### 2. UUPS Pattern (EIP-1822)

```solidity
// Implementation contract with upgrade logic
contract VaultV2 is UUPSUpgradeable {
    // Authorization check
    function _authorizeUpgrade(address newImplementation) 
        internal 
        override 
        onlyOwner 
    {}
}
```

**Upgrade Safety Checks:**
- [ ] `_authorizeUpgrade` cannot be bypassed
- [ ] Cannot upgrade to non-UUPS implementation
- [ ] Upgrade function preserved in new version

### 3. Beacon Proxy Pattern

```solidity
contract BeaconProxy {
    IBeacon public immutable beacon;
    
    fallback() external payable {
        address impl = beacon.implementation();
        _delegate(impl);
    }
}

contract UpgradeableBeacon {
    address public implementation;
    
    function upgradeTo(address newImplementation) external onlyOwner {
        implementation = newImplementation;
    }
}
```

**Upgrade Safety Checks:**
- [ ] Beacon ownership secure
- [ ] All proxies tested after upgrade
- [ ] Implementation compatible with all proxy states

---

## Storage Layout Rules

### Rule 1: Never Reorder Existing Variables

```solidity
// V1
contract VaultV1 {
    address public owner;    // slot 0
    uint256 public balance;  // slot 1
}

// V2 - WRONG ❌
contract VaultV2 {
    uint256 public balance;  // slot 0 - REORDERED!
    address public owner;    // slot 1 - REORDERED!
}

// V2 - CORRECT ✅
contract VaultV2 {
    address public owner;    // slot 0 - unchanged
    uint256 public balance;  // slot 1 - unchanged
    uint256 public newVar;   // slot 2 - appended
}
```

### Rule 2: Never Change Variable Types

```solidity
// V1
contract VaultV1 {
    uint128 public value;  // slot 0 (half)
}

// V2 - WRONG ❌
contract VaultV2 {
    uint256 public value;  // Now uses full slot!
}

// V2 - CORRECT ✅ (if needed, new variable)
contract VaultV2 {
    uint128 public value;      // unchanged
    uint128 public reserved;   // padding
    uint256 public newValue;   // new slot
}
```

### Rule 3: Never Remove Variables

```solidity
// V1
contract VaultV1 {
    address public owner;
    address public deprecated;  // Want to remove
    uint256 public balance;
}

// V2 - WRONG ❌
contract VaultV2 {
    address public owner;
    uint256 public balance;  // Shifted!
}

// V2 - CORRECT ✅
contract VaultV2 {
    address public owner;
    address public __deprecated;  // Keep slot, rename
    uint256 public balance;
}
```

### Rule 4: Maintain Storage Gaps

```solidity
// V1
abstract contract VaultStorageV1 {
    address public owner;
    uint256 public totalSupply;
    uint256[48] private __gap;  // 48 reserved slots
}

// V2 - Uses gap correctly
abstract contract VaultStorageV2 is VaultStorageV1 {
    // Parent has 2 slots + 48 gap = 50 slots total
    
    // Add to child, consuming from END of gap
    uint256 public newValue;       // From gap[47]
    mapping(address => bool) public newMapping;  // From gap[46]
    uint256[46] private __gap;     // Now 46 slots
}
```

---

## Inheritance Changes

### Safe Inheritance Modification

```solidity
// V1
contract VaultV1 is Ownable, ReentrancyGuard {
    uint256 public value;
}

// V2 - SAFE ✅ (Appending to inheritance)
contract VaultV2 is Ownable, ReentrancyGuard, Pausable {
    uint256 public value;
}

// V2 - UNSAFE ❌ (Reordering inheritance)
contract VaultV2 is Pausable, Ownable, ReentrancyGuard {
    uint256 public value;
}
```

### Diamond Storage (Avoids Inheritance Issues)

```solidity
library VaultStorage {
    bytes32 constant STORAGE_SLOT = keccak256("vault.storage");
    
    struct Storage {
        address owner;
        uint256 totalDeposits;
        mapping(address => uint256) balances;
    }
    
    function layout() internal pure returns (Storage storage s) {
        bytes32 slot = STORAGE_SLOT;
        assembly {
            s.slot := slot
        }
    }
}

// Usage - storage location is deterministic
contract VaultV2 {
    function deposit() external {
        VaultStorage.layout().balances[msg.sender] += msg.value;
    }
}
```

---

## Initializer Patterns

### Single Initialization

```solidity
// V1
contract VaultV1 is Initializable {
    function initialize(address _owner) initializer public {
        owner = _owner;
    }
}
```

### Reinitializer for Upgrades

```solidity
// V2
contract VaultV2 is VaultV1 {
    function initializeV2(address _newParam) reinitializer(2) public {
        // Only runs once, only after V1 initialized
        newParam = _newParam;
    }
}

// V3
contract VaultV3 is VaultV2 {
    function initializeV3() reinitializer(3) public {
        // Version 3 initialization
    }
}
```

### Disable Initializers in Constructor

```solidity
contract VaultV2 is VaultV1 {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }
}
```

---

## Common Upgrade Vulnerabilities

### 1. Uninitialized Implementation

```solidity
// VULNERABLE: Implementation can be initialized by attacker
contract VaultV1 is Initializable {
    function initialize(address _owner) initializer public {
        owner = _owner;  // Attacker can set themselves as owner
    }
}

// SECURE: Disable initializers in constructor
contract VaultV1 is Initializable {
    constructor() {
        _disableInitializers();
    }
    
    function initialize(address _owner) initializer public {
        owner = _owner;
    }
}
```

### 2. Selfdestruct in Implementation

```solidity
// VULNERABLE: UUPS implementation can be destroyed
contract VaultV1 is UUPSUpgradeable {
    function destroy() external onlyOwner {
        selfdestruct(payable(owner));  // Bricks all proxies!
    }
}

// SECURE: Never allow selfdestruct in upgradeable
// And use reinitializer to prevent delegatecall attacks
```

### 3. Missing Upgrade Authorization

```solidity
// VULNERABLE: Anyone can upgrade UUPS
contract VaultV1 is UUPSUpgradeable {
    function _authorizeUpgrade(address) internal override {
        // No checks!
    }
}

// SECURE: Proper authorization
contract VaultV1 is UUPSUpgradeable, OwnableUpgradeable {
    function _authorizeUpgrade(address) internal override onlyOwner {}
}
```

### 4. Function Shadowing

```solidity
// V1
contract Base {
    function foo() external returns (uint256) {
        return 1;
    }
}

// V2 - ISSUE: Child shadows parent function
contract Derived is Base {
    function foo() external returns (uint256) {  // Shadows Base.foo
        return 2;
    }
}
```

---

## Storage Analysis Tools

### Slither Storage Layout

```bash
# Generate layout
slither . --print variable-order

# Output:
# Contract Vault:
# +--------+----------------+------+--------+
# | Slot   | Variable       | Type | Offset |
# +--------+----------------+------+--------+
# | 0      | owner          | address | 0  |
# | 1      | totalDeposits  | uint256 | 0  |
# | 2      | balances       | mapping | 0  |
# +--------+----------------+------+--------+
```

### Foundry Inspect

```bash
# JSON layout
forge inspect Vault storage-layout --json

# Pretty layout
forge inspect Vault storage-layout --pretty
```

### OpenZeppelin Upgrades Plugin

```javascript
// hardhat.config.js
require("@openzeppelin/hardhat-upgrades");

// scripts/validate.js
const { validateUpgrade } = require("@openzeppelin/hardhat-upgrades");

async function main() {
    const VaultV2 = await ethers.getContractFactory("VaultV2");
    await validateUpgrade(PROXY_ADDRESS, VaultV2);
    console.log("Upgrade is safe!");
}
```

---

## Upgrade Checklist

```markdown
## Pre-Upgrade Checklist

### Storage Safety
- [ ] No variable reordering
- [ ] No type changes
- [ ] No variable removal
- [ ] Gap maintained (if used)
- [ ] Inheritance order preserved

### Initialization
- [ ] Reinitializer version correct
- [ ] Implementation constructor disables initializers
- [ ] Init function access controlled

### Authorization
- [ ] Upgrade path protected (owner/multisig/timelock)
- [ ] _authorizeUpgrade properly implemented (UUPS)
- [ ] Cannot upgrade to zero address
- [ ] Cannot upgrade to non-contract

### Functionality
- [ ] All existing functions work
- [ ] All state accessible
- [ ] New functions tested
- [ ] Edge cases covered

### Deployment
- [ ] Upgrade script tested on fork
- [ ] Timelock delay respected
- [ ] Monitoring in place
- [ ] Rollback plan ready
```

---

## Fork Testing Upgrade

```solidity
// test/Upgrade.fork.t.sol
contract UpgradeForkTest is Test {
    address constant PROXY = 0x...;
    address constant ADMIN = 0x...;
    
    function setUp() public {
        // Fork mainnet at specific block
        vm.createSelectFork("mainnet", 18_000_000);
    }
    
    function testUpgradeOnFork() public {
        // Get current state
        IVault vault = IVault(PROXY);
        uint256 preTotalDeposits = vault.totalDeposits();
        uint256 preUserBalance = vault.balances(USER);
        
        // Deploy new implementation
        VaultV2 newImpl = new VaultV2();
        
        // Impersonate admin and upgrade
        vm.prank(ADMIN);
        ITransparentUpgradeableProxy(PROXY).upgradeTo(address(newImpl));
        
        // Initialize V2
        IVaultV2(PROXY).initializeV2(NEW_PARAM);
        
        // Verify state preserved
        assertEq(vault.totalDeposits(), preTotalDeposits);
        assertEq(vault.balances(USER), preUserBalance);
        
        // Verify new functionality
        assertEq(IVaultV2(PROXY).newParam(), NEW_PARAM);
    }
}
```
