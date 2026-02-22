---
id: DIFF-UPGRADE-SAFE
title: Upgrade Safety Guide
parent: differential-review
type: resource
last_updated: 2025-01-31
---

# Upgrade Safety Guide

Comprehensive guide for verifying safe upgrades of proxy-based and non-proxy smart contracts.

---

## Storage Layout Compatibility

Upgradeable proxies (UUPS, Transparent, Diamond) store state in the **proxy contract** but delegate logic to the **implementation contract**. Changing the storage layout in the implementation breaks the proxy.

### Rules

| Rule | Safe Example | Dangerous Example |
|------|-------------|--------------------|
| Append-only | Add `uint256 newVar;` at the end | Insert `uint256 newVar;` between existing |
| No type changes | Keep `uint256 balance;` | Change to `int256 balance;` |
| No reordering | Keep original variable order | Swap `a` and `b` positions |
| No removal | Don't delete variables | Delete `uint256 deprecated;` |
| Gap usage | Use `uint256[50] __gap;` for future slots | No gap = no room to add variables |

### How Storage Slots Are Assigned

```solidity
// V1
contract MyContractV1 {
    uint256 public a;      // slot 0
    uint256 public b;      // slot 1
    address public owner;  // slot 2
    uint256[47] __gap;     // slots 3-49 (reserved)
}

// V2 - SAFE upgrade (uses gap)
contract MyContractV2 {
    uint256 public a;         // slot 0 (unchanged)
    uint256 public b;         // slot 1 (unchanged)
    address public owner;     // slot 2 (unchanged)
    uint256 public newVar;    // slot 3 (was __gap[0])
    uint256[46] __gap;        // slots 4-49 (gap reduced by 1)
}

// V2 - DANGEROUS upgrade (inserted variable)
contract MyContractV2Bad {
    uint256 public a;         // slot 0
    uint256 public newVar;    // slot 1 ← WAS 'b', now corrupted!
    uint256 public b;         // slot 2 ← WAS 'owner', corrupted!
    address public owner;     // slot 3 ← reads garbage
}
```

### Mapping and Dynamic Array Slots

```
mapping(key => value) stored at: keccak256(key . slot)
array[] length at: slot; elements at: keccak256(slot) + index
```

These don't conflict with sequential slots, but changing the **key type** or **value type** of a mapping at the same slot corrupts data.

---

## Proxy Pattern Safety

### UUPS (EIP-1822)

```solidity
// V1 Implementation
contract MyContractV1 is UUPSUpgradeable {
    function _authorizeUpgrade(address newImpl) internal override onlyOwner {}
    
    // CRITICAL: If V2 doesn't include _authorizeUpgrade, 
    // the contract becomes non-upgradeable (bricked)
}
```

| Check | What to Verify |
|-------|----------------|
| `_authorizeUpgrade` present | Must exist in every new implementation |
| `initializer` guard | `initialize()` can't be re-called |
| No `selfdestruct` | New impl must not contain `selfdestruct` |
| No `delegatecall` to untrusted | Could overwrite implementation slot |
| Storage layout compatible | Run `forge inspect --storage-layout` on both versions |

### Transparent Proxy (EIP-1967)

| Check | What to Verify |
|-------|----------------|
| Admin slot correct | `bytes32(uint256(keccak256('eip1967.proxy.admin')) - 1)` |
| Implementation slot correct | `bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)` |
| No function selector collision | Admin functions don't collide with implementation |
| Proxy admin secured | Multisig or governance, not EOA |

### Diamond (EIP-2535)

| Check | What to Verify |
|-------|----------------|
| Facet function selectors unique | No selector collision across facets |
| Storage per facet isolated | Use DiamondStorage pattern |
| Cut operation authorized | `diamondCut` restricted to owner |
| Loupe functions present | `facets()`, `facetAddresses()`, etc. |

---

## Initializer Safety

```solidity
// VULNERABLE: Can be re-initialized after upgrade
function initialize(address _owner) public {
    owner = _owner;  // No guard! Anyone can call again after upgrade
}

// SAFE: Uses OpenZeppelin initializer
function initialize(address _owner) public initializer {
    __Ownable_init(_owner);
}

// V2 SAFE: Uses reinitializer for new state
function initializeV2(address _newParam) public reinitializer(2) {
    newParam = _newParam;
}
```

| Version | Guard | Purpose |
|---------|-------|---------|
| V1 | `initializer` | First-time initialization |
| V2 | `reinitializer(2)` | Upgrade initialization |
| V3 | `reinitializer(3)` | Second upgrade initialization |

---

## Dependency Update Checks

### OpenZeppelin Upgrades

| From → To | Key Changes to Audit |
|-----------|---------------------|
| v4.x → v5.x | Namespace storage, constructor-based init, removed `_setupRole` |
| v4.8 → v4.9 | `Governor` changes, new `Nonces` |
| Any minor bump | Check CHANGELOG for security patches |

### Solidity Compiler Upgrades

| Version Change | Key Security Considerations |
|----------------|----------------------------|
| 0.8.x → 0.8.y | Check opcode changes, optimizer behavior |
| < 0.8.0 → >= 0.8.0 | Native overflow checks added |
| Any version | Check known compiler bugs for both versions |

### External Protocol Updates

| Integration | What to Check |
|-------------|---------------|
| Chainlink | Price feed address changes, decimals, heartbeat |
| Uniswap | Router address, interface changes, pool creation |
| AAVE | LendingPool interface, token wrapping changes |
| Compound | Comptroller changes, cToken interface |

---

## Automated Storage Verification

```bash
# Foundry: Compare storage layouts
forge inspect ContractV1 storage-layout > v1_storage.json
forge inspect ContractV2 storage-layout > v2_storage.json
diff v1_storage.json v2_storage.json

# OpenZeppelin Upgrades Plugin
npx @openzeppelin/upgrades-core validate

# Slither storage layout printer
slither . --print variable-order
```

---

## Upgrade Safety Checklist

### Storage
- [ ] Storage layout compared between V1 and V2
- [ ] New variables appended only (not inserted)
- [ ] No type changes on existing variables
- [ ] No variable reordering
- [ ] `__gap` reduced appropriately for new variables
- [ ] Mapping key/value types unchanged

### Initialization
- [ ] `initializer` guard present on `initialize()`
- [ ] `reinitializer(N)` used for upgrade-specific init
- [ ] New V2 state properly initialized
- [ ] Initializer cannot be front-run

### Implementation
- [ ] No `selfdestruct` in new implementation
- [ ] No `delegatecall` to untrusted targets
- [ ] `_authorizeUpgrade` present (for UUPS)
- [ ] Function selectors don't collide (for Transparent)
- [ ] All inherited contracts also storage-compatible

### Integration
- [ ] External integrations still compatible
- [ ] Events haven't changed (indexers depend on them)
- [ ] ABI backward compatible (or integrators notified)
