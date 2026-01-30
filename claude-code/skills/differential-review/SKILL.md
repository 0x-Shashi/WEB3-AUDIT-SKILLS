---
name: Differential Review
description: Compare contract versions and identify security-relevant changes
version: 1.0.0
author: Web3 Security Plugin
tags: [diff, comparison, upgrade, version, security, audit]
---

# Differential Review Skill

Systematic methodology for comparing smart contract versions and identifying security-relevant changes.

## Capabilities

- **Version Comparison**: Compare V1 to V2 contracts
- **Change Classification**: Categorize changes by risk level
- **Upgrade Safety**: Verify storage layout compatibility
- **Migration Analysis**: Review upgrade/migration logic

---

## When to Use Differential Review

1. **Protocol Upgrade**: Reviewing V2 of a previously audited protocol
2. **Fix Verification**: Confirming changes only address reported issues
3. **Fork Analysis**: Comparing a fork to the original
4. **Incremental Audit**: Reviewing changes since last audit

---

## Phase 1: Prepare the Comparison

### 1.1 Set Up Versions

```bash
# Clone both versions
git clone <repo> v1 --branch v1.0.0
git clone <repo> v2 --branch v2.0.0

# Or checkout branches
git checkout v1.0.0 -- src/ > v1/
git checkout v2.0.0 -- src/ > v2/

# Or use git worktree
git worktree add ../v1 v1.0.0
git worktree add ../v2 v2.0.0
```

### 1.2 Document Scope

```markdown
## Differential Review Scope

### Version Information
- **V1**: commit abc1234 (tag: v1.0.0)
- **V2**: commit def5678 (tag: v2.0.0)

### Expected Changes
(From changelog/PR description)
- New staking mechanism
- Fixed reentrancy issue
- Gas optimizations

### Focus Areas
- [ ] Security-relevant changes
- [ ] Storage layout changes
- [ ] Access control changes
- [ ] External interface changes
```

---

## Phase 2: Generate Diffs

### 2.1 File-Level Diff

```bash
# List changed files
diff -rq v1/src v2/src

# Or with git
git diff v1.0.0..v2.0.0 --name-status src/

# Output example:
# M   src/Vault.sol         (Modified)
# A   src/Staking.sol       (Added)
# D   src/OldHelper.sol     (Deleted)
# R   src/Utils.sol         (Renamed)
```

### 2.2 Detailed Code Diff

```bash
# Full diff
git diff v1.0.0..v2.0.0 src/ > diff.patch

# Per-file diff
git diff v1.0.0..v2.0.0 -- src/Vault.sol

# Side-by-side comparison
diff -y v1/src/Vault.sol v2/src/Vault.sol | less

# Ignore whitespace
git diff v1.0.0..v2.0.0 -w src/
```

### 2.3 Using diff-so-fancy (Recommended)

```bash
# Install
npm install -g diff-so-fancy

# Use with git
git diff v1.0.0..v2.0.0 | diff-so-fancy

# Save as HTML
git diff v1.0.0..v2.0.0 | diff-so-fancy --html > diff.html
```

---

## Phase 3: Classify Changes

### 3.1 Change Classification Matrix

```markdown
## Change Classification

### Critical (Immediate Review)
| File | Change | Reason |
|------|--------|--------|
| Vault.sol | New withdraw logic | Core financial function |
| Access.sol | Modified onlyOwner | Access control change |

### High (Detailed Review)
| File | Change | Reason |
|------|--------|--------|
| Router.sol | New swap path | External interaction |
| Oracle.sol | Price calculation | Economic impact |

### Medium (Standard Review)
| File | Change | Reason |
|------|--------|--------|
| Utils.sol | New helper functions | Could be called from critical |
| Events.sol | New events | Verify no side effects |

### Low (Quick Review)
| File | Change | Reason |
|------|--------|--------|
| Constants.sol | Value changes | Verify reasonableness |
| Comments | Documentation | Verify accuracy |

### Informational (Acknowledge)
| File | Change | Reason |
|------|--------|--------|
| Formatting | Style only | No security impact |
```

### 3.2 Change Type Categories

```markdown
## Change Categories

### Security-Critical
- [ ] Access control modifications
- [ ] External call changes
- [ ] State variable additions/removals
- [ ] Value transfer logic
- [ ] Signature/authentication
- [ ] Oracle/price logic

### Functional Changes
- [ ] New functions added
- [ ] Function logic modified
- [ ] Return value changes
- [ ] Event changes

### Interface Changes
- [ ] Function signature changes
- [ ] New external functions
- [ ] Removed functions
- [ ] Visibility changes

### Structural Changes
- [ ] Inheritance changes
- [ ] Import changes
- [ ] Library changes
- [ ] Storage layout

### Optimizations
- [ ] Gas optimizations
- [ ] Code refactoring
- [ ] Compiler version
```

---

## Phase 4: Security-Focused Review

### 4.1 Access Control Changes

```markdown
## Access Control Analysis

### New Roles/Modifiers
```solidity
// V1: Only owner
modifier onlyOwner() {...}

// V2: Added role-based
modifier onlyOwner() {...}
modifier onlyAdmin() {...}  // NEW
modifier onlyOperator() {...}  // NEW
```

### Permission Matrix Change
| Function | V1 Access | V2 Access | Risk |
|----------|-----------|-----------|------|
| withdraw | onlyOwner | onlyAdmin |  Review |
| pause | onlyOwner | onlyOperator |  Review |
| upgrade | onlyOwner | onlyOwner |  Same |

### Questions
- [ ] Can new roles escalate?
- [ ] Are role assignments secure?
- [ ] Any backdoors introduced?
```

### 4.2 External Call Changes

```markdown
## External Call Analysis

### New External Calls
```solidity
// V2 added:
interface INewOracle {
    function getPrice() external view returns (uint256);
}

// Called in:
function calculateValue() {
    uint256 price = newOracle.getPrice();  // NEW CALL
}
```

### External Call Comparison
| V1 Calls | V2 Calls | Risk |
|----------|----------|------|
| OldOracle.getPrice | NewOracle.getPrice | Trust change |
| token.transfer | token.safeTransfer |  Safer |
| - | router.swap |  New dependency |

### Questions
- [ ] New trusted contracts?
- [ ] Callback risks?
- [ ] Reentrancy implications?
```

### 4.3 Value Flow Changes

```markdown
## Value Flow Analysis

### ETH Flow Changes
| Path | V1 | V2 | Change |
|------|----|----|--------|
| Deposit | uservault | uservault | Same |
| Withdraw | vaultuser | vaulttreasuryuser |  New hop |
| Fees | None | vaulttreasury |  New extraction |

### Token Flow Changes
| Token | V1 Flow | V2 Flow | Risk |
|-------|---------|---------|------|
| USDC | Direct | Via router | New dependency |
| LP | Locked | Stakeable | New mechanics |

### Questions
- [ ] Can value be extracted?
- [ ] New fee mechanisms?
- [ ] Intermediary risks?
```

---

## Phase 5: Storage Layout Analysis

### 5.1 Compare Storage Layouts

```bash
# Using Slither
slither v1/src/Vault.sol --print variable-order > v1-storage.txt
slither v2/src/Vault.sol --print variable-order > v2-storage.txt
diff v1-storage.txt v2-storage.txt

# Using Foundry (with forge-std)
forge inspect Vault storage-layout --json > v2-layout.json
```

### 5.2 Storage Layout Verification

```markdown
## Storage Layout Comparison

### V1 Layout
| Slot | Variable | Type |
|------|----------|------|
| 0 | owner | address |
| 1 | paused | bool |
| 2 | totalDeposits | uint256 |
| 3 | balances | mapping |

### V2 Layout
| Slot | Variable | Type |
|------|----------|------|
| 0 | owner | address |
| 1 | paused | bool |
| 2 | totalDeposits | uint256 |
| 3 | balances | mapping |
| 4 | newVariable | uint256 |  NEW (OK)

### Compatibility Check
- [x] Slots 0-3 unchanged 
- [x] New variable appended 
- [ ] No insertions in middle 
- [ ] Types unchanged 

### Status:  Storage Compatible
```

### 5.3 Storage Gap Pattern

```solidity
// V1 with gap
contract VaultV1 {
    uint256 public value;
    uint256[49] private __gap;  // Reserve 49 slots
}

// V2 using gap
contract VaultV2 {
    uint256 public value;
    uint256 public newValue;     // Uses 1 slot from gap
    uint256[48] private __gap;   // Now 48 slots
}
```

---

## Phase 6: New Code Analysis

### 6.1 Review New Files

```markdown
## New Files Review

### src/Staking.sol (NEW)
- Lines: 250
- Complexity: Medium
- External Calls: 3
- Risk Level: High (handles user funds)

### Review Focus
- [ ] Access control
- [ ] Reentrancy protection
- [ ] Math safety
- [ ] Input validation
- [ ] Integration with existing code

### Slither Results
| Detector | Count |
|----------|-------|
| High | 0 |
| Medium | 2 |
| Low | 5 |
```

### 6.2 Review Removed Code

```markdown
## Removed Code Review

### Removed: src/OldHelper.sol

### Was it used?
- Called by: Vault.sol (removed calls)
- Imported by: Router.sol (import removed)

### Migration Check
- [x] All callers updated
- [x] No orphan references
- [x] Replacement works correctly

### Risk: Low - Clean removal
```

---

## Phase 7: Integration Testing

### 7.1 Upgrade Path Testing

```solidity
// test/Upgrade.t.sol
contract UpgradeTest is Test {
    VaultV1 v1;
    VaultV2 v2;
    
    function setUp() public {
        // Deploy V1 and add state
        v1 = new VaultV1();
        v1.deposit{value: 10 ether}();
        
        // Record pre-upgrade state
        uint256 preBal = v1.totalDeposits();
    }
    
    function testUpgradePreservesState() public {
        // Upgrade to V2
        v2 = VaultV2(upgradeProxy(v1, v2Impl));
        
        // Verify state preserved
        assertEq(v2.totalDeposits(), 10 ether);
        assertEq(v2.balances(user), 10 ether);
    }
    
    function testNewFunctionalityWorks() public {
        v2 = VaultV2(upgradeProxy(v1, v2Impl));
        
        // Test new features
        v2.newFunction();
        assertEq(v2.newVariable(), expectedValue);
    }
    
    function testOldFunctionalityStillWorks() public {
        v2 = VaultV2(upgradeProxy(v1, v2Impl));
        
        // Old operations still work
        v2.deposit{value: 1 ether}();
        v2.withdraw(1 ether);
    }
}
```

---

## Phase 8: Generate Report

### 8.1 Differential Review Report

```markdown
# Differential Review Report

## Overview
| Metric | V1 | V2 | Change |
|--------|----|----|--------|
| Total Files | 15 | 18 | +3 |
| Total Lines | 2,500 | 3,100 | +600 |
| External Deps | 3 | 5 | +2 |
| Modified Files | - | 8 | - |
| New Files | - | 3 | - |

## Summary of Changes

### Security-Relevant Changes
1. **New staking mechanism** - Medium risk, new funds flow
2. **Oracle change** - High risk, new trust assumption  
3. **Fee extraction** - Medium risk, new value extraction

### Fixes Verified
| Finding | Status | Notes |
|---------|--------|-------|
| AUDIT-001 |  Fixed | Reentrancy addressed |
| AUDIT-002 |  Fixed | Access control added |
| AUDIT-003 |  Partial | One variant remains |

### New Concerns
| ID | Description | Severity |
|----|-------------|----------|
| DIFF-001 | New oracle trust | Medium |
| DIFF-002 | Staking withdrawal delay | Low |

## Storage Layout
 Compatible - New variables appended correctly

## Recommendations
1. Review new oracle integration
2. Add tests for staking edge cases
3. Fix remaining variant of AUDIT-003
```

---

## Quick Reference

```bash
# File list comparison
git diff v1..v2 --name-only

# Stats
git diff v1..v2 --stat

# Changed lines only (no context)
git diff v1..v2 -U0

# Function changes only (approximate)
git diff v1..v2 | grep "function "

# Slither comparison
slither v1/ --json v1-slither.json
slither v2/ --json v2-slither.json
diff v1-slither.json v2-slither.json
```

