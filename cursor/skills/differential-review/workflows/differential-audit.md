# Differential Audit Workflow

Systematic workflow for conducting security-focused differential reviews.

---

## Phase 1: Scope Definition

### 1.1 Version Identification

```markdown
## Version Information

### Source Version (V1)
- Repository: 
- Commit: 
- Tag/Branch: 
- Audit Status: Audited by [X] on [date]

### Target Version (V2)
- Repository: 
- Commit: 
- Tag/Branch: 
- Expected Changes: (from changelog/PR)

### Comparison Method
- [ ] Git diff (same repo)
- [ ] Directory diff (different repos)
- [ ] Contract-by-contract comparison
```

### 1.2 Expected vs Actual Changes

```markdown
## Change Expectations

### Documented Changes (from changelog)
1. Fixed reentrancy in withdraw()
2. Added new staking module
3. Gas optimizations

### Verification Plan
| Expected Change | Verified | Notes |
|-----------------|----------|-------|
| Reentrancy fix | [ ] | |
| Staking module | [ ] | |
| Gas optimizations | [ ] | |
| UNEXPECTED CHANGES | [ ] | Flag any |
```

---

## Phase 2: File-Level Analysis

### 2.1 Generate File List

```bash
# Using git
git diff v1..v2 --name-status src/

# Categorize output
M   src/Vault.sol          # Modified
A   src/Staking.sol        # Added
D   src/Deprecated.sol     # Deleted
R   src/Utils.sol          # Renamed
```

### 2.2 Classify Files

```markdown
## File Classification

### Modified Files (Priority: High)
| File | Lines Changed | Risk Level |
|------|---------------|------------|
| Vault.sol | +150 -30 | Critical |
| Router.sol | +45 -10 | High |
| Utils.sol | +20 -5 | Medium |

### New Files (Priority: High)
| File | Lines | Risk Level |
|------|-------|------------|
| Staking.sol | 300 | Critical - New |
| StakingLib.sol | 100 | Medium |

### Deleted Files (Priority: Medium)
| File | Reason | Migration Check |
|------|--------|-----------------|
| OldHelper.sol | Replaced | [ ] Verify all callers updated |

### Unchanged Files (Priority: Low)
- Acknowledge no changes
- Verify no hidden modifications
```

### 2.3 Diff Statistics

```bash
# Get stats per file
git diff v1..v2 --stat src/

# Sample output:
 src/Vault.sol    | 180 +++++++++++++++++++++++--------
 src/Router.sol   | 55 ++++++++---
 src/Staking.sol  | 300 +++++++++++++++++++++++++++++++ (new)
 3 files changed, 485 insertions(+), 50 deletions(-)
```

---

## Phase 3: Critical Path Review

### 3.1 Identify Critical Changes

```markdown
## Critical Path Analysis

### Value Flow Changes
- [ ] Deposit logic
- [ ] Withdrawal logic
- [ ] Fee extraction
- [ ] Reward distribution

### Access Control Changes
- [ ] Owner/admin functions
- [ ] Role assignments
- [ ] Modifier logic
- [ ] Authentication

### External Dependency Changes
- [ ] New oracles
- [ ] New token interactions
- [ ] New protocol integrations
- [ ] New callback handlers
```

### 3.2 Deep Dive Template

```markdown
## Critical Change: [Function/Component Name]

### Location
- File: src/Vault.sol
- Function: withdraw()
- Lines: 150-200

### V1 Logic Summary
```solidity
// V1: Simple withdrawal
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;
    payable(msg.sender).transfer(amount);
}
```

### V2 Changes
```solidity
// V2: Added fee and reentrancy guard
function withdraw(uint256 amount) external nonReentrant {
    require(balances[msg.sender] >= amount);
    uint256 fee = amount * FEE_BPS / 10000;
    uint256 payout = amount - fee;
    balances[msg.sender] -= amount;
    accumulatedFees += fee;
    (bool success,) = msg.sender.call{value: payout}("");
    require(success);
}
```

### Security Analysis
- [x] Reentrancy: Protected with nonReentrant ✅
- [ ] Fee calculation: Check for rounding ⚠️
- [ ] Fee extraction: Who can claim? ⚠️
- [x] Balance update: Before external call ✅

### Findings
- [ ] None
- [ ] Informational
- [ ] Low
- [ ] Medium
- [ ] High
- [ ] Critical
```

---

## Phase 4: New Code Review

### 4.1 New File Audit

```markdown
## New File Review: Staking.sol

### Overview
- Purpose: Allow users to stake tokens for rewards
- Lines: 300
- Complexity: Medium
- External Calls: 2 (token.transferFrom, rewardToken.transfer)

### Architecture Review
- [ ] Follows protocol patterns
- [ ] Consistent with existing code
- [ ] Proper separation of concerns

### Security Checklist
- [ ] Access control on all admin functions
- [ ] Reentrancy protection
- [ ] Input validation
- [ ] Integer overflow/underflow
- [ ] DoS vectors
- [ ] Front-running risks

### Static Analysis Results
```bash
slither src/Staking.sol
# Results:
# High: 0
# Medium: 1 - External call in loop
# Low: 3 - ...
```

### Function-by-Function Review
| Function | Visibility | Risk | Reviewed |
|----------|------------|------|----------|
| stake() | external | High | [ ] |
| unstake() | external | High | [ ] |
| claimRewards() | external | Medium | [ ] |
| updateRewardRate() | onlyOwner | Medium | [ ] |
```

### 4.2 Deleted Code Verification

```markdown
## Deleted Code Review

### Removed: OldHelper.sol

### Usage Analysis
Was called by:
- Vault.sol:depositWithHelper() - REMOVED
- Router.sol:routeViaHelper() - REMOVED

### Migration Status
- [x] All calls removed
- [x] No orphan imports
- [x] Replacement logic verified
- [ ] Tests updated

### Risk: LOW - Clean removal
```

---

## Phase 5: Integration Analysis

### 5.1 New Dependencies

```markdown
## New External Dependencies

### Added: INewOracle
```solidity
// New dependency in V2
interface INewOracle {
    function getPrice(address token) external view returns (uint256);
}
```

### Trust Analysis
- Oracle address: Set by owner
- Can be changed: Yes, via setOracle()
- Validation: [ ] Check if whitelisted oracles only

### Risk Assessment
| Concern | Status |
|---------|--------|
| Oracle manipulation | [ ] Review needed |
| Stale prices | [ ] Check freshness |
| Zero/negative prices | [ ] Bounds check |
```

### 5.2 Interface Changes

```markdown
## External Interface Changes

### Modified Functions
| Function | V1 Signature | V2 Signature | Breaking? |
|----------|--------------|--------------|-----------|
| deposit | deposit(uint256) | deposit(uint256,address) | Yes ⚠️ |
| withdraw | withdraw(uint256) | withdraw(uint256) | No |

### New External Functions
| Function | Visibility | Access | Risk |
|----------|------------|--------|------|
| stake() | external | public | High |
| emergencyPause() | external | onlyOwner | Medium |

### Removed Functions
| Function | Replacement | Migration |
|----------|-------------|-----------|
| legacyDeposit() | deposit() | Scripts needed |

### Breaking Changes Action Items
- [ ] Update all integrating contracts
- [ ] Notify frontend team
- [ ] Update SDK/API documentation
```

---

## Phase 6: Storage Verification

### 6.1 Layout Comparison

```markdown
## Storage Layout Analysis

### V1 Storage
| Slot | Variable | Type |
|------|----------|------|
| 0 | owner | address |
| 1 | totalDeposits | uint256 |
| 2 | balances | mapping |
| 3-50 | __gap | uint256[48] |

### V2 Storage
| Slot | Variable | Type | Change |
|------|----------|------|--------|
| 0 | owner | address | Same |
| 1 | totalDeposits | uint256 | Same |
| 2 | balances | mapping | Same |
| 3 | stakingEnabled | bool | NEW (from gap) |
| 4 | rewardRate | uint256 | NEW (from gap) |
| 5-50 | __gap | uint256[46] | Reduced |

### Compatibility Check
- [x] Slots 0-2 unchanged
- [x] New variables from gap
- [x] Gap properly reduced
- [x] No inheritance reorder

### Status: ✅ COMPATIBLE
```

---

## Phase 7: Testing Review

### 7.1 Test Coverage Diff

```bash
# V1 coverage
cd v1 && forge coverage --report summary

# V2 coverage
cd v2 && forge coverage --report summary

# Compare
diff v1-coverage.txt v2-coverage.txt
```

### 7.2 New Test Requirements

```markdown
## Test Coverage Analysis

### New Functionality Tests
| Function | Unit Test | Integration Test | Fuzz Test |
|----------|-----------|------------------|-----------|
| stake() | [ ] | [ ] | [ ] |
| unstake() | [ ] | [ ] | [ ] |
| claimRewards() | [ ] | [ ] | [ ] |

### Edge Case Tests
- [ ] Zero amount staking
- [ ] Unstake more than balance
- [ ] Claim with no rewards
- [ ] Multiple stakes same block

### Upgrade Tests
- [ ] State preservation
- [ ] New initializer
- [ ] Old functions still work
```

---

## Phase 8: Report Generation

### 8.1 Differential Report Template

```markdown
# Differential Security Review

## Executive Summary
This review examines changes between V1 (commit abc123) and V2 (commit def456).

### Scope
- Modified files: X
- New files: Y
- Deleted files: Z
- Lines changed: +A -B

### Findings Summary
| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 1 |
| Medium | 2 |
| Low | 3 |
| Informational | 5 |

### Key Changes
1. **New Staking Module** - Medium risk, new funds flow
2. **Oracle Migration** - High risk, new trust assumption
3. **Fee Mechanism** - Low risk, properly implemented

---

## Detailed Findings

### [H-01] New Oracle Can Return Stale Prices

**Location:** src/Vault.sol#L150

**Description:** The new oracle integration...

**V2 Change:**
```diff
+ uint256 price = newOracle.getPrice(token);
- uint256 price = oldOracle.getLatestPrice();
```

**Recommendation:** Add staleness check...

---

## Verified Fixes

### Previously Reported Issues

| ID | Title | Status | Notes |
|----|-------|--------|-------|
| PREV-001 | Reentrancy in withdraw | ✅ Fixed | nonReentrant added |
| PREV-002 | Access control | ✅ Fixed | onlyOwner added |

---

## Storage Layout
✅ Compatible - See Appendix A

## Test Coverage
Coverage maintained at 95%+

## Recommendations
1. Add staleness check to oracle
2. Increase test coverage for staking edge cases
3. Consider timelock for oracle changes
```

---

## Workflow Checklist

```markdown
## Differential Review Checklist

### Preparation
- [ ] Both versions accessible
- [ ] Expected changes documented
- [ ] Previous audit findings reviewed

### File Analysis
- [ ] All file changes catalogued
- [ ] Files classified by risk
- [ ] Unexpected changes flagged

### Critical Review
- [ ] Value flow changes analyzed
- [ ] Access control changes verified
- [ ] External dependencies reviewed

### New Code
- [ ] New files audited
- [ ] Static analysis run
- [ ] Integration points verified

### Storage
- [ ] Layout compared
- [ ] Compatibility verified
- [ ] Gaps maintained

### Testing
- [ ] Coverage adequate
- [ ] Upgrade tests pass
- [ ] Edge cases covered

### Documentation
- [ ] Changes documented
- [ ] Findings reported
- [ ] Recommendations made
```
