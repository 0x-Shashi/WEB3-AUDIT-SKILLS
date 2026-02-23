---
id: METHOD-FIX-VERIFICATION
title: Fix Verification Patterns
category: methodology
difficulty: advanced
triggers: [verify fix, fix review, was the fix correct, fix introduces new bug, regression test, fix verification]
related_skills: [methodology/invariant-testing.md, methodology/poc-writing-guide.md, methodology/secure-pattern-reference.md]
tags: [fix-review, regression, verification, testing, ci-cd]
last_updated: 2026-01-31
---

# Fix Verification Patterns

## Overview

Verifying that security fixes are correct is as critical as finding the original bug. ~30% of fixes introduce new vulnerabilities or incompletely address the original issue.

---

## 1. Common Fix Failures

### 1.1 Incomplete Fixes

```solidity
// ORIGINAL BUG: Reentrancy
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    (bool success, ) = msg.sender.call{value: amount}("");
    balances[msg.sender] -= amount;
}

// BAD FIX: Only added check, still vulnerable
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    require(amount > 0, "Zero amount");  // Useless addition
    (bool success, ) = msg.sender.call{value: amount}("");
    balances[msg.sender] -= amount;
}

// CORRECT FIX: CEI pattern
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;  // State change BEFORE call
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
}
```

### 1.2 Fix Creates New Bug

```solidity
// ORIGINAL: Missing access control
function setPrice(uint256 newPrice) external {
    price = newPrice;
}

// BAD FIX: Added modifier but wrong logic
function setPrice(uint256 newPrice) external onlyOwner {
    require(newPrice > 0);  // NEW BUG: Can't set price to 0 for deprecation
    price = newPrice;
}

// ORIGINAL: Integer overflow
function multiply(uint256 a, uint256 b) public pure returns (uint256) {
    return a * b;  // Overflow in Solidity <0.8
}

// BAD FIX: Wrapped but created DoS
function multiply(uint256 a, uint256 b) public pure returns (uint256) {
    require(a == 0 || b <= type(uint256).max / a, "Overflow");
    return a * b;
}
// NEW BUG: If a=0, division by zero in check (actually safe but confusing)
// Real issue: Now legitimate large multiplications revert
```

### 1.3 Fix Bypassed by Edge Case

```solidity
// ORIGINAL: Price manipulation via flash loan
function getPrice() public view returns (uint256) {
    return reserve0 / reserve1;  // Manipulable
}

// BAD FIX: Added TWAP but wrong window
function getPrice() public view returns (uint256) {
    return twapOracle.consult(token, 1);  // 1 second window - still manipulable!
}

// CORRECT FIX: Appropriate window
function getPrice() public view returns (uint256) {
    return twapOracle.consult(token, 1800);  // 30 minute TWAP
}
```

---

## 2. Fix Verification Checklist

### 2.1 Functional Verification

```markdown
□ Original vulnerability is no longer exploitable
□ Original PoC now reverts/fails
□ All code paths through the fix are tested
□ Edge cases are handled:
  □ Zero values
  □ Max values (type(uint256).max)
  □ Empty arrays/strings
  □ Self-referential calls (user == contract)
  □ Reentrancy attempts still fail
```

### 2.2 Regression Verification

```markdown
□ Existing functionality unchanged
□ All previous tests still pass
□ Gas costs acceptable (no DoS vector introduced)
□ Return values match expected interface
□ Events still emitted correctly
□ External integrations unaffected
```

### 2.3 Security Verification

```markdown
□ No new attack vectors introduced
□ Fix cannot be bypassed by:
  □ Different caller (contract vs EOA)
  □ Different order of operations
  □ Reentrancy from new angle
  □ Front-running the fix
  □ Sandwich attacking
□ Access control correct on new code
□ Integer safety maintained
□ External calls properly handled
```

---

## 3. Testing Patterns for Fixes

### 3.1 Original PoC Must Fail

```solidity
// Test that original exploit no longer works
function test_OriginalExploit_ShouldFail() public {
    // Setup same as original PoC
    vm.startPrank(attacker);
    
    // Original attack steps
    vm.expectRevert();  // NOW MUST REVERT
    vulnerableContract.exploit();
}
```

### 3.2 Mutation Testing

```solidity
// Test fix resilience by mutating the fix
function test_FixMutation_StillSecure() public {
    // If fix uses >= , test with >
    // If fix uses block.timestamp, test manipulation
    // If fix checks length, test with length-1
}
```

### 3.3 Fuzz Testing the Fix

```solidity
function testFuzz_FixHolds(uint256 amount, address user) public {
    vm.assume(user != address(0));
    vm.assume(amount < type(uint128).max);
    
    // Fuzz the fix with random inputs
    vm.prank(user);
    try contract.fixedFunction(amount) {
        // If succeeds, verify state is correct
        assertInvariant();
    } catch {
        // If fails, verify it's expected failure
    }
}
```

### 3.4 Invariant Testing Post-Fix

```solidity
function invariant_BalancesSolvent() public {
    // After fix, this should ALWAYS hold
    assertGe(
        address(vault).balance,
        vault.totalDeposits(),
        "Insolvency detected"
    );
}

function invariant_NoReentrancy() public {
    // Verify reentrancy lock works
    assertFalse(contract.locked() && contract.inExternalCall());
}
```

---

## 4. Common Fix Patterns & Verification

### 4.1 Reentrancy Fix Verification

```solidity
// FIX: ReentrancyGuard added
contract Fixed is ReentrancyGuard {
    function withdraw() external nonReentrant {
        // ...
    }
}

// VERIFICATION: Attack contract
contract ReentrancyTest {
    function test_ReentrancyBlocked() public {
        AttackContract attacker = new AttackContract(address(fixed));
        
        // Fund attacker
        deal(address(attacker), 10 ether);
        attacker.deposit{value: 10 ether}();
        
        // Attack should fail
        vm.expectRevert("ReentrancyGuard: reentrant call");
        attacker.attack();
    }
}

contract AttackContract {
    Fixed target;
    uint256 attackCount;
    
    receive() external payable {
        if (attackCount < 5) {
            attackCount++;
            target.withdraw();  // Reentrant call
        }
    }
    
    function attack() external {
        target.withdraw();
    }
}
```

### 4.2 Access Control Fix Verification

```solidity
// FIX: Added onlyOwner
function sensitiveAction() external onlyOwner {
    // ...
}

// VERIFICATION: Multiple actors
function test_AccessControl() public {
    // Owner can call
    vm.prank(owner);
    contract.sensitiveAction();  // Should succeed
    
    // Random user cannot
    vm.prank(randomUser);
    vm.expectRevert("Ownable: caller is not the owner");
    contract.sensitiveAction();
    
    // Previous owner cannot after transfer
    vm.prank(owner);
    contract.transferOwnership(newOwner);
    
    vm.prank(owner);  // Old owner
    vm.expectRevert();
    contract.sensitiveAction();
}
```

### 4.3 Oracle Fix Verification

```solidity
// FIX: Added staleness check
function getPrice() public view returns (uint256) {
    (, int256 price, , uint256 updatedAt, ) = feed.latestRoundData();
    require(price > 0, "Invalid price");
    require(block.timestamp - updatedAt < HEARTBEAT, "Stale price");
    return uint256(price);
}

// VERIFICATION: Mock stale oracle
function test_StaleOracleRejected() public {
    // Set oracle to return stale data
    mockOracle.setUpdatedAt(block.timestamp - HEARTBEAT - 1);
    
    vm.expectRevert("Stale price");
    contract.getPrice();
}

function test_NegativePriceRejected() public {
    mockOracle.setPrice(-1);
    
    vm.expectRevert("Invalid price");
    contract.getPrice();
}

function test_ZeroPriceRejected() public {
    mockOracle.setPrice(0);
    
    vm.expectRevert("Invalid price");
    contract.getPrice();
}
```

### 4.4 Integer Overflow Fix Verification

```solidity
// FIX: Using SafeMath or Solidity 0.8+
function add(uint256 a, uint256 b) public pure returns (uint256) {
    return a + b;  // 0.8+ auto-reverts on overflow
}

// VERIFICATION: Boundary testing
function test_OverflowReverts() public {
    uint256 max = type(uint256).max;
    
    vm.expectRevert();  // Arithmetic overflow
    contract.add(max, 1);
    
    vm.expectRevert();
    contract.add(max / 2 + 1, max / 2 + 1);
}

function test_MaxValueWorks() public {
    uint256 max = type(uint256).max;
    
    // Max + 0 should work
    assertEq(contract.add(max, 0), max);
    
    // 0 + Max should work
    assertEq(contract.add(0, max), max);
}
```

---

## 5. Fix Re-Introduction Prevention

### 5.1 Documentation Requirements

```markdown
## Fix Documentation Template

### Original Vulnerability
- **ID**: VUL-001
- **Severity**: High
- **Root Cause**: Missing reentrancy protection in withdraw()
- **Attack Vector**: Recursive call via fallback

### Fix Applied
- **Commit**: abc123
- **Change**: Added ReentrancyGuard to withdraw()
- **Files Modified**: src/Vault.sol

### Verification
- **PoC Test**: test/ReentrancyTest.t.sol
- **Regression Tests**: All pass
- **Invariant Tests**: Added invariant_NoDoubleSpend

### Re-Introduction Risk
- **Risk Level**: Medium
- **Scenarios**: 
  - New withdraw function without guard
  - Refactoring that removes guard
  - New external call path
- **Prevention**: 
  - CI check for nonReentrant on all external calls with transfers
  - Slither rule: reentrancy-eth
```

### 5.2 CI/CD Checks

```yaml
# .github/workflows/security.yml
name: Security Checks

on: [push, pull_request]

jobs:
  check-fixes:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Original PoC Tests
        run: |
          forge test --match-contract "OriginalExploit" --fail-fast
          
      - name: Run Fix Verification Tests
        run: |
          forge test --match-contract "FixVerification" --fail-fast
          
      - name: Run Invariant Tests
        run: |
          forge test --match-contract "Invariant" --runs 10000
          
      - name: Slither Analysis
        run: |
          slither . --detect reentrancy-eth,unprotected-upgrade
          
      - name: Check for Removed Guards
        run: |
          # Ensure ReentrancyGuard still present
          grep -r "nonReentrant" src/ || exit 1
```

### 5.3 Code Review Checklist for Fixes

```markdown
## Fix Review Checklist

### Understanding
□ Reviewer understands original vulnerability
□ Reviewer has read original PoC
□ Reviewer understands fix rationale

### Correctness
□ Fix addresses root cause, not symptom
□ Fix covers all affected code paths
□ Fix handles edge cases
□ No new vulnerabilities introduced

### Testing
□ Original PoC test exists and passes (exploit fails)
□ New positive tests for fixed behavior
□ New negative tests for attack scenarios
□ Fuzz tests with wide input range
□ Invariant tests protect critical properties

### Integration
□ Fix doesn't break existing functionality
□ Gas impact acceptable
□ Upgrade path safe (if applicable)
□ Events/logs updated if needed
```

---

## 6. Real-World Fix Failures

### 6.1 Compound COMP Distribution Fix

```solidity
// Original Bug: Wrong index caused over-distribution
// Fix Attempt 1: Pause distribution (emergency)
// Fix Attempt 2: Update index calculation
// Issue: Fix created new edge case where users got 0 rewards
```

### 6.2 OpenZeppelin TimelockController

```solidity
// Original: Missing access control on certain paths
// Fix: Added role checks
// Issue: Fix was incomplete, edge case still exploitable
// Re-fix: Additional validation added
```

### 6.3 Wormhole Upgrade Fix

```solidity
// Original: Signature verification bypass
// Fix: Added proper verification
// Issue: Fix wasn't deployed to all chains consistently
// Result: $320M exploit on unfixed chain
```

---

## 7. Automated Fix Verification Tools

### 7.1 Slither Checks

```bash
# Verify specific fix patterns
slither . --detect reentrancy-eth  # Reentrancy still present?
slither . --detect unchecked-transfer  # Transfer checks added?
slither . --detect arbitrary-send  # Access control present?
```

### 7.2 Foundry Invariants

```solidity
// Define critical invariants that fix must preserve
function invariant_TotalSupplyMatchesBalances() public {
    uint256 sum = 0;
    for (uint i = 0; i < holders.length; i++) {
        sum += token.balanceOf(holders[i]);
    }
    assertEq(token.totalSupply(), sum);
}
```

### 7.3 Echidna Properties

```solidity
// Echidna property that should always hold post-fix
function echidna_no_drain() public view returns (bool) {
    return address(this).balance >= minReserve;
}
```

---

## Summary

| Fix Stage | Key Actions |
|-----------|-------------|
| **Pre-Fix** | Understand root cause, not just symptoms |
| **During Fix** | Minimal change, maximum coverage |
| **Post-Fix** | PoC fails, fuzz passes, invariants hold |
| **Long-Term** | CI checks, documentation, review process |

**Golden Rule**: A fix is not complete until:
1. Original PoC fails
2. All edge cases tested
3. No new vulnerabilities introduced
4. Invariants protect the fix forever
