# Audit Report Templates

## Overview

Standardized templates for consistent, professional security audit deliverables. These templates ensure comprehensive coverage and clear communication with development teams.

---

## 1. Finding Report Template

### 1.1 Standard Finding Format

```markdown
## [SEVERITY] Title - Brief Description

### Summary
One paragraph explaining the vulnerability in plain English.

### Vulnerability Details

**Location**: `src/Contract.sol#L123-L145`

**Root Cause**: Explain WHY the vulnerability exists.

**Vulnerable Code**:
```solidity
// Paste exact vulnerable code
function vulnerable() external {
    // Highlight the issue with comments
}
```

### Impact

**Severity**: [Critical/High/Medium/Low/Informational]

**Likelihood**: [High/Medium/Low] - How likely is exploitation?

**Impact**: [High/Medium/Low] - What's the damage if exploited?

Describe specific impacts:
- Financial loss (quantify if possible)
- Protocol insolvency
- User fund theft
- DoS/griefing
- Data corruption

### Proof of Concept

```solidity
// test/PoC.t.sol
function test_ExploitVulnerability() public {
    // Step-by-step reproduction
    
    // 1. Setup
    // 2. Execute attack
    // 3. Verify impact
    
    assertEq(attackerBalance, stolenFunds);
}
```

**Steps to Reproduce**:
1. Deploy contracts with provided config
2. Call function X with parameter Y
3. Observe state Z is corrupted

### Recommended Mitigation

```solidity
// Fixed code
function fixed() external {
    // Add the fix
    require(condition, "Error message");
}
```

**Alternative Mitigations**:
1. Option A: [description]
2. Option B: [description]

### References
- Similar finding: [Protocol X Audit](link)
- Related pattern: [attack-pattern.md](link)
```

---

## 2. Severity Classification Matrix

### 2.1 Impact vs Likelihood Grid

```
                    LIKELIHOOD
                    Low    Medium    High
           High  │ Medium │ High   │ Critical │
IMPACT   Medium  │ Low    │ Medium │ High     │
           Low   │ Info   │ Low    │ Medium   │
```

### 2.2 Severity Definitions

```markdown
## Critical
- Direct theft of user funds
- Protocol insolvency
- Permanent freezing of funds (>$1M or >10% TVL)
- Governance takeover
- Upgrade to malicious implementation

**Likelihood**: Likely to be exploited, minimal prerequisites
**Impact**: Catastrophic financial or operational damage

## High
- Theft of unclaimed yield/rewards
- Temporary freezing of funds
- Protocol manipulation for profit
- Bypass of critical access controls
- Griefing with significant cost to users

**Likelihood**: Realistic attack scenario
**Impact**: Significant financial loss or degraded operation

## Medium
- Griefing attacks (DoS with no profit motive)
- Incorrect accounting (no direct loss)
- Partial bypass of non-critical features
- Economic attacks requiring significant capital
- Issues requiring specific conditions

**Likelihood**: Requires specific circumstances
**Impact**: Limited financial or operational damage

## Low
- Best practice violations
- Centralization risks
- Code quality issues with minimal impact
- Gas inefficiencies
- Missing events

**Likelihood**: Edge cases or unlikely scenarios
**Impact**: Minimal direct damage

## Informational
- Code style suggestions
- Documentation improvements
- Theoretical concerns
- Future-proofing recommendations
```

### 2.3 Severity Decision Tree

```
START
  │
  ├─ Can attacker steal funds?
  │   ├─ Yes, directly → CRITICAL
  │   └─ Yes, indirectly → HIGH
  │
  ├─ Can attacker freeze funds?
  │   ├─ Permanently → CRITICAL
  │   └─ Temporarily → HIGH/MEDIUM
  │
  ├─ Can attacker manipulate protocol state?
  │   ├─ For profit → HIGH
  │   └─ For griefing → MEDIUM
  │
  ├─ Does it require admin compromise?
  │   ├─ Yes → Reduce by 1 level (max MEDIUM)
  │   └─ No → Keep severity
  │
  ├─ Does it require specific market conditions?
  │   ├─ Yes → Reduce by 1 level
  │   └─ No → Keep severity
  │
  └─ Is it a best practice violation?
      └─ Yes, no direct impact → LOW/INFO
```

---

## 3. Proof of Concept Templates

### 3.1 Foundry PoC Template

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/VulnerableContract.sol";

contract PoCTest is Test {
    VulnerableContract target;
    
    address attacker = makeAddr("attacker");
    address victim = makeAddr("victim");
    address admin = makeAddr("admin");
    
    uint256 constant INITIAL_BALANCE = 100 ether;
    
    function setUp() public {
        // Deploy contracts
        vm.prank(admin);
        target = new VulnerableContract();
        
        // Fund accounts
        deal(address(target), INITIAL_BALANCE);
        deal(attacker, 1 ether);
        deal(victim, 10 ether);
        
        // Setup initial state
        vm.prank(victim);
        target.deposit{value: 10 ether}();
    }
    
    function test_PoC_VulnerabilityName() public {
        // Log initial state
        console.log("=== Initial State ===");
        console.log("Attacker balance:", attacker.balance);
        console.log("Contract balance:", address(target).balance);
        
        // Execute attack
        vm.startPrank(attacker);
        
        // Step 1: [Description]
        target.step1();
        
        // Step 2: [Description]
        target.step2();
        
        // Step 3: [Description]
        target.step3();
        
        vm.stopPrank();
        
        // Log final state
        console.log("=== Final State ===");
        console.log("Attacker balance:", attacker.balance);
        console.log("Contract balance:", address(target).balance);
        
        // Assertions proving the exploit
        assertGt(attacker.balance, 1 ether, "Attacker should have profited");
        assertLt(address(target).balance, INITIAL_BALANCE, "Contract drained");
    }
}
```

### 3.2 Flash Loan PoC Template

```solidity
contract FlashLoanPoC is Test {
    function test_FlashLoanAttack() public {
        // 1. Take flash loan
        uint256 loanAmount = 1_000_000e18;
        
        vm.startPrank(attacker);
        
        flashLender.flashLoan(
            address(this),
            token,
            loanAmount,
            abi.encode(AttackType.PRICE_MANIPULATION)
        );
        
        vm.stopPrank();
    }
    
    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32) {
        // 2. Manipulate price/state
        vulnerableProtocol.deposit(amount);
        
        // 3. Exploit manipulated state
        vulnerableProtocol.exploit();
        
        // 4. Restore state
        vulnerableProtocol.withdraw(amount);
        
        // 5. Repay flash loan
        IERC20(token).approve(msg.sender, amount + fee);
        
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}
```

### 3.3 Reentrancy PoC Template

```solidity
contract ReentrancyAttacker {
    VulnerableContract target;
    uint256 attackCount;
    uint256 constant MAX_ATTACKS = 10;
    
    constructor(address _target) {
        target = VulnerableContract(_target);
    }
    
    function attack() external payable {
        target.deposit{value: msg.value}();
        target.withdraw(msg.value);
    }
    
    receive() external payable {
        if (attackCount < MAX_ATTACKS && address(target).balance >= 1 ether) {
            attackCount++;
            target.withdraw(1 ether);
        }
    }
}

contract ReentrancyPoCTest is Test {
    function test_Reentrancy() public {
        ReentrancyAttacker attacker = new ReentrancyAttacker(address(target));
        deal(address(attacker), 1 ether);
        
        uint256 targetBalanceBefore = address(target).balance;
        
        attacker.attack();
        
        assertLt(
            address(target).balance,
            targetBalanceBefore,
            "Reentrancy successful - funds drained"
        );
    }
}
```

---

## 4. Executive Summary Template

```markdown
# Security Audit Report
## [Protocol Name]

**Audit Date**: [Start Date] - [End Date]
**Auditor**: [Name/Firm]
**Commit Hash**: [abc123...]
**Scope**: [List of contracts]

---

## Executive Summary

[Protocol Name] is a [brief description - DeFi lending protocol, DEX, etc.].

We audited [X] lines of Solidity code across [Y] contracts over [Z] days.

### Key Statistics

| Metric | Value |
|--------|-------|
| Lines of Code | X |
| Contracts | Y |
| External Integrations | Z |
| Audit Duration | N days |

### Findings Summary

| Severity | Count | Fixed | Acknowledged | Open |
|----------|-------|-------|--------------|------|
| Critical | 0 | 0 | 0 | 0 |
| High | 2 | 2 | 0 | 0 |
| Medium | 3 | 2 | 1 | 0 |
| Low | 5 | 3 | 2 | 0 |
| Informational | 4 | 2 | 2 | 0 |
| **Total** | **14** | **9** | **5** | **0** |

### Overall Risk Assessment

**Risk Level**: [Low/Medium/High/Critical]

**Key Concerns**:
1. [Concern 1]
2. [Concern 2]
3. [Concern 3]

**Positive Observations**:
1. [Positive 1]
2. [Positive 2]

### Recommendations

1. **Immediate**: Fix all Critical and High findings before deployment
2. **Before Mainnet**: Address Medium findings
3. **Post-Launch**: Consider Low and Informational improvements

---

## Audit Scope

### Contracts in Scope

| Contract | SLOC | Complexity |
|----------|------|------------|
| LendingPool.sol | 450 | High |
| AToken.sol | 200 | Medium |
| Oracle.sol | 100 | Low |

### Out of Scope
- External dependencies (OpenZeppelin, Chainlink)
- Frontend/off-chain components
- Economic/tokenomics review

### Methodology
1. Manual code review
2. Automated analysis (Slither, Mythril)
3. Invariant testing (Foundry)
4. Economic attack modeling

---

## Findings

[Detailed findings follow...]
```

---

## 5. Threat Model Template

```markdown
# Threat Model: [Protocol Name]

## 1. System Overview

### Architecture Diagram
```
[User] → [Frontend] → [Contract A] ↔ [Contract B]
                            ↓
                      [Oracle] → [Price Feed]
```

### Components
| Component | Type | Trust Level |
|-----------|------|-------------|
| LendingPool | Core | Trustless |
| Admin | EOA | Semi-trusted |
| Oracle | External | External trust |

## 2. Actors & Capabilities

### Depositors
- **Goal**: Earn yield on deposits
- **Capabilities**: deposit(), withdraw(), claimRewards()
- **Trust**: Untrusted

### Borrowers
- **Goal**: Leverage positions
- **Capabilities**: borrow(), repay(), addCollateral()
- **Trust**: Untrusted

### Liquidators
- **Goal**: Profit from liquidations
- **Capabilities**: liquidate()
- **Trust**: Untrusted, profit-motivated

### Admin
- **Goal**: Protocol maintenance
- **Capabilities**: setParameters(), pause(), upgrade()
- **Trust**: Semi-trusted (can rug)

## 3. Trust Boundaries

### On-Chain
- User ↔ Protocol (no trust)
- Protocol ↔ Oracle (external trust)
- Protocol ↔ Other DeFi (no trust)

### Off-Chain
- Frontend ↔ RPC (centralization risk)
- Admin ↔ Multisig (operational trust)

## 4. Asset Inventory

| Asset | Location | Value | Protection |
|-------|----------|-------|------------|
| User deposits | LendingPool | ~$XXM | Withdrawal logic |
| Collateral | CollateralManager | ~$XXM | Liquidation logic |
| Protocol fees | Treasury | ~$XXM | Access control |

## 5. Attack Surfaces

### External Calls
- Token transfers (reentrancy)
- Oracle queries (manipulation)
- Cross-contract calls (trust)

### State Manipulation
- Balance updates
- Interest accrual
- Liquidation thresholds

### Access Control
- Admin functions
- Pause mechanisms
- Upgrade paths

## 6. Known Risks (Accepted)

| Risk | Mitigation | Acceptance |
|------|------------|------------|
| Oracle failure | Circuit breaker | Accepted |
| Admin key compromise | Timelock | Accepted |
| Flash loan attacks | TWAP oracle | Mitigated |
```

---

## 6. Fix Review Template

```markdown
# Fix Review Report

## Finding: [FINDING-ID] [Title]

### Original Finding
[Link to original finding]

### Fix Implementation

**Commit**: [hash]
**Files Changed**: 
- src/Contract.sol

**Code Diff**:
```diff
- function vulnerable() external {
-     // Old code
- }
+ function fixed() external {
+     // New code with fix
+ }
```

### Verification

| Check | Status | Notes |
|-------|--------|-------|
| Original PoC fails | ✅ | Reverts with "Access denied" |
| Fix addresses root cause | ✅ | Added proper validation |
| No new issues introduced | ✅ | Reviewed diff |
| Tests added | ✅ | test_FixValidation |
| Edge cases handled | ✅ | Zero, max, boundary |

### Conclusion

**Status**: ✅ FIXED / ⚠️ PARTIALLY FIXED / ❌ NOT FIXED

**Notes**: [Additional observations]
```

---

## 7. Quick Reference Cards

### 7.1 Severity Quick Reference

```
CRITICAL = Funds at immediate risk, no prerequisites
HIGH = Funds at risk OR significant protocol damage
MEDIUM = Conditional exploit OR limited damage
LOW = Best practice, unlikely scenario
INFO = Suggestion, no security impact
```

### 7.2 Finding Checklist

```markdown
□ Clear title with severity
□ Root cause explained
□ Vulnerable code identified
□ Impact quantified
□ Working PoC provided
□ Mitigation recommended
□ References included
```

### 7.3 Report Checklist

```markdown
□ Executive summary complete
□ All findings documented
□ Severity justified
□ PoCs reproducible
□ Mitigations actionable
□ Scope clearly defined
□ Limitations stated
```

---

## 8. Sample Finding Examples

### Critical Finding Example

```markdown
## [CRITICAL] Arbitrary Token Approval Allows Complete Fund Drain

### Summary
The `approveSpender` function lacks access control, allowing any user to approve arbitrary addresses to spend protocol funds.

### Vulnerability Details
**Location**: `src/Treasury.sol#L45`

```solidity
function approveSpender(address token, address spender, uint256 amount) external {
    // Missing: onlyOwner or access control
    IERC20(token).approve(spender, amount);
}
```

### Impact
- **Severity**: Critical
- **Likelihood**: High (trivial to exploit)
- **Impact**: High (complete fund loss)

An attacker can:
1. Call `approveSpender(USDC, attacker, type(uint256).max)`
2. Call `USDC.transferFrom(treasury, attacker, balance)`
3. Drain all protocol funds

### Proof of Concept
```solidity
function test_DrainTreasury() public {
    vm.prank(attacker);
    treasury.approveSpender(USDC, attacker, type(uint256).max);
    
    USDC.transferFrom(address(treasury), attacker, USDC.balanceOf(address(treasury)));
    
    assertEq(USDC.balanceOf(address(treasury)), 0);
}
```

### Recommended Mitigation
```solidity
function approveSpender(address token, address spender, uint256 amount) external onlyOwner {
    IERC20(token).approve(spender, amount);
}
```
```

---

## Summary

| Template | Use Case |
|----------|----------|
| **Finding Report** | Individual vulnerability documentation |
| **Severity Matrix** | Consistent severity classification |
| **PoC Template** | Reproducible exploit demonstration |
| **Executive Summary** | High-level audit overview |
| **Threat Model** | System security analysis |
| **Fix Review** | Remediation verification |
