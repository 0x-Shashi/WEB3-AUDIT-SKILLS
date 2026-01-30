# Report Writing Workflow

Systematic workflow for documenting findings and generating professional audit reports.

---

## Phase 1: Finding Documentation (During Audit)

### 1.1 Real-Time Finding Capture

```markdown
## Finding Log Template

### Finding: [Short descriptive title]
**Time Found:** [Date/Time]
**Reviewer:** [Name]
**Initial Severity:** [Quick assessment]

### Quick Notes
- What: [Brief description]
- Where: [File#Line]
- Why: [Root cause]
- Impact: [Quick impact assessment]

### TODO
- [ ] Verify reproducibility
- [ ] Check for variants
- [ ] Assess full impact
- [ ] Draft recommendation
```

### 1.2 Severity Pre-Assessment

```markdown
## Quick Severity Check

Ask yourself:
1. Can an attacker steal funds?  Critical/High
2. Can an attacker cause permanent damage?  Critical/High
3. Is user action required for exploitation?  Reduce severity
4. Are special conditions needed?  Reduce severity
5. Is it a best practice violation?  Low/Informational

### Likelihood  Impact Matrix
|              | Low Impact | Med Impact | High Impact | Critical Impact |
|--------------|------------|------------|-------------|-----------------|
| High Like.   | Low        | Medium     | High        | Critical        |
| Med Like.    | Low        | Medium     | Medium      | High            |
| Low Like.    | Info       | Low        | Low         | Medium          |
```

---

## Phase 2: Finding Development

### 2.1 Expand Raw Finding

Transform quick notes into full finding:

```markdown
## [DRAFT] [X-XX] Finding Title

### Current State
- [ ] Description complete
- [ ] Root cause identified
- [ ] Impact quantified
- [ ] PoC developed
- [ ] Recommendation tested
- [ ] Severity finalized

### Working Notes
[Expand on quick notes with full analysis]
```

### 2.2 Proof of Concept Development

```solidity
// test/findings/[X-XX].t.sol
contract FindingPoCTest is Test {
    // Setup matching mainnet or expected deployment
    function setUp() public {
        // Deploy contracts
        // Fund accounts
        // Set up initial state
    }
    
    function testExploit() public {
        // Document pre-state
        uint256 victimBalanceBefore = vault.balanceOf(victim);
        
        // Execute attack
        vm.startPrank(attacker);
        // Attack steps...
        vm.stopPrank();
        
        // Verify exploit
        uint256 victimBalanceAfter = vault.balanceOf(victim);
        assertLt(victimBalanceAfter, victimBalanceBefore, "Funds stolen");
    }
}
```

### 2.3 Recommendation Verification

```solidity
// test/fixes/[X-XX]-fix.t.sol
contract FixVerificationTest is Test {
    function testFixedVersion() public {
        // Apply fix (or use fixed contract)
        
        // Attempt same exploit
        vm.startPrank(attacker);
        vm.expectRevert(); // Should fail now
        // Attack steps...
        vm.stopPrank();
    }
    
    function testNormalOperationAfterFix() public {
        // Ensure fix doesn't break functionality
    }
}
```

---

## Phase 3: Finding Finalization

### 3.1 Peer Review Checklist

```markdown
## Finding Review: [X-XX]

### Technical Accuracy
- [ ] Description is correct
- [ ] Root cause is accurate
- [ ] Impact is not overstated
- [ ] PoC works as described
- [ ] Recommendation fixes the issue

### Severity Check
- [ ] Likelihood assessment correct
- [ ] Impact assessment correct
- [ ] Final severity appropriate

### Quality Check
- [ ] Clear and concise language
- [ ] Code snippets are accurate
- [ ] No typos or grammatical errors
- [ ] Follows template format

### Reviewer Sign-off
- Reviewed by: [Name]
- Date: [Date]
- Comments: [Any feedback]
```

### 3.2 Final Finding Format

```markdown
## [C-01] Reentrancy in withdraw() Allows Complete Fund Drainage

### Severity
**Critical** 

### Location
- **File:** `src/Vault.sol`
- **Lines:** 150-165
- **Function:** `withdraw(uint256 amount)`

### Description
The `withdraw()` function sends ETH to the caller via a low-level call before 
updating the user's balance. This allows a malicious contract to recursively 
call `withdraw()` and drain all funds from the vault.

### Root Cause
The function violates the checks-effects-interactions pattern by performing 
an external call (interaction) before updating state (effect).

### Vulnerable Code
```solidity
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "Insufficient balance");
    
    (bool success, ) = msg.sender.call{value: amount}("");  // L158: External call
    require(success, "Transfer failed");                      // L159
    
    balances[msg.sender] -= amount;  // L161: State update AFTER call
}
```

### Impact
- **Funds at Risk:** 100% of vault deposits
- **Current TVL:** [Amount if known]
- **Attack Complexity:** Low (simple attacker contract)
- **Attack Cost:** Minimal (only gas)

An attacker with any deposited balance can drain the entire vault in a 
single transaction.

### Proof of Concept
```solidity
contract ReentrancyAttacker {
    Vault public vault;
    uint256 public attackAmount = 1 ether;
    
    constructor(address _vault) {
        vault = Vault(_vault);
    }
    
    function attack() external payable {
        vault.deposit{value: msg.value}();
        vault.withdraw(attackAmount);
    }
    
    receive() external payable {
        if (address(vault).balance >= attackAmount) {
            vault.withdraw(attackAmount);
        }
    }
}
```

Test output:
```
Attacker balance before: 1 ETH
Vault balance before: 100 ETH
--- Attack ---
Attacker balance after: 101 ETH
Vault balance after: 0 ETH
```

### Recommendation
1. Apply checks-effects-interactions pattern
2. Add ReentrancyGuard as defense in depth

```solidity
function withdraw(uint256 amount) external nonReentrant {
    require(balances[msg.sender] >= amount, "Insufficient balance");
    
    balances[msg.sender] -= amount;  // State update FIRST
    
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
}
```

### References
- [SWC-107: Reentrancy](https://swcregistry.io/docs/SWC-107)
- [Consensys: Reentrancy](https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/)

### Status
**Fixed** 

### Team Response
> We have implemented both recommendations: checks-effects-interactions 
> pattern and added OpenZeppelin's ReentrancyGuard to all withdrawal functions.

### Fix Verification
Verified in commit `def5678`. The fix correctly:
- [x] Updates state before external call
- [x] Adds nonReentrant modifier
- [x] Applies pattern consistently across all withdrawal paths
```

---

## Phase 4: Report Compilation

### 4.1 Report Assembly Order

1. **Collect all finalized findings**
2. **Sort by severity** (Critical  High  Medium  Low  Info)
3. **Number findings** (C-01, C-02, H-01, etc.)
4. **Generate summary tables**
5. **Write executive summary** (last, after all findings known)
6. **Add scope and methodology**
7. **Add appendices**

### 4.2 Executive Summary Writing

```markdown
## Writing the Executive Summary

### Do LAST
The executive summary should be written after all findings are documented 
so it accurately reflects the audit results.

### Key Elements
1. **One-line protocol description**
2. **Audit dates and scope summary**
3. **Findings count by severity**
4. **Overall assessment (1-2 sentences)**
5. **Top 3 recommendations**

### Tone Guidelines
- Professional and objective
- Clear for non-technical readers
- Balanced (acknowledge positives)
- Actionable recommendations

### Assessment Templates

**Clean Audit:**
> The codebase demonstrates strong security practices. No critical or 
> high-severity issues were identified. The protocol appears ready for 
> mainnet deployment following resolution of the medium and low findings.

**Minor Issues:**
> The codebase shows solid security fundamentals with appropriate access 
> controls and input validation. The [X] medium-severity issues identified 
> should be addressed before deployment, but pose limited risk.

**Significant Issues:**
> The audit identified [X] high-severity issues that require immediate 
> attention. We recommend postponing deployment until these findings are 
> resolved and verified.

**Critical Issues:**
> The audit identified critical vulnerabilities that could result in 
> [complete loss of funds / protocol takeover / etc.]. Deployment should 
> be postponed until all critical issues are resolved and the fixes are 
> verified through a follow-up review.
```

---

## Phase 5: Review & Delivery

### 5.1 Report Quality Checklist

```markdown
## Final Report QA

### Content
- [ ] All findings properly formatted
- [ ] Severity ratings consistent
- [ ] All code snippets verified
- [ ] All links working
- [ ] Executive summary accurate

### Consistency
- [ ] Finding numbering correct
- [ ] Summary tables match findings
- [ ] Status labels consistent
- [ ] Terminology consistent throughout

### Accuracy
- [ ] File paths correct
- [ ] Line numbers accurate
- [ ] Commit hashes correct
- [ ] Dates accurate

### Quality
- [ ] No spelling errors
- [ ] No grammatical issues
- [ ] Professional tone throughout
- [ ] Clear and readable

### Completeness
- [ ] All sections filled
- [ ] Scope documented
- [ ] Methodology included
- [ ] Disclaimer present
```

### 5.2 Client Delivery

```markdown
## Delivery Package

### Contents
1. **report-v1.0.pdf** - Main audit report
2. **findings.md** - Markdown source of findings
3. **pocs/** - Proof of concept test files
4. **slither-results.json** - Static analysis output

### Delivery Email Template

Subject: Security Audit Report - [Protocol Name]

Dear [Client Name],

Please find attached the security audit report for [Protocol Name].

**Summary:**
- [X] Critical, [Y] High, [Z] Medium severity findings
- [Overall assessment one-liner]

**Next Steps:**
1. Review findings and provide initial feedback
2. Implement fixes for Critical/High issues
3. Schedule fix review call for [proposed date]

Please let us know if you have any questions.

Best regards,
[Auditor Name]
```

---

## Phase 6: Fix Review

### 6.1 Fix Verification Process

```markdown
## Fix Review Template

### Finding: [X-XX] [Title]

### Original Issue
[Brief summary]

### Fix Commit
`abc1234` - [commit message]

### Changes Made
```diff
- old vulnerable code
+ new fixed code
```

### Verification
- [ ] Fix addresses root cause
- [ ] No new issues introduced
- [ ] Related variants checked
- [ ] Tests added for fix
- [ ] Normal functionality preserved

### Status Update
**[Fixed/Partially Fixed/Not Fixed]**

### Notes
[Any comments on the fix quality or remaining concerns]
```

### 6.2 Updated Report

```markdown
## Report Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | [Date] | Initial report |
| 1.1 | [Date] | Fix verification for C-01, H-01, H-02 |
| 1.2 | [Date] | Final status updates |
```

