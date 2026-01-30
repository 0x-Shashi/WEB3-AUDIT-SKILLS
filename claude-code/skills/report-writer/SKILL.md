---
name: Audit Report Writer
description: Professional security audit report generation with templates and methodologies
version: 1.0.0
author: Web3 Security Plugin
tags: [report, documentation, findings, audit, professional]
---

# Audit Report Writer Skill

Generate professional-grade security audit reports with standardized templates, severity classifications, and comprehensive documentation.

## Capabilities

- **Finding Documentation**: Standardized format for security findings
- **Severity Classification**: CVSS-based severity ratings
- **Report Structure**: Professional audit report templates
- **Executive Summary**: Clear communication for non-technical stakeholders

---

## Report Structure

### Standard Audit Report Sections

```markdown
1. Executive Summary
2. Scope & Methodology
3. Findings Summary
4. Detailed Findings
5. Recommendations
6. Appendices
   - Code Quality
   - Test Coverage
   - Gas Optimization
   - Informational Items
```

---

## Section 1: Executive Summary

### Template

```markdown
# Executive Summary

## Overview
[Protocol Name] engaged [Auditor] to conduct a security assessment of their 
[description] smart contracts. The audit was performed between [start date] 
and [end date].

## Scope
The review covered [X] contracts totaling approximately [Y] lines of code, 
focusing on [main focus areas].

## Key Findings
The assessment identified:
- **[X] Critical** findings requiring immediate attention
- **[Y] High** severity issues affecting security
- **[Z] Medium** severity concerns
- **[W] Low** severity and informational items

## Overall Assessment
[Overall security posture assessment. Example:]
The codebase demonstrates [good/moderate/concerning] security practices. 
[Critical issues require immediate remediation before deployment / 
The protocol is ready for mainnet deployment after addressing the identified issues /
No critical issues were found; the protocol follows security best practices.]

## Key Recommendations
1. [Most critical recommendation]
2. [Second priority]
3. [Third priority]
```

---

## Section 2: Scope & Methodology

### Template

```markdown
# Scope & Methodology

## Audit Timeline
| Phase | Dates | Duration |
|-------|-------|----------|
| Initial Review | [date] - [date] | X days |
| Deep Dive | [date] - [date] | X days |
| Fix Review | [date] - [date] | X days |
| Report | [date] | X days |

## Scope

### In-Scope Contracts
| Contract | Lines | Commit |
|----------|-------|--------|
| Vault.sol | 450 | abc1234 |
| Router.sol | 320 | abc1234 |
| Staking.sol | 280 | abc1234 |

### Out of Scope
- External dependencies (OpenZeppelin, etc.)
- Frontend/backend code
- Deployment scripts

## Methodology

### Review Process
1. **Architecture Review**: Understanding system design and trust assumptions
2. **Manual Code Review**: Line-by-line analysis of all in-scope contracts
3. **Automated Analysis**: Static analysis tools (Slither, custom detectors)
4. **Threat Modeling**: Identifying attack vectors and potential exploits
5. **Testing Review**: Assessment of test coverage and quality

### Standards Referenced
- Solidity Style Guide
- ERC Standards (ERC20, ERC721, ERC4626, etc.)
- Security best practices

## Limitations
This audit is a point-in-time assessment and cannot guarantee the absence 
of all vulnerabilities. The security of the system also depends on off-chain 
components, operational security, and future code changes.
```

---

## Section 3: Findings Summary

### Template

```markdown
# Findings Summary

## By Severity

| Severity | Count | Status |
|----------|-------|--------|
| Critical | 1 | Fixed |
| High | 2 | 1 Fixed, 1 Acknowledged |
| Medium | 4 | 3 Fixed, 1 Won't Fix |
| Low | 6 | Fixed |
| Informational | 8 | Acknowledged |

## By Category

| Category | Critical | High | Medium | Low | Info |
|----------|----------|------|--------|-----|------|
| Access Control | 0 | 1 | 1 | 0 | 1 |
| Reentrancy | 1 | 0 | 0 | 0 | 0 |
| Input Validation | 0 | 1 | 2 | 2 | 1 |
| Logic Errors | 0 | 0 | 1 | 2 | 3 |
| Gas/Optimization | 0 | 0 | 0 | 2 | 3 |

## Findings Index

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| C-01 | Reentrancy in withdraw | Critical | Fixed |
| H-01 | Missing access control | High | Fixed |
| H-02 | Oracle manipulation | High | Acknowledged |
| M-01 | Rounding error | Medium | Fixed |
```

---

## Section 4: Detailed Findings

### Finding Template

```markdown
## [C-01] Reentrancy Vulnerability in Withdraw Function

### Severity
**Critical**

### Location
- File: `src/Vault.sol`
- Lines: 150-165
- Function: `withdraw()`

### Description
The `withdraw()` function sends ETH to the user before updating state variables, 
allowing an attacker to recursively call withdraw and drain the contract.

### Vulnerable Code
```solidity
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "Insufficient balance");
    
    // ETH sent before state update - VULNERABLE
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
    
    balances[msg.sender] -= amount;  // State updated after external call
}
```

### Impact
An attacker can drain all funds from the vault by deploying a malicious 
contract that calls `withdraw()` in its receive function.

**Severity Justification:**
- Likelihood: High (easily exploitable)
- Impact: Critical (complete loss of funds)

### Proof of Concept
```solidity
contract Attacker {
    Vault vault;
    
    constructor(address _vault) {
        vault = Vault(_vault);
    }
    
    function attack() external payable {
        vault.deposit{value: msg.value}();
        vault.withdraw(msg.value);
    }
    
    receive() external payable {
        if (address(vault).balance >= 1 ether) {
            vault.withdraw(1 ether);
        }
    }
}
```

### Recommendation
Apply the checks-effects-interactions pattern by updating state before 
external calls:

```solidity
function withdraw(uint256 amount) external nonReentrant {
    require(balances[msg.sender] >= amount, "Insufficient balance");
    
    // Update state BEFORE external call
    balances[msg.sender] -= amount;
    
    // Then transfer
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
}
```

Additionally, use OpenZeppelin's `ReentrancyGuard` as defense in depth.

### Status
**Fixed** - The team implemented the recommended fix in commit `def5678`.

### Team Response
> We've applied the checks-effects-interactions pattern and added 
> ReentrancyGuard to all withdrawal functions.
```

---

## Severity Classifications

### Critical
- Direct loss of funds
- Permanent freezing of funds
- Governance takeover
- Protocol insolvency

```markdown
### Criteria
- Likelihood: High (easily exploitable)
- Impact: Critical (>$100K or protocol-wide impact)
- No user error required
```

### High
- Theft of unclaimed yield
- Manipulation of protocol parameters
- Temporary freezing of funds
- Significant economic damage

```markdown
### Criteria
- Likelihood: High with Impact: High
- OR Likelihood: Medium with Impact: Critical
- Limited user action may be required
```

### Medium
- Theft requiring unlikely conditions
- Minor economic impact
- DoS requiring specific conditions
- Unexpected behavior with limited impact

```markdown
### Criteria
- Likelihood: Medium with Impact: Medium
- OR Likelihood: Low with Impact: High
- Requires specific conditions or user error
```

### Low
- Issues with minimal impact
- Gas optimizations with security implications
- Best practice violations
- Minor unexpected behavior

```markdown
### Criteria
- Likelihood: Low with Impact: Low
- OR High likelihood with minimal impact
- Edge cases or theoretical issues
```

### Informational
- Code quality suggestions
- Documentation improvements
- Gas optimizations (no security impact)
- Style guide violations

---

## Category Classifications

```markdown
### Security Categories
- **Access Control**: Permission and authorization issues
- **Reentrancy**: Cross-function and cross-contract reentrancy
- **Oracle/Price Manipulation**: Price feed and oracle issues
- **Flash Loan**: Flash loan attack vectors
- **Input Validation**: Missing or insufficient validation
- **Logic Error**: Incorrect business logic
- **Math/Precision**: Overflow, underflow, rounding
- **DoS**: Denial of service vectors
- **Front-running**: MEV and ordering attacks
- **Upgrade Safety**: Proxy and upgrade issues
- **Data Validation**: Insufficient data checks
- **External Calls**: Issues with external dependencies
- **Signature/Replay**: Cryptographic issues
- **Governance**: DAO and voting issues
- **Integration**: Third-party integration issues
```

---

## Professional Writing Guidelines

### DO:
- Be specific and actionable
- Include code snippets for both vulnerable and fixed code
- Explain the attack scenario clearly
- Quantify impact when possible
- Provide concrete recommendations

### DON'T:
- Use vague language ("might be vulnerable")
- Exaggerate severity
- Include theoretical attacks without realistic paths
- Write findings without recommendations
- Use overly technical jargon without explanation

### Tone:
- Professional and objective
- Clear and concise
- Educational, not accusatory
- Constructive, not critical

---

## Quick Finding Template

```markdown
## [X-XX] Finding Title

### Severity: [Critical/High/Medium/Low/Informational]

### Location: `file.sol#L123`

### Description
[What the issue is]

### Impact
[What could happen]

### Recommendation
[How to fix it]

### Status: [Open/Fixed/Acknowledged/Won't Fix]
```

---

## Report Automation Commands

```bash
# Generate findings table
/audit-report summary

# Format finding
/audit-report format-finding [ID]

# Generate executive summary
/audit-report executive-summary

# Export to markdown
/audit-report export-md

# Export to PDF (requires pandoc)
/audit-report export-pdf
```

