# Full Audit Report Template

Complete template for a professional security audit report.

---

```markdown
# Security Audit Report

## [Protocol Name]

### Prepared by: [Auditor Name/Firm]
### Date: [Report Date]
### Version: 1.0

---

# Table of Contents

1. [Executive Summary](#executive-summary)
2. [Audit Overview](#audit-overview)
3. [Scope](#scope)
4. [Methodology](#methodology)
5. [Findings Summary](#findings-summary)
6. [Detailed Findings](#detailed-findings)
7. [Recommendations](#recommendations)
8. [Appendix A: Code Quality](#appendix-a-code-quality)
9. [Appendix B: Test Coverage](#appendix-b-test-coverage)
10. [Appendix C: Gas Optimizations](#appendix-c-gas-optimizations)
11. [Disclaimer](#disclaimer)

---

# Executive Summary

## Overview

[Protocol Name] is a [brief description of what the protocol does]. The protocol 
enables users to [main functionality]. This audit was conducted to identify 
security vulnerabilities and provide recommendations for improvement.

## Key Statistics

| Metric | Value |
|--------|-------|
| Audit Duration | [X] days |
| Lines of Code | [X] |
| Contracts Reviewed | [X] |
| Total Findings | [X] |

## Findings Overview

| Severity | Count | Fixed | Acknowledged | Open |
|----------|-------|-------|--------------|------|
| 🔴 Critical | X | X | X | X |
| 🟠 High | X | X | X | X |
| 🟡 Medium | X | X | X | X |
| 🟢 Low | X | X | X | X |
| ℹ️ Informational | X | X | X | X |

## Overall Assessment

[Assessment paragraph - examples below]

**Option A (Critical issues found):**
> The audit identified critical vulnerabilities that must be addressed before 
> deployment. The most severe finding ([C-01]) allows [describe impact]. We 
> recommend postponing deployment until all critical and high findings are resolved.

**Option B (Issues found but manageable):**
> The codebase demonstrates solid security practices with appropriate use of 
> access controls and input validation. The identified issues are addressable 
> and the team has been responsive in implementing fixes. After remediation, 
> the protocol should be suitable for mainnet deployment.

**Option C (Clean audit):**
> The codebase demonstrates excellent security practices. No critical or high 
> severity issues were found. The protocol appears ready for mainnet deployment, 
> though we recommend addressing the medium and low findings for defense in depth.

## Key Recommendations

1. **[Highest Priority]** - [Brief recommendation]
2. **[Second Priority]** - [Brief recommendation]
3. **[Third Priority]** - [Brief recommendation]

---

# Audit Overview

## Engagement Details

| Item | Details |
|------|---------|
| Client | [Client Name] |
| Auditor | [Auditor Name/Team] |
| Start Date | [Date] |
| End Date | [Date] |
| Commit Hash | [Hash] |
| Report Version | 1.0 |

## Team

| Role | Name | Contribution |
|------|------|--------------|
| Lead Auditor | [Name] | Architecture review, findings |
| Security Researcher | [Name] | Manual review, testing |
| Security Researcher | [Name] | Static analysis, verification |

## Audit Phases

| Phase | Duration | Description |
|-------|----------|-------------|
| Kickoff | Day 1 | Scope review, documentation |
| Initial Review | Days 2-5 | Architecture, threat modeling |
| Deep Dive | Days 6-12 | Manual review, testing |
| Report | Days 13-14 | Documentation, recommendations |
| Fix Review | Days 15-17 | Verify remediations |

---

# Scope

## In-Scope Contracts

| Contract | File | Lines | Description |
|----------|------|-------|-------------|
| Vault | src/Vault.sol | 450 | Main vault logic |
| Router | src/Router.sol | 320 | Swap routing |
| Staking | src/Staking.sol | 280 | Staking rewards |
| VaultFactory | src/VaultFactory.sol | 150 | Factory pattern |

**Total Lines of Code:** [X]

## Out of Scope

- External dependencies (OpenZeppelin, Solmate, etc.)
- Test files
- Deployment scripts
- Frontend/backend code
- Previously audited contracts (if unchanged)

## Commit Information

- **Repository:** [Repo URL]
- **Branch:** [Branch name]
- **Commit:** [Commit hash]
- **Date:** [Commit date]

---

# Methodology

## Review Process

### 1. Documentation Review
- Whitepaper and technical documentation
- Architecture diagrams
- Previous audit reports (if available)

### 2. Architecture Analysis
- System design review
- Trust assumptions identification
- Data flow mapping
- Privilege analysis

### 3. Threat Modeling
- Attack surface enumeration
- Threat scenario development
- Economic attack analysis
- Access control review

### 4. Manual Code Review
- Line-by-line code review
- Business logic verification
- Edge case analysis
- Cross-function interaction review

### 5. Automated Analysis
- Static analysis (Slither)
- Symbolic execution (Mythril)
- Custom pattern detection
- Fuzz testing review

### 6. Testing
- Unit test review
- Integration test analysis
- Fork testing for integrations
- Proof of concept development

## Standards Referenced

- Solidity Style Guide
- [ERC-20](https://eips.ethereum.org/EIPS/eip-20)
- [ERC-721](https://eips.ethereum.org/EIPS/eip-721)
- [ERC-4626](https://eips.ethereum.org/EIPS/eip-4626)
- [EIP-1967](https://eips.ethereum.org/EIPS/eip-1967) (Proxy Storage)

## Severity Classification

| Severity | Description |
|----------|-------------|
| 🔴 **Critical** | Direct loss of funds, protocol insolvency, governance takeover |
| 🟠 **High** | Theft of yield, significant economic damage, temporary freeze |
| 🟡 **Medium** | Conditional theft, minor economic impact, limited DoS |
| 🟢 **Low** | Best practice violations, minor issues, edge cases |
| ℹ️ **Informational** | Code quality, documentation, gas optimizations |

---

# Findings Summary

## By Severity

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| [C-01](#c-01-title) | [Title] | 🔴 Critical | Fixed |
| [H-01](#h-01-title) | [Title] | 🟠 High | Fixed |
| [H-02](#h-02-title) | [Title] | 🟠 High | Acknowledged |
| [M-01](#m-01-title) | [Title] | 🟡 Medium | Fixed |
| [M-02](#m-02-title) | [Title] | 🟡 Medium | Fixed |
| [L-01](#l-01-title) | [Title] | 🟢 Low | Fixed |
| [L-02](#l-02-title) | [Title] | 🟢 Low | Acknowledged |

## By Category

| Category | C | H | M | L | I |
|----------|---|---|---|---|---|
| Access Control | 0 | 1 | 0 | 1 | 0 |
| Reentrancy | 1 | 0 | 0 | 0 | 0 |
| Input Validation | 0 | 1 | 1 | 0 | 1 |
| Logic Errors | 0 | 0 | 1 | 1 | 2 |
| Oracle | 0 | 0 | 1 | 0 | 0 |

---

# Detailed Findings

## Critical Findings

### [C-01] [Finding Title]

**Severity:** 🔴 Critical

**Location:** `src/Vault.sol#L150-165`

**Description:**

[Detailed description of the vulnerability]

**Vulnerable Code:**

```solidity
// Code snippet showing the vulnerability
```

**Impact:**

[Explain the potential damage - funds at risk, affected users]

**Proof of Concept:**

```solidity
// PoC code demonstrating the exploit
```

**Recommendation:**

```solidity
// Fixed code
```

**Status:** ✅ Fixed

**Team Response:**
> [Team's comment on the finding]

**Auditor Verification:**
Verified fixed in commit `abc1234`.

---

## High Findings

### [H-01] [Finding Title]

**Severity:** 🟠 High

[Continue with same format...]

---

## Medium Findings

### [M-01] [Finding Title]

**Severity:** 🟡 Medium

[Continue with same format...]

---

## Low Findings

### [L-01] [Finding Title]

**Severity:** 🟢 Low

[Continue with same format...]

---

## Informational Findings

### [I-01] [Finding Title]

**Type:** ℹ️ Informational

[Continue with same format...]

---

# Recommendations

## Immediate Actions (Pre-Deployment)

1. **Address all Critical and High findings**
   - [C-01]: [Specific action]
   - [H-01]: [Specific action]
   - [H-02]: [Specific action]

2. **Review and address Medium findings**
   - Prioritize [M-01] and [M-02]

## Short-Term Improvements

1. **Increase test coverage**
   - Add edge case tests for [specific areas]
   - Implement fuzz testing for [functions]

2. **Documentation**
   - Add NatSpec comments to all public functions
   - Document trust assumptions and invariants

## Long-Term Security

1. **Monitoring**
   - Implement on-chain monitoring for unusual activity
   - Set up alerting for privilege operations

2. **Incident Response**
   - Establish emergency pause procedures
   - Document incident response plan

3. **Ongoing Security**
   - Schedule regular security reviews
   - Implement bug bounty program

---

# Appendix A: Code Quality

## Overall Assessment

| Aspect | Rating | Notes |
|--------|--------|-------|
| Documentation | ⭐⭐⭐⭐ | Good NatSpec coverage |
| Code Style | ⭐⭐⭐⭐⭐ | Consistent formatting |
| Complexity | ⭐⭐⭐ | Some complex functions |
| Error Handling | ⭐⭐⭐⭐ | Custom errors used |

## Observations

### Positive
- Consistent use of custom errors
- Good separation of concerns
- Appropriate use of libraries

### Areas for Improvement
- [Specific suggestion 1]
- [Specific suggestion 2]

---

# Appendix B: Test Coverage

## Coverage Report

| Contract | Lines | Statements | Branches | Functions |
|----------|-------|------------|----------|-----------|
| Vault.sol | 95% | 92% | 85% | 100% |
| Router.sol | 88% | 85% | 78% | 95% |
| Staking.sol | 90% | 88% | 82% | 100% |

## Recommendations

- Increase branch coverage for [specific areas]
- Add tests for [edge cases]
- Implement fuzz tests for [functions]

---

# Appendix C: Gas Optimizations

| ID | Description | Savings |
|----|-------------|---------|
| G-01 | Use calldata instead of memory | ~200 gas/call |
| G-02 | Cache storage variable | ~100 gas/call |
| G-03 | Use unchecked for safe math | ~40 gas/operation |

[Details for each optimization...]

---

# Disclaimer

This audit report is provided "as is" with no warranties regarding the 
completeness, accuracy, or suitability for any purpose. This report is not 
investment advice and should not be used as the sole basis for any decisions.

The audit was conducted based on the code state at the specified commit hash. 
Any changes made after this commit were not reviewed. The findings in this 
report are based on the information available at the time of the audit.

Smart contracts are experimental technology and carry inherent risks. Even 
audited contracts may contain undiscovered vulnerabilities. Users should 
exercise caution and perform their own due diligence.

The auditors are not responsible for any losses incurred through the use of 
the audited protocol.

---

**© [Year] [Auditor Name]. All rights reserved.**
```

