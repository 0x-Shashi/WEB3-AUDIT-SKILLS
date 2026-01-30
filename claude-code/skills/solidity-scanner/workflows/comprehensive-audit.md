# Comprehensive Audit Workflow

Full security audit workflow for thorough protocol analysis.

---

## Overview

This workflow covers a complete security audit from start to finish:
- **Duration:** 1-2 weeks depending on codebase size
- **Output:** Professional audit report with findings
- **Coverage:** All vulnerability categories, business logic, economic attacks

---

## Phase 1: Preparation (Day 1)

### 1.1 Scope Definition

```markdown
## Audit Scope

**Client:** [Protocol Name]
**Version:** [Commit hash / Version]
**Date Range:** [Start] - [End]

### In Scope
| Contract | Lines | Priority |
|----------|-------|----------|
| Vault.sol | 450 | Critical |
| Strategy.sol | 300 | High |
| Token.sol | 150 | Medium |

**Total Lines:** [count]

### Out of Scope
- [ ] Test files
- [ ] Mock contracts
- [ ] OpenZeppelin imports
- [ ] [Other exclusions]

### Focus Areas
1. [Primary concern from client]
2. [Secondary concern]
3. [Any known issues to verify]
```

### 1.2 Environment Setup

```bash
# Clone and setup
git clone [repo]
cd [repo]
git checkout [commit]

# Install dependencies
npm install
# or
forge install

# Compile
forge build
# or
npx hardhat compile

# Run existing tests
forge test
# or
npx hardhat test
```

### 1.3 Documentation Review

Read and summarize:
- [ ] README and documentation
- [ ] Whitepaper (if applicable)
- [ ] Previous audit reports
- [ ] Known issues/bug bounty rules

---

## Phase 2: Reconnaissance (Days 1-2)

### 2.1 Automated Scanning

```bash
# Create output directory
mkdir -p audit-output

# Slither comprehensive scan
slither . --json audit-output/slither.json
slither . --print human-summary > audit-output/slither-summary.txt
slither . --print contract-summary > audit-output/contracts.txt
slither . --print function-summary > audit-output/functions.txt
slither . --print call-graph --call-graph-format dot > audit-output/callgraph.dot

# Semgrep
semgrep --config "p/smart-contracts" --json -o audit-output/semgrep.json .

# Mythril (if time permits)
myth analyze contracts/Main.sol --json > audit-output/mythril.json
```

### 2.2 Architecture Mapping

Document using [audit-context-building](../../audit-context-building/SKILL.md):

```markdown
## Architecture Summary

### System Type
[DEX / Lending / NFT / Vault / Bridge / Other]

### Components
[Diagram or list of contracts and relationships]

### External Integrations
| Integration | Type | Trust Level |
|-------------|------|-------------|
| Chainlink | Oracle | High |
| Uniswap | DEX | Medium |

### Actors
| Actor | Trust | Capabilities |
|-------|-------|--------------|
| Owner | High | Admin functions |
| User | None | Deposit, withdraw |

### Value Flows
[Where value enters, moves, exits]
```

### 2.3 Entry Point Enumeration

List all external/public functions:

```markdown
## Entry Points

### User Functions
| Function | Contract | Value | Risk |
|----------|----------|-------|------|
| deposit() | Vault | ETH | Critical |
| withdraw() | Vault | ETH | Critical |

### Admin Functions
| Function | Contract | Impact | Risk |
|----------|----------|--------|------|
| setFee() | Vault | Config | Medium |
| pause() | Vault | Operations | Low |

### Callback Functions
| Function | Contract | Caller | Risk |
|----------|----------|--------|------|
| onFlashLoan() | Vault | Lender | High |
```

---

## Phase 3: Deep Analysis (Days 3-7)

### 3.1 Function-by-Function Analysis

For each function in priority order:

```markdown
## Function: deposit(uint256 amount)

### Quick Info
- File: Vault.sol:45-82
- Visibility: external
- Modifiers: nonReentrant, whenNotPaused

### Analysis
[Using audit-context-building methodology]

### Checks Performed
- [ ] Reentrancy
- [ ] Access Control
- [ ] Input Validation
- [ ] Arithmetic
- [ ] External Calls
- [ ] State Changes
- [ ] Events

### Issues Found
- [Issue or "None"]
```

### 3.2 Category-by-Category Scan

Work through each vulnerability category:

#### Reentrancy Scan
```bash
# Find external calls
grep -rn "\.call\|\.transfer\|\.send" contracts/

# Find state changes
grep -rn "=\|+=\|-=" contracts/
```
- [ ] All patterns reviewed
- [ ] Issues documented

#### Access Control Scan
```bash
# Find modifiers
slither . --print modifiers

# Find role checks
grep -rn "onlyOwner\|require.*msg.sender\|onlyRole" contracts/
```
- [ ] All patterns reviewed
- [ ] Issues documented

[Continue for each category...]

### 3.3 Protocol-Specific Checks

Apply relevant protocol checklist from SKILL.md:
- [ ] DEX checklist (if applicable)
- [ ] Lending checklist (if applicable)
- [ ] NFT checklist (if applicable)
- [ ] Vault checklist (if applicable)

### 3.4 Business Logic Review

```markdown
## Business Logic Analysis

### Invariants
From documentation and code:
1. [Invariant] - Verified: ✅/❌
2. [Invariant] - Verified: ✅/❌

### Economic Model
- Fee mechanism: [analysis]
- Reward distribution: [analysis]
- Incentive alignment: [analysis]

### Edge Cases
| Edge Case | Expected | Actual | Status |
|-----------|----------|--------|--------|
| Zero deposit | Revert | [check] | ✅/❌ |
| Max deposit | Accept | [check] | ✅/❌ |
```

---

## Phase 4: Advanced Analysis (Days 7-10)

### 4.1 Cross-Function Analysis

```markdown
## Cross-Function Interactions

### Shared State
| State | Read By | Written By | Invariant |
|-------|---------|------------|-----------|
| balance | view, withdraw | deposit, withdraw | Sum consistency |

### Function Ordering Attacks
- [ ] deposit → withdraw: [safe/unsafe]
- [ ] [other orderings]

### State Inconsistencies
- [ ] During reentrancy: [analysis]
- [ ] During multi-call: [analysis]
```

### 4.2 External Integration Analysis

```markdown
## External Integration: [Name]

### Integration Points
| Our Function | Their Function | Data Exchanged |
|--------------|----------------|----------------|
| getPrice() | latestRoundData() | Price feed |

### Trust Analysis
- Assumption: [What we assume about them]
- If wrong: [Impact]
- Mitigation: [How we protect ourselves]

### Failure Modes
| Failure | Our Response | Adequate |
|---------|--------------|----------|
| Reverts | Propagate | ✅ |
| Stale data | [check] | ❌ |
```

### 4.3 Economic Attack Analysis

```markdown
## Economic Attack Vectors

### Flash Loan Attacks
- [ ] Can governance be attacked? [analysis]
- [ ] Can oracle be manipulated? [analysis]
- [ ] Can collateral be inflated? [analysis]

### MEV Attacks
- [ ] Sandwich vulnerability: [analysis]
- [ ] Front-running exposure: [analysis]
- [ ] Back-running opportunities: [analysis]

### Oracle Manipulation
- [ ] Price source: [analysis]
- [ ] Manipulation resistance: [analysis]
- [ ] Fallback mechanism: [analysis]
```

### 4.4 Fuzzing & Invariant Testing

```bash
# Run Echidna
echidna . --contract TestContract --config echidna.yaml

# Run Foundry invariant tests
forge test --match-test invariant -vvv
```

Document any findings from fuzzing.

---

## Phase 5: Finding Documentation (Days 10-12)

### 5.1 Finding Compilation

For each finding, document using template:

```markdown
## [SEV-##] Finding Title

**Severity:** Critical/High/Medium/Low/Info
**Status:** New/Confirmed/Fixed
**Category:** [Category]

### Location
- File: Contract.sol
- Lines: 45-52
- Function: functionName()

### Description
[Clear explanation]

### Vulnerable Code
```solidity
// Code
```

### Impact
[What can happen]

### Proof of Concept
```solidity
// Attack code
```

### Recommendation
```solidity
// Fixed code
```
```

### 5.2 Severity Classification

Review each finding against [severity-guide.md](../resources/severity-guide.md):

| # | Title | Initial | Final | Justification |
|---|-------|---------|-------|---------------|
| 1 | [Title] | High | High | [Reason] |
| 2 | [Title] | Medium | Low | [Changed because...] |

### 5.3 Cross-Reference Check

- [ ] Similar findings in [Cyfrin Solodit](https://solodit.xyz)
- [ ] Related findings in this audit linked
- [ ] Recommendations are consistent

---

## Phase 6: Report Writing (Days 12-14)

### 6.1 Report Structure

```markdown
# Security Audit Report

## Executive Summary
- Scope
- Timeline
- Summary of findings
- Recommendations

## Findings Summary
| ID | Title | Severity | Status |
|----|-------|----------|--------|
| H-01 | [Title] | High | Open |

## Detailed Findings
[Each finding in detail]

## Informational
[Lower severity items]

## Appendix
- Scope
- Methodology
- Tool output
```

### 6.2 Quality Checklist

Before delivery:
- [ ] All findings have clear descriptions
- [ ] All findings have recommendations
- [ ] Severity classifications are consistent
- [ ] Code snippets are accurate
- [ ] No typos or formatting issues
- [ ] Executive summary matches findings
- [ ] All scope items covered

---

## Phase 7: Delivery & Follow-up

### 7.1 Initial Delivery

- [ ] Draft report delivered
- [ ] Findings walkthrough with client
- [ ] Q&A session

### 7.2 Fix Review (if applicable)

For each fix:
```markdown
## Fix Review: [Finding ID]

**Original Finding:** [Link/ID]
**Fix Commit:** [hash]

### Review
- [ ] Fix addresses the issue
- [ ] No new issues introduced
- [ ] Test coverage added

### Status
- [ ] Fixed
- [ ] Partially Fixed
- [ ] Not Fixed
- [ ] Acknowledged (won't fix)
```

### 7.3 Final Report

- [ ] All fixes reviewed
- [ ] Status updated
- [ ] Final report delivered

---

## Audit Artifacts

By the end, you should have:

```
audit-output/
├── slither.json
├── slither-summary.txt
├── semgrep.json
├── contracts.txt
├── functions.txt
├── callgraph.dot
├── findings/
│   ├── H-01.md
│   ├── H-02.md
│   ├── M-01.md
│   └── ...
├── notes/
│   ├── day1.md
│   ├── day2.md
│   └── ...
├── report-draft.md
└── report-final.pdf
```

---

## Time Allocation Guide

For a 2-week audit:

| Phase | Days | % of Time |
|-------|------|-----------|
| Preparation | 1 | 7% |
| Reconnaissance | 1-2 | 11% |
| Deep Analysis | 4-5 | 36% |
| Advanced Analysis | 3 | 21% |
| Documentation | 2 | 14% |
| Report & Delivery | 1-2 | 11% |

Adjust based on codebase complexity and client requirements.

