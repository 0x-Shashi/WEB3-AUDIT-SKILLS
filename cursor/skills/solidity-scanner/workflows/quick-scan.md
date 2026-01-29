# Quick Scan Workflow

Rapid security assessment for time-constrained situations.

---

## Purpose

This workflow provides a fast security scan when time is limited:
- Pre-merge code review (30 minutes)
- Initial triage of new codebase (1 hour)
- Spot check before deployment (15 minutes)

---

## 15-Minute Critical Check

### Automated Tools (5 minutes)

```bash
# Run Slither with critical detectors only
slither . --detect \
  reentrancy-eth,\
  arbitrary-send-eth,\
  arbitrary-send-erc20,\
  unprotected-upgrade,\
  suicidal,\
  delegatecall-loop \
  --exclude-dependencies

# Quick Semgrep scan
semgrep --config "p/smart-contracts" . --severity ERROR
```

### Manual Critical Checks (10 minutes)

#### Check 1: Access Control (3 minutes)

```bash
# Find all external/public functions
grep -rn "external\|public" contracts/ | grep -v "view\|pure"
```

For each:
- [ ] Has appropriate modifier OR is intentionally public
- [ ] No owner/admin functions without protection

#### Check 2: External Calls (3 minutes)

```bash
# Find all external calls
grep -rn "\.call\|\.transfer\|\.send\|\.delegatecall" contracts/
```

For each:
- [ ] Return value checked
- [ ] State updated before call (CEI pattern)

#### Check 3: Value Handling (2 minutes)

```bash
# Find payable functions and ETH handling
grep -rn "payable\|msg\.value\|\.value\(" contracts/
```

For each:
- [ ] msg.value handled correctly
- [ ] No msg.value in loop issue

#### Check 4: Token Transfers (2 minutes)

```bash
# Find token interactions
grep -rn "transfer\|transferFrom\|approve" contracts/
```

For each:
- [ ] Return value handled (or SafeERC20 used)
- [ ] Approval patterns safe

---

## 30-Minute Standard Check

### Phase 1: Automated Scan (10 minutes)

```bash
# Full Slither scan
slither . --json slither-output.json
slither . --print human-summary

# Semgrep
semgrep --config "p/smart-contracts" --json -o semgrep-output.json .
```

Review output for High/Critical findings.

### Phase 2: Entry Point Review (10 minutes)

List all entry points:
```bash
grep -rn "external\|public" contracts/ | grep "function"
```

For each external function, quick check:

| Function | Access | Value | External Call | Status |
|----------|--------|-------|---------------|--------|
| deposit() | ✅ | ✅ ETH | ❌ None | OK |
| withdraw() | ⚠️ Check | ✅ | ✅ Check CEI | Check |

### Phase 3: High-Risk Patterns (10 minutes)

Check for known patterns:

- [ ] **Reentrancy:** External calls with state after
- [ ] **Access Control:** Missing modifiers
- [ ] **Oracle:** Spot price usage
- [ ] **Flash Loan:** Single-block price dependency
- [ ] **Upgrades:** Storage gaps, initializers

---

## 1-Hour Initial Triage

### Phase 1: Setup & Automated (15 minutes)

```bash
# Compile and run tools
forge build
slither . --json output/slither.json
slither . --print contract-summary > output/contracts.txt
slither . --print function-summary > output/functions.txt
```

### Phase 2: Architecture Overview (15 minutes)

Document quickly:

```markdown
## Quick Architecture

### Contracts
- Main: [name] - [purpose]
- Token: [name] - [purpose]
- [other]

### Entry Points
| Function | Contract | Risk Level |
|----------|----------|------------|
| | | |

### External Integrations
- [ ] Oracles: [which]
- [ ] DEX: [which]
- [ ] Other: [which]
```

### Phase 3: Critical Path Review (20 minutes)

Identify and review the 3 most critical functions:

1. **Highest Value Function**
   - Quick analysis (5 min)
   - Note any concerns

2. **Main User Function**
   - Quick analysis (5 min)
   - Note any concerns

3. **Admin/Privileged Function**
   - Quick analysis (5 min)
   - Note any concerns

### Phase 4: Document Findings (10 minutes)

```markdown
## Quick Triage Results

**Date:** [date]
**Time Spent:** 1 hour
**Scope:** [contracts]

### Critical Issues
- [ ] None found / [List]

### High Priority Concerns
- [ ] None found / [List]

### Areas Needing Deep Review
1. [Area and why]
2. [Area and why]

### Recommendation
- [ ] Safe for further review
- [ ] Needs immediate attention
- [ ] Recommend full audit
```

---

## Quick Scan Checklists

### Solidity 0.8+ Quick Check

```markdown
- [ ] Compiler version locked (not floating)
- [ ] No `unchecked` blocks with user input
- [ ] No assembly without review
- [ ] Uses OpenZeppelin (if applicable)
- [ ] Events for state changes
```

### DeFi Protocol Quick Check

```markdown
- [ ] Slippage protection on swaps
- [ ] Oracle manipulation protection
- [ ] Flash loan resistance
- [ ] Reentrancy guards on value functions
- [ ] Access control on admin functions
```

### NFT Quick Check

```markdown
- [ ] Mint limits enforced
- [ ] Signature verification (if whitelist)
- [ ] Metadata protection
- [ ] Royalty enforcement
```

### Upgrade Quick Check

```markdown
- [ ] Initializer protected (initializer modifier)
- [ ] Storage gaps for future variables
- [ ] No selfdestruct in implementation
- [ ] Admin controls timelocked
```

---

## Quick Scan Output Template

```markdown
# Quick Scan Report

**Target:** [Contract/Protocol Name]
**Date:** [Date]
**Duration:** [X minutes]
**Scanner:** [Your name]

## Summary

| Category | Status |
|----------|--------|
| Critical Issues | ✅ None / ❌ [count] |
| High Issues | ✅ None / ⚠️ [count] |
| Tool Alerts | [count] to review |

## Automated Tool Results

### Slither
- High: [count]
- Medium: [count]
- Low: [count]
- Info: [count]

### Semgrep
- Errors: [count]
- Warnings: [count]

## Manual Checks

| Check | Result | Notes |
|-------|--------|-------|
| Access Control | ✅/❌ | |
| Reentrancy | ✅/❌ | |
| Value Handling | ✅/❌ | |
| Token Safety | ✅/❌ | |

## Immediate Concerns

[List any issues found or "None identified in quick scan"]

## Recommendations

- [ ] Proceed with deployment
- [ ] Address issues before deployment
- [ ] Full audit required
- [ ] Do not deploy

## Limitations

This was a quick scan, not a comprehensive audit.
The following was NOT checked:
- Deep business logic
- Economic attack vectors
- Full test coverage review
- [Other limitations]
```

---

## When to Escalate

Quick scan should escalate to full audit if:

- [ ] Any Critical/High finding from tools
- [ ] Complex external integrations
- [ ] Novel mechanisms not reviewed before
- [ ] High TVL expected
- [ ] Bridge or cross-chain functionality
- [ ] Upgrade mechanism present
- [ ] Complex math/calculations
- [ ] Reviewer is uncertain about any area
