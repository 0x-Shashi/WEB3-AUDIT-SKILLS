---
id: AUDITOR-FIRST-PASS
title: Auditor First Pass Checklist
category: checklist
role: auditor
phase: initial-scan
triggers:
  - first pass audit
  - initial audit scan
  - quick audit
  - low hanging fruit
  - audit triage
related_skills:
  - methodology/llm-audit-workflow.md
  - ROUTE-MAP.md
  - checklists/comprehensive-checklist.md
---

# Auditor First Pass Checklist

The "low hanging fruit" scan. Complete this in first 30-60 minutes to filter critical issues before deep analysis.

---

## Scope Triage (5 min)

- [ ] Identify protocol type (Lending/DEX/Bridge/Vault/etc)
- [ ] Check ROUTE-MAP.md for recommended reading path
- [ ] Note dependencies (Uniswap, Chainlink, etc)
- [ ] Identify high-value functions (withdraw, claim, swap, etc)
- [ ] Check if upgradeable (proxy pattern)

---

## Access Control (Quick Scan)

- [ ] Every `public`/`external` function needs it?
- [ ] Check for missing `onlyOwner`/`onlyRole` modifiers
- [ ] Look for unprotected `initialize()` functions
- [ ] Check `selfdestruct` or `delegatecall` authorization
- [ ] Verify `tx.origin` not used for auth
- [ ] Check constructor doesn't set `msg.sender` as permanent admin

**Quick Grep:**
```bash
grep -r "public\|external" --include="*.sol"
grep -r "tx.origin" --include="*.sol"
grep -r "delegatecall" --include="*.sol"
```

---

## Reentrancy (Quick Scan)

- [ ] All functions with external calls have `nonReentrant`?
- [ ] CEI pattern followed? (state before external call)
- [ ] Check ERC777/ERC1155 callback reentrancy
- [ ] Read-only reentrancy on view functions?
- [ ] Cross-function reentrancy (shared state)?

**Quick Grep:**
```bash
grep -r "call{value:" --include="*.sol"
grep -r ".call\|.transfer\|.send" --include="*.sol"
```

---

## Integer/Math Issues

- [ ] All arithmetic checked or using 0.8.0+?
- [ ] Division before multiplication? (precision loss)
- [ ] Check for rounding issues in share calculations
- [ ] Zero-value validations on critical parameters
- [ ] Max uint checks (type(uint256).max)

**Quick Grep:**
```bash
grep -r "pragma solidity" --include="*.sol"  # Check version
grep -r "unchecked" --include="*.sol"  # Manual review needed
```

---

## Oracle/Price Manipulation

- [ ] Chainlink staleness check?
- [ ] Zero/negative price validation?
- [ ] Using TWAP instead of spot price?
- [ ] Sequencer uptime check (L2)?
- [ ] Multiple oracle fallback?

**Quick Grep:**
```bash
grep -r "latestRoundData\|getReserves" --include="*.sol"
```

---

## Token Handling

- [ ] SafeERC20 used everywhere?
- [ ] Return values checked?
- [ ] Fee-on-transfer tokens considered?
- [ ] Rebasing tokens handled?
- [ ] Approval race condition (use safeIncreaseAllowance)?
- [ ] Token address validation (not zero address)?

**Quick Grep:**
```bash
grep -r "\.transfer\|\.transferFrom" --include="*.sol"
grep -r "\.approve\(" --include="*.sol"
```

---

## Input Validation

- [ ] Zero address checks on critical params?
- [ ] Array length validations?
- [ ] Parameter bounds checked (min/max)?
- [ ] Duplicate entries handled?
- [ ] Empty arrays handled?

**Quick Grep:**
```bash
grep -r "address\[\]" --include="*.sol"  # Check array params
```

---

## Logic Flaws (Quick Spots)

- [ ] Can function be called multiple times?
- [ ] State updates in correct order?
- [ ] Return values actually returned?
- [ ] Loops have bounds?
- [ ] No infinite loops possible?

---

## Common Gotchas

- [ ] Block timestamp manipulation risks?
- [ ] Block number for randomness?
- [ ] Strict equality checks? (use >= / <=)
- [ ] Uninitialized state variables?
- [ ] Shadowed variables?

**Quick Grep:**
```bash
grep -r "block.timestamp\|block.number" --include="*.sol"
grep -r "==" --include="*.sol"  # Look for strict equality
```

---

## Gas Optimization Risks

- [ ] Unchecked blocks justified?
- [ ] Assembly usage safe?
- [ ] Storage packing doesn't break logic?
- [ ] Minimal proxy delegatecall safe?

**Quick Grep:**
```bash
grep -r "assembly\|unchecked" --include="*.sol"
```

---

## External Calls

- [ ] Low-level calls (call/delegatecall) necessary?
- [ ] Return value checked?
- [ ] Gas forwarding correct?
- [ ] Reentrancy protected?
- [ ] Destination address validated?

**Quick Grep:**
```bash
grep -r "\.call\|\.delegatecall\|\.staticcall" --include="*.sol"
```

---

## Events & Logging

- [ ] Critical actions emit events?
- [ ] Indexed parameters used correctly?
- [ ] Sensitive data not in events?

---

## Signature Verification

- [ ] Nonce replay protection?
- [ ] Deadline check?
- [ ] EIP-712 domain includes chainId?
- [ ] Signature malleability protected?
- [ ] Using ECDSA library (not raw ecrecover)?

**Quick Grep:**
```bash
grep -r "ecrecover\|ECDSA" --include="*.sol"
```

---

## Upgrade Patterns

- [ ] `_disableInitializers()` in constructor?
- [ ] Storage gaps present?
- [ ] `_authorizeUpgrade()` has access control?
- [ ] Initialization can't be front-run?
- [ ] Storage layout preserved?

**Quick Grep:**
```bash
grep -r "initialize\|upgradeable" --include="*.sol"
```

---

## Flash Loan Risks

- [ ] Protocol assumes balance = state?
- [ ] TWAP used instead of spot?
- [ ] Deposit-to-use delay?
- [ ] Balance check before/after?

---

## Quick Win Findings

Common copy-paste bugs to check:

- [ ] Missing return statements
- [ ] Copy-paste with wrong variable names
- [ ] Inconsistent require messages
- [ ] Dead code or commented-out logic
- [ ] TODO/FIXME comments
- [ ] Unused imports or variables

**Quick Grep:**
```bash
grep -r "TODO\|FIXME\|HACK" --include="*.sol"
```

---

## Priority Ranking (After First Pass)

Based on findings, rank areas for deep dive:

**Critical (Drop Everything):**
- Unprotected initializers
- Missing reentrancy guards on value transfers
- Unvalidated external calls
- Oracle manipulation without protection

**High (Next 2-4 Hours):**
- Complex math/accounting logic
- Cross-protocol interactions
- Upgrade mechanisms
- Token handling edge cases

**Medium (If Time Permits):**
- Gas optimizations
- Event completeness
- Code quality issues

**Low (Document & Move On):**
- Style issues
- Minor gas optimizations
- Informational findings

---

## Output Template

After first pass, document:

```markdown
## First Pass Summary

**Protocol Type:** [Lending/DEX/Bridge/etc]
**Total Lines:** [X LOC]
**Time Spent:** [30-60 min]

### Immediate Red Flags
- [ ] [Issue 1]
- [ ] [Issue 2]

### Areas for Deep Dive
1. [Function/Contract Name] - [Reason]
2. [Function/Contract Name] - [Reason]

### Initial Risk Assessment
- Access Control: [Low/Medium/High]
- Reentrancy: [Low/Medium/High]
- Oracle Risk: [Low/Medium/High]
- Token Handling: [Low/Medium/High]

### Next Steps
1. Deep dive into [Specific Area]
2. Test [Specific Scenario]
3. Review [Specific Pattern]
```

---

## Time Management

- **0-10 min:** Scope triage + protocol type
- **10-25 min:** Access control + reentrancy scan
- **25-40 min:** Math + oracle + token checks
- **40-55 min:** External calls + signatures + upgrades
- **55-60 min:** Document findings + prioritize

---

## When to Escalate Immediately

Stop and escalate if you find:
- [ ] Unprotected `selfdestruct` or `delegatecall`
- [ ] Missing reentrancy protection on fund transfers
- [ ] Unprotected proxy upgrade function
- [ ] Hardcoded private keys or sensitive data
- [ ] Known exploit patterns (e.g., DAO reentrancy)
- [ ] Oracle price without any validation
