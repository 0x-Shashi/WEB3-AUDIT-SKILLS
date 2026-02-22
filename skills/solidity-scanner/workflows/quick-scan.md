# Quick Scan Workflow (15-20 minutes)

## Purpose
Rapid vulnerability identification for time-constrained reviews (contests, triage).

## Steps

### 1. Setup (2 min)
- [ ] Identify Solidity version and compiler settings
- [ ] Note external dependencies (OpenZeppelin, Chainlink, etc.)
- [ ] Count contracts and total SLOC

### 2. Automated Scan (3 min)
- [ ] Run Slither on entire codebase
- [ ] Run Aderyn for Cyfrin-specific patterns
- [ ] Review critical/high findings immediately

### 3. Access Control Pass (3 min)
- [ ] Identify all external/public functions
- [ ] Check each for proper access control
- [ ] Look for unprotected admin functions
- [ ] Verify initializer protection

### 4. Money Flow Pass (5 min)
- [ ] Trace ETH/token flows (deposit → internal → withdraw)
- [ ] Check all external calls follow CEI pattern
- [ ] Verify token transfer return values checked
- [ ] Look for hardcoded addresses

### 5. High-Impact Checks (5 min)
- [ ] Oracle usage: staleness, manipulation resistance
- [ ] Flash loan attack vectors
- [ ] Signature replay protection
- [ ] Proxy storage layout

### 6. Report Quick Findings
- Document each finding with severity
- Include code reference and fix suggestion
- Prioritize by exploitability

## Exit Criteria
- All external functions reviewed for access control
- Money flows traced end-to-end
- Automated tool findings triaged
- Top 5 risk areas identified
