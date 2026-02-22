# Deep Dive Chain

## Duration: 1-2 Days
## Depth: Focused Analysis

## Purpose
Thorough analysis of specific contracts or modules. Used after Quick Scan identifies areas of concern, or when scope is limited to specific functionality.

## Chain Steps (in order)

### Step 1: Full Context Build (2 hours)
- Read ALL documentation (README, specs, architecture docs)
- Map contract inheritance hierarchy
- Identify all external interactions (calls, delegatecalls)
- Build function call graph
- List all state variables and their purpose
- Identify trust boundaries

### Step 2: Static Analysis + Triage (1 hour)
- Run Slither with ALL detectors
- Run Aderyn for additional coverage
- Triage ALL findings (High through Informational)
- Document false positives with reasoning

### Step 3: Function-by-Function Review (4-6 hours)
For each function in scope:
1. Read the function line by line
2. Check all require/assert conditions
3. Trace all state changes
4. Verify CEI pattern (Checks-Effects-Interactions)
5. Check math operations for precision loss
6. Verify access control
7. Check event emissions match state changes
8. Look for edge cases (zero amounts, max values, empty arrays)

### Step 4: Protocol-Specific Checks (2-3 hours)
Load appropriate template based on protocol type:
- Lending: Oracle, liquidation, interest rates, collateral factors
- DEX: Pricing math, LP attacks, MEV, slippage
- Bridge: Message verification, replay, accounting
- Governance: Voting, timelock, threshold
- Staking: Reward distribution, exchange rate, lock periods

### Step 5: Attack Chain Analysis (1-2 hours)
For identified risks, build full attack chains:
1. Can a flash loan amplify this?
2. What's the maximum extractable value?
3. Is the attack profitable after gas?
4. Can the attack be sandwiched or front-run?

### Step 6: Variant Analysis (1 hour)
For each finding:
- Search for same pattern across all contracts
- Check related patterns (same root cause)
- Verify fix addresses all instances

### Step 7: Report Writing (1-2 hours)
For each finding:
```
Title: [Clear, descriptive]
Severity: [Critical/High/Medium/Low/Info]
Location: [Contract:Function:Line]
Description: [What's wrong]
Impact: [What an attacker can do]
Proof of Concept: [Step-by-step exploit]
Recommendation: [How to fix]
```

## Exit Criteria
- Every function in scope reviewed line-by-line
- Protocol-specific template fully checked
- Attack chains documented for all High+ findings
- Variant analysis completed
- Report with PoCs for all findings
