# Quick Scan Chain

## Duration: 1-2 Hours
## Depth: Surface Level

## Purpose
Rapid assessment to identify obvious vulnerabilities and determine if a deeper audit is warranted. Useful for triage, initial client engagement, or competitive audit time-boxing.

## Chain Steps (in order)

### Step 1: Context Detection (10 min)
- Identify protocol type (lending, DEX, bridge, etc.)
- Count contracts and lines of code
- Identify external dependencies (OpenZeppelin, Uniswap, Chainlink)
- Note deployment chain(s)

### Step 2: Static Analysis (15 min)
```bash
slither . --json output.json --filter-paths "node_modules|lib|test"
```
- Run Slither on entire codebase
- Review all High/Medium findings
- Note areas flagged for manual review

### Step 3: Access Control Review (15 min)
- Identify all `onlyOwner`, `onlyAdmin`, `onlyRole` functions
- Check for missing access control on state-changing functions
- Verify ownership transfer pattern (2-step preferred)
- Check for centralization risks

### Step 4: Top-10 Vulnerability Check (30 min)
Manually check for:
1. Reentrancy (external calls before state updates)
2. Oracle manipulation (spot price usage)
3. Unchecked return values
4. Integer overflow in Solidity < 0.8
5. Front-running susceptibility
6. Flash loan enablement of exploits
7. Wrong access control
8. Uninitialized storage/proxy
9. Signature replay
10. Incorrect parameter validation

### Step 5: Quick Report (10 min)
Document findings in format:
```
QUICK SCAN RESULTS
Protocol: [name]
Contracts: [count]
LOC: [count]
Risk Level: [Low/Medium/High/Critical]

Findings:
- [H/M/L] Description
...

Recommendation: [No issues / Needs deep dive on X / Do not deploy]
```

## Exit Criteria
- All Slither High/Medium triaged
- Top-10 manually checked
- Access control mapped
- Report delivered with recommendation
