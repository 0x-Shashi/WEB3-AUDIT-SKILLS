# Static Analysis Workflow

## Prerequisites
- Solidity project compiles successfully
- Slither installed (`pip install slither-analyzer`)
- Project dependencies resolved

## Step-by-Step Process

### Step 1: Environment Setup
```bash
# Ensure compilation works
forge build  # or npx hardhat compile

# Verify Slither version
slither --version
```

### Step 2: Initial Full Scan
```bash
slither . --json slither-output.json --filter-paths "node_modules|lib|test"
```

### Step 3: Review High-Severity Findings
For each High finding:
1. Read the detector description
2. Navigate to the flagged code
3. Determine if it's exploitable in context
4. Mark as TRUE POSITIVE or FALSE POSITIVE with reasoning

### Step 4: Review Medium-Severity Findings
Same triage process. Pay special attention to:
- Reentrancy variants (cross-function, read-only)
- Unchecked return values on token transfers
- Dangerous equality comparisons

### Step 5: Targeted Detector Runs
```bash
# Focus on reentrancy variants
slither . --detect reentrancy-eth,reentrancy-no-eth,reentrancy-benign,reentrancy-events

# Focus on access control
slither . --detect arbitrary-send-eth,controlled-delegatecall,suicidal,unprotected-upgrade

# Focus on ERC compliance
slither . --detect erc20-interface,erc721-interface
```

### Step 6: Printer Analysis
```bash
# Generate call graph for complex contracts
slither . --print call-graph

# Check storage layout for upgrade safety
slither . --print variable-order
```

### Step 7: Document Results
Create findings table:
| # | Detector | Contract | Function | Verdict | Notes |
|---|----------|----------|----------|---------|-------|
| 1 | reentrancy-eth | Vault | withdraw() | TP | No CEI pattern |
| 2 | arbitrary-send | Treasury | sweep() | FP | onlyOwner protected |

### Step 8: Cross-Reference with Manual Review
- Use Slither findings to prioritize manual code review
- Focus manual effort on areas Slither flagged
- Look for issues Slither cannot detect (business logic, economic exploits)

## Common Pitfalls
- Don't ignore Low/Info findings — they can indicate design issues
- Don't trust FP labels without verification
- Always re-run after code changes
- Slither cannot detect: flash loan attacks, oracle manipulation, governance exploits, economic invariant violations
