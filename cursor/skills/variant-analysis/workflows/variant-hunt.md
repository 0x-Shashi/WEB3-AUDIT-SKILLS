# Variant Hunting Workflow

Step-by-step workflow for systematically finding variants of a discovered vulnerability.

---

## Prerequisites

- [ ] Initial vulnerability documented
- [ ] Vulnerability pattern extracted
- [ ] Codebase indexed/searchable
- [ ] Static analysis tools configured

---

## Phase 1: Document Initial Finding

### 1.1 Capture the Bug

```markdown
## Initial Vulnerability

**ID**: [V-XXX]
**Type**: [Category]
**Severity**: [Critical/High/Medium/Low]
**Location**: [file:function:lines]

### Vulnerable Code
[Paste exact vulnerable code]

### Why It's Vulnerable
[Explain the root cause]

### Exploitation Path
1. [Step 1]
2. [Step 2]
3. [Step 3]

### Prerequisites for Exploitation
- [Condition 1]
- [Condition 2]
```

### 1.2 Extract Vulnerability Components

```markdown
## Vulnerability Components

### Required Elements
1. [Component 1: e.g., External call]
2. [Component 2: e.g., State modification]
3. [Component 3: e.g., Missing guard]

### Pattern Signature
- [Code pattern 1]
- [Code pattern 2]
- [Code pattern 3]

### Trigger Conditions
- [Condition 1]
- [Condition 2]
```

---

## Phase 2: Build Search Queries

### 2.1 Exact Pattern Search

```bash
# Create search patterns based on vulnerability

# Example: Reentrancy
# Pattern: call{value: X}(...) followed by state update

# Search 1: Find all external calls
grep -rn "\.call\{value:" contracts/
grep -rn "\.call\{gas:" contracts/
grep -rn "payable.*\.call\(" contracts/

# Search 2: Find all ETH transfers
grep -rn "\.transfer(" contracts/
grep -rn "\.send(" contracts/

# Search 3: Find callback patterns
grep -rn "safeTransfer\|safeMint" contracts/
```

### 2.2 Generalized Pattern Search

```bash
# Broaden the search

# Example: Any external call
grep -rn "\.call(\|\.delegatecall(\|\.staticcall(" contracts/

# Example: Any state modification after call
# (Requires two-step: find calls, then check next lines)

# Create pattern file for complex searches
cat > patterns.txt << 'EOF'
\.call\{
\.delegatecall\(
\.transfer\(
\.send\(
safeTransfer
safeMint
EOF

# Search with patterns
grep -rnf patterns.txt contracts/
```

### 2.3 Semgrep Rule Creation

```yaml
# variants.yaml
rules:
  # Based on the initial finding, create rules

  - id: variant-pattern-1
    patterns:
      - pattern: |
          $EXTERNAL_CALL(...)
          ...
          $STATE_VAR = $VAL
    message: "Potential variant: [Description]"
    languages: [solidity]
    severity: ERROR

  - id: variant-pattern-2
    patterns:
      - pattern: |
          function $FUNC(...) external {
            ...
            $EXTERNAL_CALL(...)
            ...
          }
      - pattern-not-inside: |
          function $FUNC(...) external nonReentrant {
            ...
          }
    message: "Potential variant: [Description]"
    languages: [solidity]
    severity: WARNING
```

---

## Phase 3: Execute Search

### 3.1 Run All Searches

```bash
#!/bin/bash
# variant-search.sh

CONTRACTS_DIR=${1:-"contracts"}
OUTPUT_DIR="variant-analysis"
mkdir -p "$OUTPUT_DIR"

echo "=== Starting Variant Search ==="

# Grep searches
echo "Running grep searches..."
grep -rn "\.call\{" "$CONTRACTS_DIR" > "$OUTPUT_DIR/grep-calls.txt"
grep -rn "\.transfer(\|\.send(" "$CONTRACTS_DIR" > "$OUTPUT_DIR/grep-transfers.txt"
grep -rn "safeTransfer" "$CONTRACTS_DIR" > "$OUTPUT_DIR/grep-safetransfer.txt"

# Semgrep
echo "Running Semgrep..."
semgrep --config variants.yaml "$CONTRACTS_DIR" --json > "$OUTPUT_DIR/semgrep-variants.json"

# Slither specific detectors
echo "Running Slither..."
slither "$CONTRACTS_DIR" --detect reentrancy-eth,reentrancy-no-eth --json "$OUTPUT_DIR/slither-reent.json"

echo "=== Search Complete ==="
echo "Results in $OUTPUT_DIR/"
```

### 3.2 Collect All Matches

```markdown
## Search Results

### Grep: External Calls
| File | Line | Code | Potential Variant? |
|------|------|------|-------------------|
| Vault.sol | 45 | `.call{value: amount}` | YES - initial |
| Pool.sol | 78 | `.call{value: reward}` | REVIEW |
| Router.sol | 120 | `.call{value: 0}` | NO - zero value |

### Grep: Token Transfers
| File | Line | Code | Potential Variant? |
|------|------|------|-------------------|
| Lending.sol | 234 | `asset.safeTransfer` | REVIEW |
| Staking.sol | 89 | `token.transfer` | REVIEW |

### Semgrep Matches
| Rule | File | Line | Severity |
|------|------|------|----------|
| variant-pattern-1 | Pool.sol | 78 | ERROR |
| variant-pattern-2 | Lending.sol | 234 | WARNING |
```

---

## Phase 4: Triage Results

### 4.1 Initial Categorization

```markdown
## Triage Categories

### Category A: Highly Likely Variants
Matches all vulnerability components:
- [ ] Pool.sol:78 - withdraw()
- [ ] Treasury.sol:156 - claim()

### Category B: Possible Variants
Matches some components, needs investigation:
- [ ] Lending.sol:234 - liquidate()
- [ ] Staking.sol:89 - unstake()

### Category C: Unlikely/False Positives
Pattern match but likely not vulnerable:
- [ ] Router.sol:120 - zero value call
- [ ] Token.sol:45 - internal function
```

### 4.2 Priority Queue

```markdown
## Investigation Priority

### Priority 1: Same Pattern, Same Risk
1. Pool.sol:withdraw() - Exact same pattern
2. Treasury.sol:claim() - Nearly identical

### Priority 2: Similar Pattern, Similar Risk  
3. Lending.sol:liquidate() - Different trigger, same mechanism
4. Staking.sol:unstake() - Different asset, same pattern

### Priority 3: Related Pattern, Lower Risk
5. Router.sol:swap() - Has reentrancy guard, check bypass
6. NFT.sol:mint() - ERC721 callback, check state
```

---

## Phase 5: Deep Investigation

### 5.1 Investigation Template

```markdown
## Variant Investigation: [Location]

### Quick Assessment
- **Pattern Match Level**: [Exact/Partial/Weak]
- **Initial Verdict**: [Likely Variant/Possible/Unlikely]

### Code Analysis
```solidity
[Paste the code]
```

### Component Checklist
- [ ] Component 1 present? [YES/NO/PARTIAL]
- [ ] Component 2 present? [YES/NO/PARTIAL]
- [ ] Component 3 present? [YES/NO/PARTIAL]

### Differences from Original
- Difference 1: [description]
- Difference 2: [description]

### Exploitation Analysis
**Can this be exploited?**
- Condition 1: [MET/NOT MET]
- Condition 2: [MET/NOT MET]

### Verdict
- [ ] CONFIRMED VARIANT
- [ ] POSSIBLE VARIANT (needs more analysis)
- [ ] FALSE POSITIVE

### Evidence
[Provide reasoning or PoC]
```

### 5.2 Example Investigation

```markdown
## Variant Investigation: Pool.sol:78

### Quick Assessment
- **Pattern Match Level**: Exact
- **Initial Verdict**: Likely Variant

### Code Analysis
```solidity
function withdraw(uint256 amount) external {
    require(deposits[msg.sender] >= amount, "Insufficient");
    
    // External call - MATCHES PATTERN
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
    
    // State update after call - MATCHES PATTERN
    deposits[msg.sender] -= amount;
}
```

### Component Checklist
- [x] External call present? YES
- [x] State modified after call? YES
- [x] Missing reentrancy guard? YES

### Differences from Original
- Uses `deposits` instead of `balances` (same semantics)
- Same ETH transfer pattern
- Same CEI violation

### Exploitation Analysis
**Can this be exploited?**
- Contract holds ETH: YES (Pool receives deposits)
- User can trigger: YES (public withdraw)
- No reentrancy guard: YES (none present)

### Verdict
- [x] CONFIRMED VARIANT

### Evidence
Same attack pattern applies. Attacker can:
1. Deposit 1 ETH
2. Call withdraw(1 ETH)
3. In receive(), call withdraw again
4. Repeat until pool drained
```

---

## Phase 6: Document All Variants

### 6.1 Variant Summary

```markdown
## Variant Analysis Summary

### Original Finding
- Location: Vault.sol:45 withdraw()
- Type: Reentrancy
- Severity: Critical

### Confirmed Variants
| ID | Location | Pattern Match | Severity | Status |
|----|----------|---------------|----------|--------|
| V-001a | Pool.sol:78 | Exact | Critical | Confirmed |
| V-001b | Treasury.sol:156 | Exact | Critical | Confirmed |

### Possible Variants (Needs Fix Review)
| ID | Location | Pattern Match | Risk | Notes |
|----|----------|---------------|------|-------|
| V-001c | Lending.sol:234 | Partial | Medium | ERC20 only, no callback |

### False Positives
| Location | Reason |
|----------|--------|
| Router.sol:120 | Zero value, no state change |
| Token.sol:45 | Internal only, not reachable |
```

### 6.2 Root Cause Analysis

```markdown
## Root Cause Analysis

### Why Do These Variants Exist?

**Pattern**: Copy-paste development
- Similar functions across contracts
- Same developer, same mistakes
- No security review between copies

**Missing**: Security guidelines
- No reentrancy guard requirement
- No CEI pattern enforcement
- No code review checklist

**Systemic**: No static analysis
- Slither not run during development
- No CI/CD security checks
- Issues only caught in audit

### Prevention Recommendations
1. Add reentrancy guard to all external functions with calls
2. Enforce CEI pattern in development guidelines
3. Add Slither to CI/CD pipeline
4. Create internal security checklist
```

---

## Phase 7: Comprehensive Remediation

### 7.1 Fix Scope

```markdown
## Required Fixes

### Must Fix (Confirmed Variants)
- [ ] Vault.sol:45 - Add nonReentrant + CEI
- [ ] Pool.sol:78 - Add nonReentrant + CEI
- [ ] Treasury.sol:156 - Add nonReentrant + CEI

### Should Fix (Defense in Depth)
- [ ] Lending.sol:234 - Add nonReentrant (ERC777 protection)
- [ ] Staking.sol:89 - Add nonReentrant (future-proofing)

### Systemic Fixes
- [ ] Add ReentrancyGuard to base contract
- [ ] Update development guidelines
- [ ] Add Slither to CI/CD
```

### 7.2 Fix Verification

```markdown
## Fix Verification Checklist

### Per-Location Verification
For each fixed location:
- [ ] Fix applied correctly
- [ ] No regression introduced
- [ ] Test passes
- [ ] Slither clean

### Global Verification
- [ ] All variants addressed
- [ ] No new variants introduced by fix
- [ ] Systemic measures in place

### Re-run Analysis
- [ ] Grep search clean
- [ ] Semgrep scan clean
- [ ] Slither reentrancy detectors clean
```

---

## Quick Reference

```bash
# Fast variant search command
grep -rn "PATTERN" contracts/ | grep -v "test\|mock" | sort -t: -k1,1 -k2,2n

# Multi-pattern search
grep -rn "pattern1\|pattern2\|pattern3" contracts/

# Find functions matching signature
grep -Pzo "function \w+\([^)]*\)[^{]*\{[^}]*\.call" contracts/

# Run Slither for specific detector
slither . --detect reentrancy-eth --json variants.json

# Run Semgrep with custom rules
semgrep --config ./variants.yaml . --json
```
