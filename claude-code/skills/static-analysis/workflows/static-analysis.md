# Static Analysis Audit Workflow

Systematic workflow for integrating static analysis tools into smart contract security audits.

---

## Prerequisites

- [ ] Static analysis tools installed (Slither, Mythril, Semgrep)
- [ ] Project compiles successfully
- [ ] Correct solc version configured
- [ ] Remappings configured

---

## Phase 1: Project Setup

### 1.1 Verify Compilation

```bash
# Foundry
forge build

# Hardhat
npx hardhat compile

# Check for errors
echo $?
```

### 1.2 Configure Slither

```bash
# Create slither config
cat > slither.config.json << 'EOF'
{
    "filter_paths": ["test/", "lib/", "script/", "node_modules/"],
    "exclude_informational": false,
    "exclude_optimization": true,
    "solc_remaps": []
}
EOF

# Test configuration
slither . --print contract-summary
```

### 1.3 Document Scope

```markdown
## Analysis Scope

### In Scope
- [ ] src/core/*.sol
- [ ] src/periphery/*.sol

### Out of Scope
- [ ] test/**
- [ ] lib/**
- [ ] script/**
- [ ] interfaces/** (already audited)
```

---

## Phase 2: Quick Scan (Slither)

### 2.1 Run Full Analysis

```bash
# Full analysis with JSON output
slither . --json results/slither-full.json 2>&1 | tee results/slither.log

# Check summary
slither . --print human-summary
```

### 2.2 High Severity Focus

```bash
# Run only high impact detectors
slither . --detect \
  reentrancy-eth,reentrancy-no-eth,\
  arbitrary-send-eth,arbitrary-send-erc20,\
  controlled-delegatecall,suicidal,\
  unprotected-upgrade,unchecked-transfer \
  --json results/slither-high.json
```

### 2.3 Initial Triage

```markdown
## Slither Initial Triage

| ID | Detector | Location | Status | Notes |
|----|----------|----------|--------|-------|
| S-01 | reentrancy-eth | Vault.sol:45 | REVIEW | CEI pattern? |
| S-02 | unchecked-transfer | Router.sol:123 | FP | Uses SafeERC20 |
| S-03 | arbitrary-send | Treasury.sol:89 | REVIEW | Admin check? |
```

---

## Phase 3: Deep Analysis (Mythril)

### 3.1 Run Mythril on Critical Contracts

```bash
# Identify critical contracts
CRITICAL_CONTRACTS=(
    "src/core/Vault.sol"
    "src/core/Lending.sol"
    "src/core/Treasury.sol"
)

# Run Mythril on each
for contract in "${CRITICAL_CONTRACTS[@]}"; do
    echo "Analyzing: $contract"
    myth analyze "$contract" \
        --execution-timeout 600 \
        --max-depth 50 \
        -o json \
        > "results/mythril-$(basename $contract .sol).json" 2>&1
done
```

### 3.2 Mythril Triage

```markdown
## Mythril Findings

| ID | Issue Type | Location | Status | Notes |
|----|------------|----------|--------|-------|
| M-01 | Integer Overflow | Token.sol:89 | FP | Solidity 0.8+ |
| M-02 | Ether Thief | Vault.sol:120 | REVIEW | Check access |
| M-03 | State Change After Call | Lending.sol:200 | CONFIRMED | Reentrancy |
```

---

## Phase 4: Pattern Matching (Semgrep)

### 4.1 Run Solidity Rules

```bash
# Official Solidity rules
semgrep --config "p/solidity" . --json > results/semgrep-solidity.json

# Custom rules
semgrep --config .semgrep/rules.yaml . --json > results/semgrep-custom.json
```

### 4.2 Custom Rule Examples

```yaml
# .semgrep/rules.yaml
rules:
  - id: missing-zero-check-in-constructor
    patterns:
      - pattern: |
          constructor(..., address $ADDR, ...) {
            ...
            $VAR = $ADDR;
            ...
          }
      - pattern-not: |
          constructor(..., address $ADDR, ...) {
            ...
            require($ADDR != address(0), ...);
            ...
          }
    message: "Constructor missing zero address check for $ADDR"
    languages: [solidity]
    severity: WARNING

  - id: external-call-in-loop
    patterns:
      - pattern: |
          for (...; ...; ...) {
            ...
            $ADDR.call{...}(...)
            ...
          }
    message: "External call inside loop - potential DoS"
    languages: [solidity]
    severity: ERROR
```

---

## Phase 5: Cross-Reference Analysis

### 5.1 Compare Tool Outputs

```bash
# Extract unique issues
python3 << 'EOF'
import json

# Load results
with open('results/slither-full.json') as f:
    slither = json.load(f)
    
with open('results/mythril-Vault.json') as f:
    mythril = json.load(f)

with open('results/semgrep-solidity.json') as f:
    semgrep = json.load(f)

# Extract locations
slither_locs = set()
for d in slither.get('results', {}).get('detectors', []):
    for e in d.get('elements', []):
        sm = e.get('source_mapping', {})
        if sm.get('filename'):
            slither_locs.add(f"{sm['filename']}:{sm.get('lines', [0])[0]}")

mythril_locs = set()
for i in mythril.get('issues', []):
    mythril_locs.add(f"{i.get('filename')}:{i.get('lineno')}")

semgrep_locs = set()
for r in semgrep.get('results', []):
    semgrep_locs.add(f"{r['path']}:{r['start']['line']}")

# Find overlaps
overlap = slither_locs & mythril_locs
print("Issues found by both Slither and Mythril:")
for loc in overlap:
    print(f"  {loc}")
EOF
```

### 5.2 Prioritization Matrix

```markdown
## Prioritization Matrix

### Critical (Multiple Tools Flagged)
- Vault.sol:120 - Flagged by Slither + Mythril (reentrancy)
- Treasury.sol:89 - Flagged by Slither + Semgrep (access control)

### High (Single Tool, High Confidence)
- Lending.sol:200 - Mythril (state change after call)
- Router.sol:45 - Slither (arbitrary-send)

### Medium (Needs Investigation)
- Token.sol:89 - Mythril (integer issue) - Check if 0.8+
- Pool.sol:234 - Semgrep (unchecked return)

### Low/Info (Batch Review)
- Various naming convention issues
- Solidity version recommendations
```

---

## Phase 6: Manual Verification

### 6.1 Verify Each Finding

```markdown
## Finding Verification Template

### Finding: [S-01] Reentrancy in Vault.withdraw()

**Tool**: Slither
**Detector**: reentrancy-eth
**Location**: src/core/Vault.sol:45-60

**Code Review**:
```solidity
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "Insufficient");
    
    // External call BEFORE state update
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
    
    // State update AFTER external call
    balances[msg.sender] -= amount;  // <-- BUG
}
```

**Analysis**:
- External call at line 50
- State update at line 54
- No reentrancy guard
- CEI pattern violated

**Verdict**: TRUE POSITIVE

**Severity**: Critical

**PoC Required**: Yes
```

### 6.2 Write PoC for Confirmed Issues

```solidity
// test/Exploit.t.sol
contract ReentrancyExploit is Test {
    Vault vault;
    Attacker attacker;
    
    function setUp() public {
        vault = new Vault();
        attacker = new Attacker(address(vault));
        
        // Fund vault
        vm.deal(address(vault), 10 ether);
    }
    
    function testReentrancy() public {
        // Give attacker initial funds
        vm.deal(address(attacker), 1 ether);
        
        // Record balances before
        uint256 vaultBefore = address(vault).balance;
        uint256 attackerBefore = address(attacker).balance;
        
        // Execute attack
        attacker.attack{value: 1 ether}();
        
        // Attacker drained vault
        assertEq(address(vault).balance, 0);
        assertGt(address(attacker).balance, attackerBefore);
    }
}

contract Attacker {
    Vault vault;
    uint256 count;
    
    constructor(address _vault) {
        vault = Vault(_vault);
    }
    
    function attack() external payable {
        vault.deposit{value: msg.value}();
        vault.withdraw(msg.value);
    }
    
    receive() external payable {
        if (count < 10 && address(vault).balance > 0) {
            count++;
            vault.withdraw(1 ether);
        }
    }
}
```

---

## Phase 7: Documentation

### 7.1 Finding Report Template

```markdown
# Static Analysis Findings Report

## Executive Summary

| Severity | Count | True Positives | False Positives |
|----------|-------|----------------|-----------------|
| Critical | 2 | 2 | 0 |
| High | 5 | 3 | 2 |
| Medium | 8 | 4 | 4 |
| Low | 12 | 6 | 6 |
| Info | 20 | N/A | N/A |

## True Positive Findings

### [C-01] Reentrancy in Vault.withdraw()

**File**: src/core/Vault.sol
**Lines**: 45-60
**Tool**: Slither (reentrancy-eth), Mythril (state-change-after-call)

**Description**:
The withdraw function updates state after making an external call, enabling reentrancy.

**Impact**:
Complete fund drainage. An attacker can recursively call withdraw before balance is decremented.

**Recommendation**:
Apply CEI pattern - update state before external call.

**Code Change**:
```diff
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "Insufficient");
    
+   // Update state BEFORE external call
+   balances[msg.sender] -= amount;
    
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
-   
-   balances[msg.sender] -= amount;
}
```

---

## False Positive Documentation

### [FP-01] Slither: unchecked-transfer in Router.sol

**Reason**: Contract uses SafeERC20 library which handles return values.

**Evidence**:
```solidity
using SafeERC20 for IERC20;
// ...
token.safeTransfer(to, amount);  // SafeERC20 handles return
```

**Suppression**: Add slither-disable comment or filter in config.
```

### 7.2 Final Checklist

```markdown
## Static Analysis Completion Checklist

### Tools Run
- [x] Slither - Full scan
- [x] Slither - High severity focus
- [x] Mythril - Critical contracts
- [x] Semgrep - Pattern matching

### Triage Complete
- [x] All HIGH/CRITICAL reviewed
- [x] All MEDIUM reviewed
- [x] LOW/INFO batch reviewed

### Verification
- [x] True positives have PoC
- [x] False positives documented
- [x] Uncertain items escalated

### Documentation
- [x] Finding report complete
- [x] False positive list updated
- [x] Recommendations provided

### CI/CD
- [ ] Slither config committed
- [ ] Semgrep rules committed
- [ ] GitHub Actions configured
```

---

## Quick Reference Commands

```bash
# One-liner: Full Slither scan with filter
slither . --filter-paths "test|lib|script" --json results.json

# One-liner: Run critical detectors only
slither . --detect reentrancy-eth,arbitrary-send-eth,suicidal,controlled-delegatecall

# One-liner: Mythril quick scan
myth analyze Contract.sol --execution-timeout 120 --max-depth 20

# One-liner: Semgrep Solidity
semgrep --config "p/solidity" --json -o semgrep.json .

# Full analysis script
./scripts/security-scan.sh > security-report.md
```
