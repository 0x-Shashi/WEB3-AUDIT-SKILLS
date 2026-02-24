---
id: METHOD-FORK-AUDIT
title: Fork Audit Methodology
category: methodology
difficulty: intermediate
triggers: [fork audit, forked protocol, compare to original, diff analysis, Uniswap fork, Compound fork, Aave fork]
related_skills: [methodology/upgrade-migration-patterns.md, methodology/secure-pattern-reference.md, checklists/comprehensive-checklist.md]
tags: [fork, diff, comparison, compound, uniswap, aave]
last_updated: 2026-02-24
---

# Fork Audit Methodology

## Overview

~60% of DeFi protocols are forks of established codebases. Forked protocols carry unique risks:
- Inherited bugs from the base protocol
- New bugs introduced by modifications
- Subtle incompatibilities with integrated systems
- Missing security patches from upstream

This guide provides systematic methodology for auditing forks.

---

## 1. Identify the Base Protocol

### 1.1 Common Fork Bases

| Base Protocol | Typical Forks | Key Files to Check |
|--------------|---------------|-------------------|
| Uniswap V2 | Most AMM DEXes | UniswapV2Pair.sol, UniswapV2Router02.sol |
| Uniswap V3 | Concentrated liquidity DEXes | UniswapV3Pool.sol, NonfungiblePositionManager.sol |
| Compound V2 | Most lending protocols | CToken.sol, Comptroller.sol |
| Aave V2/V3 | Lending variants | LendingPool.sol, AToken.sol |
| MasterChef | Yield farms | MasterChef.sol |
| OpenZeppelin | Most ERC standards | ERC20.sol, ERC721.sol, AccessControl.sol |

### 1.2 Identification Techniques

```bash
# Search for common base protocol identifiers
grep -r "UniswapV2" contracts/
grep -r "Compound" contracts/
grep -r "MasterChef" contracts/

# Check import statements
grep -r "import.*openzeppelin" contracts/
grep -r "import.*uniswap" contracts/

# Look at package.json for dependencies
cat package.json | jq '.dependencies'

# Check deployment history
# If verified on Etherscan, compare bytecode with known protocols
```

### 1.3 Version Identification

```bash
# Check for version comments
grep -r "SPDX-License-Identifier\|pragma solidity\|@version" contracts/

# Compare with known protocol versions
diff -r contracts/ reference/uniswap-v2-core/contracts/

# Check git history for initial commit (often copied from base)
git log --oneline --follow contracts/core/Pair.sol | tail -5
```

---

## 2. Git Diff Techniques for Code Comparison

### 2.1 Setup Reference Repository

```bash
# Clone reference protocol
git clone https://github.com/Uniswap/v2-core.git reference/uniswap-v2-core
git clone https://github.com/compound-finance/compound-protocol.git reference/compound

# Or download specific tagged version
git clone --branch v1.0.0 https://github.com/original/protocol.git reference/
```

### 2.2 File-Level Comparison

```bash
# List all files that differ
diff -rq contracts/ reference/uniswap-v2-core/contracts/ 2>/dev/null | grep -v "Only in"

# Generate patch file for all differences
diff -ruN reference/uniswap-v2-core/contracts/ contracts/ > changes.patch

# Count changed lines per file
diff -ruN reference/ contracts/ | grep "^diff" -A3 | grep "^@@" | wc -l
```

### 2.3 Detailed Diff Analysis

```bash
# Side-by-side diff with context
diff -y --width=180 reference/UniswapV2Pair.sol contracts/Pair.sol | less

# Unified diff for specific file
diff -u reference/UniswapV2Pair.sol contracts/Pair.sol > pair_changes.diff

# Ignore whitespace changes
diff -u -w reference/UniswapV2Pair.sol contracts/Pair.sol

# Show only added/removed lines (not context)
diff reference/file.sol contracts/file.sol | grep "^[<>]"
```

### 2.4 Using Git for Comparison

```bash
# If both repos are git repos, use git diff
git diff --no-index reference/contracts/ forked/contracts/

# Generate statistics
git diff --stat --no-index reference/ forked/

# Find functions that changed
git diff --no-index reference/ forked/ | grep "^[-+].*function"

# Ignore comments and empty lines
git diff --no-index -w --ignore-blank-lines reference/ forked/
```

### 2.5 Automated Diff Tools

```python
# Python script to extract meaningful diffs
import difflib
from pathlib import Path

def compare_contracts(original_dir, forked_dir):
    """Compare Solidity files and highlight security-relevant changes."""
    
    original_files = set(Path(original_dir).rglob("*.sol"))
    forked_files = set(Path(forked_dir).rglob("*.sol"))
    
    # New files (not in original)
    new_files = forked_files - original_files
    print(f"New files: {len(new_files)}")
    
    # Modified files
    for orig_file in original_files:
        fork_file = Path(forked_dir) / orig_file.relative_to(original_dir)
        if fork_file.exists():
            diff = list(difflib.unified_diff(
                orig_file.read_text().splitlines(),
                fork_file.read_text().splitlines(),
                lineterm=''
            ))
            if diff:
                # Filter for security-relevant keywords
                security_changes = [
                    line for line in diff 
                    if any(kw in line.lower() for kw in [
                        'transfer', 'call', 'delegatecall', 'selfdestruct',
                        'owner', 'admin', 'require', 'assert', 'external',
                        'payable', 'approve', 'allowance'
                    ])
                ]
                if security_changes:
                    print(f"\n{orig_file}:")
                    for line in security_changes[:20]:
                        print(line)
```

---

## 3. Common Forking Mistakes

### 3.1 Incomplete Feature Removal

```solidity
// Original: Had flash loans
function flashLoan(...) external {
    // Full implementation
}

// Fork: Tried to remove but left callback
// [MISTAKE]: flashLoanCallback still exists and callable
function flashLoanCallback(...) external {
    // Can be called directly!
}
```

**Detection:**
```bash
# Find callback functions without corresponding callers
grep -r "Callback\|Hook\|callback\|hook" contracts/ | cut -d: -f2 | sort -u
```

### 3.2 Hardcoded Addresses

```solidity
// Original Uniswap V2:
address constant FACTORY = 0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f;

// [MISTAKE] Fork kept mainnet address on Arbitrum
// Protocol interacts with wrong/non-existent contract
```

**Detection:**
```bash
# Find hardcoded addresses
grep -rE "0x[a-fA-F0-9]{40}" contracts/
```

### 3.3 Fee/Parameter Modifications

```solidity
// Original: 0.3% fee, well-tested
uint256 constant FEE = 30; // basis points

// [MISTAKE] Fork: Changed to 1%, breaks invariants
uint256 constant FEE = 100;
// Math that assumed FEE < 100 now overflows
```

**Detection:**
```bash
# Compare constants
diff <(grep -r "constant\|immutable" reference/) <(grep -r "constant\|immutable" contracts/)
```

### 3.4 Interface Mismatches

```solidity
// Original: Used standard ERC20
IERC20(token).transfer(to, amount);

// [MISTAKE] Fork: Integrates with non-standard token
// Token returns (bool, bytes) instead of bool
// Silent failure or revert
```

### 3.5 Missing Access Control Inheritance

```solidity
// Original: Inherited Ownable properly
contract Protocol is Ownable, ReentrancyGuard {
    function admin() external onlyOwner { }
}

// [MISTAKE] Fork: Copied functions but forgot inheritance
contract ForkedProtocol is ReentrancyGuard {  // Missing Ownable!
    function admin() external onlyOwner { }    // onlyOwner undefined → compile error
    // Or worse: they define own broken modifier
}
```

### 3.6 Upstream Security Patches Not Applied

```solidity
// Original was patched after audit finding
// Fork copied pre-patch version

// Check original's commit history for security fixes:
// git log --oneline --grep="fix\|security\|vulnerability" reference/
```

**Detection:**
```bash
# Compare with latest security patches
git log --oneline --grep="security\|fix\|vulnerability\|reentrancy" reference/

# Check if patch commits are in fork
git log --oneline forked/ | grep -f <(git log --oneline reference/ --grep="fix")
```

---

## 4. "Hidden Bug" Patterns in Forks

### 4.1 Modified Invariants

```solidity
// Original: Invariant x * y = k maintained
function swap(uint256 amountIn) external {
    // Complex math that maintains k
}

// Fork: Added fee that breaks invariant
function swap(uint256 amountIn) external {
    uint256 fee = amountIn * FEE / 10000;
    // Forgot to account for fee in k calculation
    // k slowly drains from pool
}
```

### 4.2 Initialization Order Changes

```solidity
// Original: Initialize A before B (B depends on A)
function initialize() {
    initA();
    initB(); // Uses values set by initA
}

// [MISTAKE] Fork: Reordered initialization
function initialize() {
    initB(); // Reads uninitialized values!
    initA();
}
```

### 4.3 Removed Safety Checks

```solidity
// Original: Had reentrancy guard
function withdraw() external nonReentrant {
    // ...
}

// [MISTAKE] Fork: Removed "unnecessary" modifier for gas
function withdraw() external {
    // Now vulnerable!
}
```

### 4.4 Changed Event Emissions

```solidity
// Original: Emitted event with correct values
emit Transfer(from, to, amount);

// [MISTAKE] Fork: Changed parameter order (off-chain indexers break)
emit Transfer(to, from, amount);  // Reversed!

// Or: Removed event entirely (indexers can't track)
```

---

## 5. Fork Audit Checklist

### Phase 1: Identification
- [ ] Identify base protocol and version
- [ ] Clone reference repository at correct version
- [ ] Map file structure differences
- [ ] List all new files not in original
- [ ] List all removed files from original

### Phase 2: Diff Analysis
- [ ] Generate comprehensive diff
- [ ] Categorize changes: cosmetic, functional, security-relevant
- [ ] Document all constant/parameter changes
- [ ] Document all function signature changes
- [ ] Document all removed code (especially modifiers, checks)

### Phase 3: Security-Relevant Changes
- [ ] New external/public functions
- [ ] Removed access controls
- [ ] Changed validation logic
- [ ] Modified transfer/call patterns
- [ ] Altered fee calculations
- [ ] Different oracle integrations

### Phase 4: Upstream Patches
- [ ] Check base protocol's security advisories
- [ ] Verify all security patches applied
- [ ] Review original audit reports
- [ ] Cross-reference with known vulnerabilities

### Phase 5: Integration Risks
- [ ] Hardcoded addresses updated for target chain
- [ ] Token compatibility (decimals, return values)
- [ ] Oracle compatibility
- [ ] Gas differences if different chain

---

## 6. Fork Audit Report Template

```markdown
## Fork Analysis: [Protocol Name]

### Base Protocol
- **Original:** [Uniswap V2 / Compound V2 / etc.]
- **Version:** [Commit hash or version tag]
- **Reference:** [GitHub URL]

### Change Summary
| Category | Files Changed | Lines Added | Lines Removed |
|----------|--------------|-------------|---------------|
| Core Logic | X | Y | Z |
| Access Control | X | Y | Z |
| Fee/Parameters | X | Y | Z |
| Cosmetic | X | Y | Z |

### Security-Relevant Changes

#### 1. [Change Category]
**File:** `contracts/Changed.sol`
**Original:**
```solidity
// Original code
```
**Forked:**
```solidity
// Forked code
```
**Risk:** [Low/Medium/High/Critical]
**Analysis:** [Why this change matters]

### Missing Upstream Patches
| Patch | Original Commit | Status | Risk |
|-------|----------------|--------|------|
| Reentrancy fix | abc123 | [X] Missing | High |

### Recommendations
1. [Recommendation]
2. [Recommendation]
```

---

## Related

- [Differential Review Skill](../differential-review/SKILL.md)
- [Fix Verification Patterns](../fix-patterns/INDEX.md)
- [Protocol Playbooks](../playbooks/)
