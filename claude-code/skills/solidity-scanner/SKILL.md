---
name: solidity-scanner
description: "Comprehensive Solidity/EVM vulnerability scanner with 100+ vulnerability patterns, protocol-specific checks, and deep integration with static analysis tools. Use this skill when auditing Ethereum, BSC, Polygon, Arbitrum, Optimism, or any EVM-compatible chain."
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
---

# Solidity Vulnerability Scanner

## Purpose

This skill provides systematic vulnerability scanning for Solidity smart contracts on EVM-compatible chains. It includes:
- 100+ vulnerability patterns organized by category
- Protocol-type specific checklists (DEX, Lending, NFT, etc.)
- Static analysis tool integration
- Severity classification framework
- Comprehensive output templates

---

## When to Use This Skill

**Use when:**
- Auditing Solidity/Vyper smart contracts
- Reviewing EVM-compatible code (Ethereum, BSC, Polygon, Arbitrum, Optimism, etc.)
- Scanning for known vulnerability patterns
- Performing systematic security review
- Preparing competitive audit submissions

**Trigger phrases:**
- "Scan this Solidity code"
- "Check for vulnerabilities"
- "Audit this contract"
- "Security review for EVM"
- "Find bugs in this smart contract"

---

## When NOT to Use

Do NOT use this skill for:
- Non-EVM chains (use chain-specific scanners)
- Context building phase (use audit-context-building first)
- Research on similar vulnerabilities (use cyfrin-findings)
- Report writing (use audit-report-writer)

---

## Quick Start

### Scan Single Function
```markdown
## Scan Request
Target: functionName() in Contract.sol
Type: [reentrancy | access-control | arithmetic | all]
Depth: [quick | standard | deep]
```

### Scan Full Contract
```markdown
## Scan Request
Target: Contract.sol
Protocol Type: [DEX | Lending | NFT | Vault | Bridge | Other]
Scan Mode: [quick | standard | comprehensive]
Output: [summary | detailed | findings-only]
```

---

## Vulnerability Categories

### Category 1: Reentrancy

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| RE-01 | Classic reentrancy | Critical | External call before state update |
| RE-02 | Cross-function reentrancy | Critical | Shared state across functions |
| RE-03 | Cross-contract reentrancy | High | Multiple contract interactions |
| RE-04 | Read-only reentrancy | High | View function manipulation |
| RE-05 | ERC777 hooks | High | Token callback during transfer |
| RE-06 | ERC721 hooks | High | onERC721Received callback |
| RE-07 | ERC1155 hooks | High | onERC1155Received callback |

**Quick Check Pattern:**
```
External call (call, transfer, send, or token interaction)
    
State changes AFTER the call?
    
YES = Potential reentrancy
```

### Category 2: Access Control

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| AC-01 | Missing access control | Critical | Public function modifies state |
| AC-02 | Incorrect modifier | High | Wrong role check |
| AC-03 | Missing zero-address check | Medium | Owner set to address(0) |
| AC-04 | Centralization risk | Medium | Single owner controls critical functions |
| AC-05 | Broken role hierarchy | High | Role escalation possible |
| AC-06 | tx.origin authentication | High | Phishing vulnerability |
| AC-07 | Unprotected initializer | Critical | Can be called multiple times |
| AC-08 | Unprotected self-destruct | Critical | Contract can be destroyed |

### Category 3: Arithmetic & Logic

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| AR-01 | Integer overflow (pre-0.8) | Critical | Unchecked arithmetic |
| AR-02 | Integer underflow | Critical | Subtraction below zero |
| AR-03 | Division by zero | High | Unchecked divisor |
| AR-04 | Precision loss | Medium | Integer division truncation |
| AR-05 | Rounding errors | Medium | Cumulative precision loss |
| AR-06 | Unsafe casting | High | uint256 to uint128, etc. |
| AR-07 | Off-by-one errors | Medium | Array bounds, loops |
| AR-08 | Incorrect comparison | Medium | < vs <= errors |

### Category 4: Oracle & Price Manipulation

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| OR-01 | Spot price manipulation | Critical | Using pool.getReserves() |
| OR-02 | Flash loan price attack | Critical | Single-block price dependency |
| OR-03 | Stale oracle data | High | No freshness check |
| OR-04 | Missing oracle validation | High | No bounds checking |
| OR-05 | Sequencer downtime | High | L2 sequencer not checked |
| OR-06 | Oracle decimals mismatch | Medium | Incorrect decimal handling |
| OR-07 | Single oracle dependency | Medium | No fallback oracle |

### Category 5: Token Integration

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| TK-01 | Fee-on-transfer tokens | High | Balance discrepancy |
| TK-02 | Rebasing tokens | High | Balance changes unexpectedly |
| TK-03 | Non-standard return values | Medium | Missing return check |
| TK-04 | Missing approval reset | Medium | Approval race condition |
| TK-05 | Double-entry tokens | High | Multiple addresses same balance |
| TK-06 | Pausable tokens | Medium | Transfer can be blocked |
| TK-07 | Blacklist tokens | Medium | Address can be blocked |
| TK-08 | Low decimal tokens | Medium | Precision issues |
| TK-09 | High decimal tokens | Medium | Overflow issues |
| TK-10 | ERC777 callback | High | Reentrancy via hooks |

### Category 6: Flash Loan Attacks

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| FL-01 | Flash loan governance | Critical | Vote with borrowed tokens |
| FL-02 | Flash loan price oracle | Critical | Manipulate price same block |
| FL-03 | Flash loan collateral | High | Borrow against borrowed assets |
| FL-04 | Flash minting attack | High | Unlimited token mint/burn |

### Category 7: Denial of Service

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| DOS-01 | Unbounded loop | High | Loop over growing array |
| DOS-02 | Block gas limit | High | Operation exceeds gas limit |
| DOS-03 | External call failure | Medium | Revert on failed call |
| DOS-04 | Push over pull | Medium | Mass transfer to many addresses |
| DOS-05 | Griefing attack | Medium | Intentional failure for others |
| DOS-06 | Storage slot exhaustion | Medium | Unbounded mappings/arrays |

### Category 8: MEV & Frontrunning

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| MEV-01 | Sandwich attack | High | No slippage protection |
| MEV-02 | Frontrunnable approval | Medium | Approval visible in mempool |
| MEV-03 | Missing deadline | Medium | Stale transaction execution |
| MEV-04 | Predictable randomness | High | block.timestamp/blockhash |
| MEV-05 | Commit-reveal bypass | High | Weak commit scheme |

### Category 9: Low-Level Calls

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| LC-01 | Unchecked return value | High | call().value without check |
| LC-02 | Arbitrary call target | Critical | User-controlled call address |
| LC-03 | Delegatecall to untrusted | Critical | Delegatecall to user address |
| LC-04 | Signature malleability | High | ecrecover without s check |
| LC-05 | Empty return check | Medium | Extcodesize = 0 |
| LC-06 | Assembly overflow | High | Unchecked assembly math |

### Category 10: Upgrades & Proxies

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| UP-01 | Storage collision | Critical | Slot overlap in upgrade |
| UP-02 | Function selector clash | High | Same selector, different function |
| UP-03 | Missing initializer | Critical | No initializer modifier |
| UP-04 | Initialization race | High | Can initialize before owner |
| UP-05 | Incorrect implementation | High | Wrong implementation set |
| UP-06 | Missing storage gap | Medium | No __gap for future variables |
| UP-07 | Constructor in implementation | Medium | Constructor won't run |

---

## Protocol-Specific Checklists

### DEX / AMM Protocol

```markdown
## DEX Security Checklist

### Swap Functions
- [ ] Slippage protection enforced
- [ ] Deadline parameter checked
- [ ] No spot price manipulation possible
- [ ] Flash loan resistant pricing

### Liquidity Functions
- [ ] First depositor attack prevented
- [ ] LP share calculation correct
- [ ] No sandwich attack on add liquidity
- [ ] Minimum liquidity enforced

### Fees
- [ ] Fee calculation overflow-safe
- [ ] Fee cannot be set to 100%
- [ ] Fee distribution correct

### Oracle
- [ ] TWAP used instead of spot
- [ ] Manipulation resistant
- [ ] Fallback oracle available
```

### Lending Protocol

```markdown
## Lending Security Checklist

### Collateral
- [ ] Collateral factor reasonable
- [ ] Liquidation threshold correct
- [ ] Oracle manipulation resistant
- [ ] Different oracle per asset possible

### Borrowing
- [ ] Interest rate model correct
- [ ] Borrow limit enforced
- [ ] Flash loan borrow protected
- [ ] Compound interest calculated correctly

### Liquidations
- [ ] Health factor calculation correct
- [ ] Liquidation incentive reasonable
- [ ] No self-liquidation exploit
- [ ] Bad debt handling exists

### Tokens
- [ ] Fee-on-transfer handled
- [ ] Rebasing tokens handled
- [ ] Weird decimals handled
```

### NFT Protocol

```markdown
## NFT Security Checklist

### Minting
- [ ] Mint limit enforced
- [ ] Mint price cannot be bypassed
- [ ] Whitelist/allowlist secure
- [ ] Signature not replayable

### Metadata
- [ ] Metadata reveal secure
- [ ] No metadata prediction
- [ ] IPFS/Arweave correctly referenced

### Marketplace
- [ ] Signature verification correct
- [ ] Order cancellation works
- [ ] Royalty calculation correct
- [ ] No order replay possible
```

### Vault / Yield Protocol

```markdown
## Vault Security Checklist

### Deposits
- [ ] Share calculation correct
- [ ] First depositor protected
- [ ] Minimum deposit enforced
- [ ] Deposit receipt atomic

### Withdrawals
- [ ] Withdrawal queue if needed
- [ ] Slippage protection
- [ ] Emergency withdrawal exists
- [ ] Partial withdrawal works

### Strategy
- [ ] Strategy validation
- [ ] Rug pull prevention
- [ ] Harvest timing secure
- [ ] Loss handling correct

### Accounting
- [ ] Total assets accurate
- [ ] Share price manipulation prevented
- [ ] Fee calculation correct
- [ ] Reward distribution fair
```

---

## Scanning Workflow

### Step 1: Initial Scan

```bash
# Run automated tools first
slither . --print human-summary
slither . --detect all --json slither-output.json

# Echidna for invariant testing
echidna . --contract ContractName --config echidna.yaml

# Custom semgrep rules
semgrep --config=p/smart-contracts .
```

### Step 2: Category Scan

For each vulnerability category:

1. **Search for patterns:**
   ```bash
   # Example: Find external calls
   grep -rn "\.call\|\.transfer\|\.send" contracts/
   
   # Example: Find state changes
   grep -rn "=\|+=\|-=" contracts/
   ```

2. **Analyze each match:**
   - Does it match a vulnerability pattern?
   - What's the context?
   - Is there mitigation in place?

3. **Document findings:**
   - Location (file, line)
   - Pattern matched
   - Severity
   - Impact
   - Recommendation

### Step 3: Protocol-Specific Scan

Apply the relevant protocol checklist based on the protocol type.

### Step 4: Cross-Reference

```bash
# Search Cyfrin Solodit for similar findings
# Use cyfrin-findings skill to query:
# - Same protocol type
# - Same vulnerability patterns
# - Same functions/patterns
```

---

## Output Format

### Finding Template

```markdown
## [SEV-ID] Title

**Severity:** Critical | High | Medium | Low | Informational
**Category:** [Category Name]
**Pattern ID:** [XX-##]

### Location
- **File:** path/to/Contract.sol
- **Lines:** 45-52
- **Function:** functionName()

### Description
[Clear explanation of the vulnerability]

### Vulnerable Code
```solidity
// The problematic code
function vulnerable() external {
    // Issue is here
}
```

### Impact
[What an attacker could achieve]

### Proof of Concept
```solidity
// Attack scenario
function attack() {
    // Steps to exploit
}
```

### Recommendation
```solidity
// Fixed code
function secure() external {
    // Proper implementation
}
```

### References
- [Link to similar finding]
- [Relevant documentation]
```

---

## Static Analysis Integration

### Slither Commands

```bash
# Full analysis
slither . --detect all

# Specific detectors
slither . --detect reentrancy-eth,reentrancy-no-eth

# Print useful info
slither . --print contract-summary
slither . --print function-summary
slither . --print modifiers

# Export for further analysis
slither . --json output.json
```

### Mythril Commands

```bash
# Analyze contract
myth analyze contracts/Contract.sol

# With specific checks
myth analyze --execution-timeout 300 contracts/Contract.sol

# Verbose output
myth analyze -v4 contracts/Contract.sol
```

### Foundry Integration

```bash
# Fuzz testing
forge test --fuzz-runs 10000

# Invariant testing
forge test --match-test invariant

# Gas optimization
forge test --gas-report

# Coverage
forge coverage
```

---

## Resources

- [Vulnerability Patterns Database](resources/vulnerability-patterns.md)
- [False Positive Guide](resources/false-positives.md)
- [Severity Classification](resources/severity-guide.md)
- [Tool Configuration](resources/tool-configs.md)

## Workflows

- [Quick Scan](workflows/quick-scan.md)
- [Comprehensive Audit](workflows/comprehensive-audit.md)
- [Competitive Audit](workflows/competitive-audit.md)

