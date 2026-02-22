---
id: STATIC-SLITHER
title: Slither Configuration & Usage Guide
parent: static-analysis
type: resource
last_updated: 2025-01-31
---

# Slither Configuration & Usage Guide

Slither is the industry-standard static analysis tool for Solidity. It performs data flow analysis on the Solidity AST to detect vulnerability patterns. Created and maintained by Trail of Bits.

---

## Installation

```bash
# Standard install
pip install slither-analyzer

# Isolated install (recommended)
pipx install slither-analyzer

# Verify
slither --version

# Also need solc (Solidity compiler)
pip install solc-select
solc-select install 0.8.20
solc-select use 0.8.20
```

### Framework Compatibility

| Framework | Compatibility | Notes |
|-----------|-------------|-------|
| Foundry | Full | Auto-detects `foundry.toml` |
| Hardhat | Full | Auto-detects `hardhat.config.js/ts` |
| Brownie | Full | Auto-detects |
| Truffle | Full | Auto-detects |
| Dapp | Partial | May need manual config |

---

## Basic Usage

```bash
# Run all detectors on current project
slither .

# Run on specific file
slither src/Vault.sol

# Run specific detectors only
slither . --detect reentrancy-eth,reentrancy-no-eth

# JSON output for parsing
slither . --json output.json

# Exclude dependencies and tests
slither . --filter-paths "node_modules|lib|test|script"

# Exclude specific detectors
slither . --exclude naming-convention,pragma,solc-version

# Show all available detectors
slither . --list-detectors

# Markdown report
slither . --checklist --markdown-root https://github.com/org/repo/blob/main/
```

---

## Complete Detector Reference

### Critical / High Severity

| Detector ID | Description | Impact | Confidence |
|-------------|-------------|--------|------------|
| `reentrancy-eth` | State change after ETH transfer | Fund theft | Medium |
| `arbitrary-send-eth` | Unprotected ETH transfer to arbitrary address | Fund theft | Medium |
| `arbitrary-send-erc20` | Unprotected ERC-20 transfer | Fund theft | High |
| `controlled-delegatecall` | User-controlled delegatecall target | Code injection | Medium |
| `suicidal` | Unprotected `selfdestruct` | Contract destruction | High |
| `uninitialized-state` | Storage variable never initialized | Undefined behavior | High |
| `uninitialized-storage` | Storage pointer not initialized | Data corruption | High |
| `unprotected-upgrade` | Upgradeable implementation without auth check | Proxy takeover | High |
| `delegatecall-loop` | Delegatecall inside a loop | Gas griefing or worse | Medium |

### Medium Severity

| Detector ID | Description | Impact | Confidence |
|-------------|-------------|--------|------------|
| `reentrancy-no-eth` | State change after external call (no ETH) | State corruption | Medium |
| `tx-origin` | Authentication via `tx.origin` | Auth bypass | Medium |
| `unchecked-transfer` | ERC-20 transfer without checking return | Silent failure | Medium |
| `unchecked-lowlevel` | Low-level call without checking success | Silent failure | Medium |
| `incorrect-equality` | Strict equality (`==`) with balance/supply | Manipulable | Medium |
| `locked-ether` | Contract receives ETH but can't send | Permanent lock | Medium |
| `missing-zero-check` | No check for address(0) | Fund loss | Medium |
| `reentrancy-benign` | Benign reentrancy (no impact) | Info | Medium |
| `reentrancy-events` | Events emitted after external call | Event ordering | Medium |
| `boolean-cst` | Boolean compared to constant | Logic error | High |
| `divide-before-multiply` | Division before multiplication (precision loss) | Rounding error | Medium |
| `tautology` | Tautological comparison | Dead logic | High |

### Low / Informational

| Detector ID | Description | Impact | Confidence |
|-------------|-------------|--------|------------|
| `shadowing-state` | Local variable shadows state variable | Confusion | High |
| `shadowing-local` | Local shadows function parameter | Confusion | High |
| `naming-convention` | Non-standard naming | Code quality | High |
| `pragma` | Floating pragma | Reproducibility | High |
| `solc-version` | Old or unusual Solidity version | Security patches | High |
| `dead-code` | Unreachable functions | Code quality | Medium |
| `unused-state` | State variable never used | Gas waste | High |
| `unused-return` | Return value ignored | Potential bug | Medium |
| `costly-loop` | Expensive operation inside loop | Gas DoS | Medium |
| `calls-loop` | External call inside loop | Gas DoS + reentrancy | Medium |
| `assembly` | Assembly usage | Manual review needed | High |
| `timestamp` | Block timestamp dependency | Manipulable | Medium |
| `low-level-calls` | Low-level call usage | Review needed | High |
| `encode-packed-collision` | `abi.encodePacked` with dynamic types | Hash collision | High |

---

## Custom Configuration

Create `.slither.config.json` in project root:

```json
{
  "detectors_to_run": "all",
  "exclude_informational": false,
  "exclude_low": false,
  "exclude_medium": false,
  "exclude_high": false,
  "filter_paths": "node_modules|lib|test|script|mock",
  "solc_remaps": [
    "@openzeppelin=node_modules/@openzeppelin",
    "@chainlink=node_modules/@chainlink"
  ],
  "exclude_dependencies": true
}
```

### Advanced Configuration

```json
{
  "detectors_to_exclude": "naming-convention,solc-version",
  "printers_to_run": "contract-summary",
  "solc_args": "--optimize --optimize-runs 200",
  "compile_force_framework": "foundry",
  "show_ignored_findings": false
}
```

---

## Triage Process

### Decision Framework

For each Slither finding, determine:

```
1. Is the code path reachable? → NO → FALSE POSITIVE
2. Is it exploitable in context? → NO → FALSE POSITIVE (but note design concern)
3. Is there a mitigation in place? → YES → FALSE POSITIVE (verify mitigation)
4. What is the concrete impact? → DETERMINES SEVERITY
```

### True Positive Indicators

| Indicator | Example |
|-----------|--------|
| State written after external call, no reentrancy guard | `balances[user] = 0;` after `token.transfer(user, amount)` |
| Token return value unchecked on non-SafeERC20 call | `IERC20(token).transfer(to, amount);` without `safeTransfer` |
| `tx.origin` used for authorization (not logging) | `require(tx.origin == owner)` |
| User-controlled `delegatecall` target | `address(userInput).delegatecall(data)` |
| `selfdestruct` callable by non-owner | No access modifier on function with `selfdestruct` |
| Unprotected initializer | `initialize()` without `initializer` modifier |

### Common False Positives

| Finding | Why It's FP |
|---------|------------|
| `reentrancy-eth` on view-only callback | No state to corrupt during callback |
| `arbitrary-send-eth` on `onlyOwner` function | Owner is trusted to send ETH |
| `shadowing-state` in constructor for immutable | Constructor initializes immutable, no ambiguity |
| `naming-convention` on interface | Interface follows external standard naming |
| `timestamp` on timelock delay | Timestamp use is intentional for time delays |
| `reentrancy-benign` on balance update | State change is non-critical (e.g., counter) |
| `locked-ether` on WETH wrapper | Contract intentionally holds ETH = WETH |

### Triage Template

```
| # | Detector | Contract : Function | Verdict | Reasoning |
|---|----------|--------------------|---------|-----------|
| 1 | reentrancy-eth | Vault : withdraw() | TP → HIGH | State updated after transfer, no guard |
| 2 | arbitrary-send-eth | Treasury : sweep() | FP | onlyOwner, trusted role |
| 3 | tx-origin | Auth : validate() | TP → MED | Used for auth, phishable |
| 4 | unchecked-transfer | Pool : swap() | TP → MED | Non-OZ token, return unchecked |
| 5 | naming-convention | IVault : Deposit | FP | Custom event, acceptable |
```

---

## Slither Printers (Code Analysis)

Printers generate analysis output without finding vulnerabilities. Useful for architecture understanding.

| Printer | Command | Output |
|---------|---------|--------|
| Contract summary | `--print contract-summary` | All contracts with functions, modifiers, state |
| Function summary | `--print function-summary` | Every function with visibility, modifiers, calls |
| Inheritance graph | `--print inheritance-graph` | DOT format graph of inheritance |
| Call graph | `--print call-graph` | DOT format graph of function calls |
| Storage layout | `--print variable-order` | Storage slots in order per contract |
| Data dependency | `--print data-dependency` | Which variables depend on which |
| ERC conformance | `--print erc-conformance` | Checks standard compliance |
| Human summary | `--print human-summary` | Overview: SLOC, § functions, complexity |
| Modifiers | `--print modifiers` | Modifier usage across functions |

### Useful Printer Workflows

```bash
# Quick protocol overview
slither . --print human-summary --filter-paths "node_modules|lib|test"

# Storage layout for upgrade review
slither . --print variable-order --filter-paths "node_modules|lib|test"

# Generate call graph for architecture analysis
slither . --print call-graph --filter-paths "node_modules|lib|test"
# Output: .dot files → convert with Graphviz: dot -Tpng CallGraph.dot -o callgraph.png

# Check ERC compliance
slither . --print erc-conformance
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Slither Analysis
on: [push, pull_request]
jobs:
  slither:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: crytic/slither-action@v0.4.0
        with:
          target: '.'
          slither-args: '--filter-paths "node_modules|lib|test" --exclude naming-convention'
          fail-on: 'high'
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit
slither . --filter-paths "node_modules|lib|test" --exclude-informational --exclude-low 2>&1
if [ $? -ne 0 ]; then
    echo "Slither found issues. Fix before committing."
    exit 1
fi
```

---

## Integration with Manual Review

| Phase | Action |
|-------|--------|
| 1. Run Slither | Generate full findings list |
| 2. Triage | Mark each as TP / FP with reasoning |
| 3. Prioritize manual review | Start manual review where Slither found issues |
| 4. Look for what Slither misses | Business logic, economics, cross-contract, oracle manipulation |
| 5. Re-run after fixes | Verify fixes don't introduce new issues |
2. Triage all High/Medium findings
3. Use findings to prioritize manual review areas
4. Re-run after reviewing fixes
5. Document false positives with reasoning
