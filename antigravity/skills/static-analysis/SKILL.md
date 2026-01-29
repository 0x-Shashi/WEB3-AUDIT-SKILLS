---
name: Static Analysis Integration
description: Integration guides for static analysis tools - Slither, Mythril, Semgrep, and more
version: 1.0.0
author: Web3 Security Plugin
tags: [slither, mythril, semgrep, static-analysis, automation, security-tools]
---

# Static Analysis Integration Skill

Comprehensive integration guides for static analysis tools used in smart contract security auditing.

## Capabilities

- **Slither Integration**: Detector configuration, custom detectors, triage
- **Mythril Analysis**: Symbolic execution, vulnerability detection
- **Semgrep Rules**: Custom pattern matching for smart contracts
- **Tool Orchestration**: Combined analysis workflows
- **CI/CD Integration**: Automated security checks

---

## Tool Overview

| Tool | Type | Strengths | Limitations |
|------|------|-----------|-------------|
| Slither | Static Analysis | Fast, extensible, good DeFi coverage | False positives, no symbolic execution |
| Mythril | Symbolic Execution | Deep bug finding, path exploration | Slow, state explosion |
| Semgrep | Pattern Matching | Custom rules, fast, multi-language | No semantic analysis |
| Echidna | Fuzzing | Property testing, invariants | Requires test writing |
| Foundry | Testing/Fuzzing | Fast, Solidity native | Requires test writing |

---

## Slither

### Installation

```bash
# Install via pip
pip3 install slither-analyzer

# Or via pipx (recommended)
pipx install slither-analyzer

# Verify installation
slither --version
```

### Basic Usage

```bash
# Analyze single file
slither Contract.sol

# Analyze project
slither .

# Analyze with specific solc version
slither . --solc-remaps "@openzeppelin=node_modules/@openzeppelin"

# JSON output for processing
slither . --json output.json

# Specific detectors only
slither . --detect reentrancy-eth,arbitrary-send

# Exclude detectors
slither . --exclude naming-convention,solc-version
```

### Important Detectors

| Detector | Severity | Description |
|----------|----------|-------------|
| `reentrancy-eth` | High | Reentrancy with ETH transfer |
| `reentrancy-no-eth` | Medium | Reentrancy without ETH |
| `arbitrary-send-eth` | High | Arbitrary ETH send |
| `arbitrary-send-erc20` | High | Arbitrary token transfer |
| `suicidal` | High | Unprotected selfdestruct |
| `unprotected-upgrade` | High | Anyone can upgrade |
| `controlled-delegatecall` | High | User-controlled delegatecall |
| `unchecked-transfer` | High | Unchecked ERC20 transfer |
| `tx-origin` | Medium | tx.origin for auth |
| `locked-ether` | Medium | ETH can't be withdrawn |
| `divide-before-multiply` | Medium | Precision loss |
| `incorrect-equality` | Medium | Dangerous strict equality |

### Detector Categories

```bash
# Run only high severity
slither . --filter-paths "test|mock" --exclude-informational --exclude-low --exclude-medium

# Run specific categories
slither . --detect \
  reentrancy-eth,reentrancy-no-eth,\
  arbitrary-send-eth,arbitrary-send-erc20,\
  controlled-delegatecall,suicidal,\
  unprotected-upgrade,unchecked-transfer
```

### Slither Printers

```bash
# Contract summary
slither . --print contract-summary

# Function summary
slither . --print function-summary

# Call graph
slither . --print call-graph

# Inheritance graph
slither . --print inheritance-graph

# Variables written/read
slither . --print vars-and-auth

# Human summary
slither . --print human-summary

# CFG of functions
slither . --print cfg
```

### Custom Detector Example

```python
# my_detector.py
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

class UnsafeExternalCall(AbstractDetector):
    ARGUMENT = 'unsafe-external-call'
    HELP = 'Detect unsafe external calls'
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    
    WIKI = 'https://example.com/wiki'
    WIKI_TITLE = 'Unsafe External Call'
    WIKI_DESCRIPTION = 'External calls without proper checks'
    
    def _detect(self):
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                for node in function.nodes:
                    for ir in node.irs:
                        if self._is_unsafe_external_call(ir):
                            results.append(self._create_result(function, node))
        
        return results
    
    def _is_unsafe_external_call(self, ir):
        # Detection logic
        pass
    
    def _create_result(self, function, node):
        info = [
            function, " contains unsafe external call at ",
            node, "\n"
        ]
        return self.generate_result(info)

# Usage: slither . --detect unsafe-external-call
```

### Slither Configuration File

```json
// slither.config.json
{
    "detectors_to_run": [
        "reentrancy-eth",
        "reentrancy-no-eth",
        "arbitrary-send-eth",
        "controlled-delegatecall",
        "suicidal"
    ],
    "exclude_informational": true,
    "exclude_low": false,
    "exclude_medium": false,
    "exclude_high": false,
    "filter_paths": [
        "test",
        "lib",
        "node_modules"
    ],
    "solc_remaps": [
        "@openzeppelin=node_modules/@openzeppelin"
    ]
}
```

### Triaging Slither Output

```markdown
## Slither Triage Workflow

1. **Filter False Positives**
   - Test files (--filter-paths "test")
   - Mock contracts (--filter-paths "mock")
   - Library code (--filter-paths "lib")

2. **Prioritize by Severity**
   - High: Investigate immediately
   - Medium: Review in context
   - Low/Info: Batch review

3. **Common False Positives**
   - `reentrancy-benign`: Check if state change matters
   - `low-level-calls`: Check if intentional
   - `naming-convention`: Style preference

4. **Verification Steps**
   - Read the flagged code
   - Trace the data flow
   - Write PoC if exploitable
   - Document in findings
```

---

## Mythril

### Installation

```bash
# Install via pip
pip3 install mythril

# Or via Docker
docker pull mythril/myth

# Verify installation
myth version
```

### Basic Usage

```bash
# Analyze contract
myth analyze Contract.sol

# Analyze with more execution depth
myth analyze Contract.sol --execution-timeout 300 --max-depth 50

# Analyze specific contract in file
myth analyze Contract.sol:TargetContract

# Analyze deployed contract
myth analyze --address 0x...

# JSON output
myth analyze Contract.sol -o json

# Specific vulnerability types
myth analyze Contract.sol --modules delegatecall,ether_thief
```

### Mythril Modules

| Module | Description |
|--------|-------------|
| `delegatecall` | Dangerous delegatecall |
| `ether_thief` | Unauthorized ETH withdrawal |
| `suicide` | Unprotected selfdestruct |
| `state_change_external_calls` | State changes after calls |
| `dependence_on_predictable_vars` | Block/timestamp dependence |
| `integer` | Integer overflow/underflow |
| `unchecked_retval` | Unchecked return values |
| `external_calls` | External call issues |

### Mythril Analysis Options

```bash
# Deep analysis (slow but thorough)
myth analyze Contract.sol \
    --execution-timeout 600 \
    --max-depth 100 \
    --solver-timeout 25000 \
    --strategy bfs

# Quick scan
myth analyze Contract.sol \
    --execution-timeout 60 \
    --max-depth 12 \
    --strategy dfs

# With constructor args
myth analyze Contract.sol \
    --solc-json config.json
```

### Mythril Configuration

```json
// config.json for mythril
{
    "remappings": [
        "@openzeppelin/=node_modules/@openzeppelin/"
    ],
    "optimizer": {
        "enabled": true,
        "runs": 200
    }
}
```

---

## Semgrep

### Installation

```bash
# Install via pip
pip3 install semgrep

# Or via brew
brew install semgrep

# Verify
semgrep --version
```

### Smart Contract Rules

```bash
# Run Solidity rules
semgrep --config "p/solidity"

# Run Rust rules (for Solana/Cosmos)
semgrep --config "p/rust"

# Custom rules file
semgrep --config rules.yaml .

# Output formats
semgrep --config rules.yaml . --json > results.json
semgrep --config rules.yaml . --sarif > results.sarif
```

### Custom Semgrep Rules

```yaml
# solidity-rules.yaml
rules:
  - id: unchecked-transfer
    patterns:
      - pattern: $TOKEN.transfer($TO, $AMOUNT)
      - pattern-not-inside: require($TOKEN.transfer($TO, $AMOUNT), ...)
      - pattern-not-inside: if ($TOKEN.transfer($TO, $AMOUNT)) { ... }
    message: "Unchecked transfer return value"
    languages: [solidity]
    severity: ERROR
    metadata:
      category: security
      cwe: CWE-252

  - id: tx-origin-auth
    pattern: require(tx.origin == $ADDR, ...)
    message: "Using tx.origin for authentication"
    languages: [solidity]
    severity: WARNING
    metadata:
      category: security
      cwe: CWE-477

  - id: reentrancy-pattern
    patterns:
      - pattern: |
          $CALL(...);
          ...
          $STATE = $VALUE;
      - metavariable-regex:
          metavariable: $CALL
          regex: (call|delegatecall|transfer|send)
    message: "Potential reentrancy: state change after external call"
    languages: [solidity]
    severity: ERROR

  - id: unsafe-delegatecall
    patterns:
      - pattern: $ADDR.delegatecall($DATA)
      - pattern-not: address(this).delegatecall($DATA)
    message: "Delegatecall to potentially user-controlled address"
    languages: [solidity]
    severity: ERROR

  - id: unprotected-selfdestruct
    patterns:
      - pattern: selfdestruct($ADDR)
      - pattern-not-inside: |
          function $FUNC(...) ... onlyOwner ... {
            ...
          }
    message: "Unprotected selfdestruct"
    languages: [solidity]
    severity: ERROR
```

### Semgrep for Solana (Rust)

```yaml
# solana-rules.yaml
rules:
  - id: missing-signer-check
    patterns:
      - pattern: |
          pub fn $FUNC(ctx: Context<$CTX>, ...) -> Result<()> {
            ...
          }
      - pattern-not-inside: |
          pub fn $FUNC(ctx: Context<$CTX>, ...) -> Result<()> {
            ...
            require!(ctx.accounts.$SIGNER.is_signer, ...);
            ...
          }
      - pattern-not-inside: |
          #[derive(Accounts)]
          pub struct $CTX<'info> {
            ...
            #[account(signer)]
            ...
          }
    message: "Missing signer verification"
    languages: [rust]
    severity: ERROR

  - id: missing-owner-check
    patterns:
      - pattern: |
          pub fn $FUNC(ctx: Context<$CTX>, ...) -> Result<()> {
            ...
            let $ACC = &ctx.accounts.$NAME;
            ...
          }
      - pattern-not-inside: |
          require!($ACC.owner == ..., ...);
    message: "Missing account owner check"
    languages: [rust]
    severity: WARNING
```

---

## Tool Orchestration

### Combined Analysis Script

```bash
#!/bin/bash
# full-analysis.sh

set -e

PROJECT_DIR=${1:-.}
OUTPUT_DIR="security-reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$OUTPUT_DIR"

echo "=== Running Slither ==="
slither "$PROJECT_DIR" \
    --json "$OUTPUT_DIR/slither_$TIMESTAMP.json" \
    --filter-paths "test|mock|lib" \
    2>&1 | tee "$OUTPUT_DIR/slither_$TIMESTAMP.log"

echo "=== Running Mythril ==="
find "$PROJECT_DIR/src" -name "*.sol" | while read file; do
    echo "Analyzing: $file"
    myth analyze "$file" \
        --execution-timeout 300 \
        -o json \
        >> "$OUTPUT_DIR/mythril_$TIMESTAMP.json" 2>&1 || true
done

echo "=== Running Semgrep ==="
semgrep --config "p/solidity" \
    --json \
    "$PROJECT_DIR" \
    > "$OUTPUT_DIR/semgrep_$TIMESTAMP.json" 2>&1

echo "=== Generating Summary ==="
python3 generate_summary.py "$OUTPUT_DIR" "$TIMESTAMP"

echo "Analysis complete! Reports in $OUTPUT_DIR/"
```

### Summary Generator

```python
# generate_summary.py
import json
import sys
from pathlib import Path

def load_json(file_path):
    try:
        with open(file_path) as f:
            return json.load(f)
    except:
        return None

def summarize(output_dir, timestamp):
    summary = {
        "slither": {"high": 0, "medium": 0, "low": 0, "info": 0},
        "mythril": {"high": 0, "medium": 0, "low": 0},
        "semgrep": {"error": 0, "warning": 0, "info": 0}
    }
    
    # Process Slither
    slither_data = load_json(f"{output_dir}/slither_{timestamp}.json")
    if slither_data and "results" in slither_data:
        for det in slither_data["results"].get("detectors", []):
            impact = det.get("impact", "").lower()
            if impact in summary["slither"]:
                summary["slither"][impact] += 1
    
    # Process Mythril
    mythril_data = load_json(f"{output_dir}/mythril_{timestamp}.json")
    if mythril_data:
        for issue in mythril_data.get("issues", []):
            severity = issue.get("severity", "").lower()
            if severity in summary["mythril"]:
                summary["mythril"][severity] += 1
    
    # Process Semgrep
    semgrep_data = load_json(f"{output_dir}/semgrep_{timestamp}.json")
    if semgrep_data:
        for result in semgrep_data.get("results", []):
            severity = result.get("extra", {}).get("severity", "").lower()
            if severity in summary["semgrep"]:
                summary["semgrep"][severity] += 1
    
    # Print summary
    print("\n" + "="*50)
    print("SECURITY ANALYSIS SUMMARY")
    print("="*50)
    
    for tool, counts in summary.items():
        print(f"\n{tool.upper()}:")
        for severity, count in counts.items():
            if count > 0:
                print(f"  {severity.capitalize()}: {count}")
    
    # Save summary
    with open(f"{output_dir}/summary_{timestamp}.json", "w") as f:
        json.dump(summary, f, indent=2)

if __name__ == "__main__":
    summarize(sys.argv[1], sys.argv[2])
```

---

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security Analysis

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  slither:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Foundry
        uses: foundry-rs/foundry-toolchain@v1
        
      - name: Install dependencies
        run: forge install
        
      - name: Run Slither
        uses: crytic/slither-action@v0.3.0
        with:
          node-version: 18
          sarif: results.sarif
          fail-on: high
          
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif

  mythril:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Mythril
        uses: docker://mythril/myth:latest
        with:
          args: analyze src/Contract.sol --execution-timeout 300
          
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Semgrep
        uses: returntocorp/semgrep-action@v1
        with:
          config: p/solidity
```

### Pre-commit Hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: slither-check
        name: Slither Security Check
        entry: slither
        args: ['.', '--filter-paths', 'test|mock', '--exclude-informational']
        language: python
        types: [solidity]
        pass_filenames: false

      - id: semgrep-check
        name: Semgrep Security Check
        entry: semgrep
        args: ['--config', 'p/solidity', '--error']
        language: python
        types: [solidity]
        pass_filenames: false
```

---

## Resources

- [slither-guide.md](resources/slither-guide.md) - Detailed Slither usage
- [mythril-guide.md](resources/mythril-guide.md) - Detailed Mythril usage

## Workflows

- [static-analysis.md](workflows/static-analysis.md) - Analysis workflow

---

## Best Practices

### Tool Selection

1. **Quick Review**: Slither + Semgrep (minutes)
2. **Thorough Analysis**: Add Mythril (hours)
3. **Complete Coverage**: Add Echidna/Foundry fuzzing

### False Positive Management

1. Add inline comments to suppress known FPs
2. Maintain .slitherignore for project-wide FPs
3. Document why each suppression is safe

### Integration Strategy

1. Run fast tools in CI (Slither, Semgrep)
2. Run slow tools on demand (Mythril)
3. Track findings in issue tracker
4. Require sign-off before merge
