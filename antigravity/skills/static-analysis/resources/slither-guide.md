# Comprehensive Slither Guide

Complete guide for using Slither static analyzer in smart contract security audits.

---

## Installation & Setup

### Installation Options

```bash
# Option 1: pip (recommended for most users)
pip3 install slither-analyzer

# Option 2: pipx (isolated environment)
pipx install slither-analyzer

# Option 3: From source (latest features)
git clone https://github.com/crytic/slither.git
cd slither
pip3 install .

# Option 4: Docker
docker pull trailofbits/slither
docker run -v $(pwd):/code trailofbits/slither /code
```

### Verify Installation

```bash
slither --version
slither --list-detectors
slither --list-printers
```

### Solc Version Management

```bash
# Install solc-select for version management
pip3 install solc-select

# Install specific version
solc-select install 0.8.19

# Use specific version
solc-select use 0.8.19

# Verify
solc --version
```

---

## Basic Commands

### Analyze a Project

```bash
# Foundry project
slither .

# Hardhat project  
slither . --hardhat-ignore-compile

# Truffle project
slither . --truffle-ignore-compile

# Single file
slither Contract.sol

# With remappings
slither . --solc-remaps "@openzeppelin=node_modules/@openzeppelin"
```

### Output Formats

```bash
# Text output (default)
slither .

# JSON output
slither . --json output.json

# SARIF output (for GitHub Security)
slither . --sarif output.sarif

# Markdown
slither . --markdown-root . > report.md

# Checklist format
slither . --checklist > checklist.md
```

### Filtering

```bash
# Filter by path
slither . --filter-paths "test|lib|node_modules"

# Include only specific contracts
slither . --include-paths "src/core"

# Exclude by severity
slither . --exclude-informational
slither . --exclude-low
slither . --exclude-medium
slither . --exclude-high
slither . --exclude-optimization

# Exclude specific detectors
slither . --exclude naming-convention,solc-version,assembly
```

---

## Detector Reference

### High Severity Detectors

| Detector | Description | False Positive Rate |
|----------|-------------|---------------------|
| `reentrancy-eth` | Reentrancy with ETH transfer | Low |
| `reentrancy-no-eth` | Reentrancy without ETH | Medium |
| `arbitrary-send-eth` | ETH sent to arbitrary address | Low |
| `arbitrary-send-erc20` | Tokens sent to arbitrary address | Low |
| `controlled-delegatecall` | User-controlled delegatecall target | Low |
| `suicidal` | Unprotected selfdestruct | Low |
| `unprotected-upgrade` | Anyone can upgrade proxy | Low |
| `unchecked-transfer` | ERC20 transfer not checked | Low |
| `weak-prng` | Weak randomness | Low |
| `codex` | AI-detected issues | Medium |

### Medium Severity Detectors

| Detector | Description | False Positive Rate |
|----------|-------------|---------------------|
| `reentrancy-benign` | Benign reentrancy | High |
| `reentrancy-events` | Reentrancy with event | Medium |
| `tx-origin` | tx.origin for auth | Low |
| `locked-ether` | ETH locked in contract | Low |
| `divide-before-multiply` | Precision loss | Low |
| `incorrect-equality` | Dangerous == check | Medium |
| `tautology` | Always true/false condition | Low |
| `shadowing-state` | State variable shadowing | Low |
| `uninitialized-state` | Uninitialized state variable | Medium |
| `uninitialized-local` | Uninitialized local variable | Medium |

### Low Severity Detectors

| Detector | Description | False Positive Rate |
|----------|-------------|---------------------|
| `calls-loop` | Calls inside loop | Medium |
| `low-level-calls` | Low-level call usage | High |
| `missing-zero-check` | Missing zero address check | Medium |
| `reentrancy-unlimited-gas` | Reentrancy with unlimited gas | Medium |
| `boolean-cst` | Boolean constant comparison | Low |
| `timestamp` | Block.timestamp usage | High |
| `assembly` | Assembly usage | High |

### Running Specific Detectors

```bash
# Run only reentrancy detectors
slither . --detect reentrancy-eth,reentrancy-no-eth,reentrancy-benign

# Run DeFi-focused detectors
slither . --detect \
  arbitrary-send-eth,arbitrary-send-erc20,\
  reentrancy-eth,reentrancy-no-eth,\
  unchecked-transfer,divide-before-multiply,\
  incorrect-equality

# Run access control focused
slither . --detect \
  suicidal,unprotected-upgrade,\
  tx-origin,controlled-delegatecall
```

---

## Printers

### Code Understanding

```bash
# Contract summary (inheritance, functions, etc.)
slither . --print contract-summary

# Function summary (visibility, modifiers)
slither . --print function-summary

# State variable summary
slither . --print vars-and-auth

# Modifier usage
slither . --print modifiers

# Constructor summary
slither . --print constructor-calls
```

### Visualization

```bash
# Call graph
slither . --print call-graph
# Generates call-graph.dot file

# Inheritance graph
slither . --print inheritance-graph

# Control flow graph
slither . --print cfg
```

### Security-Focused

```bash
# Human readable summary
slither . --print human-summary

# ERC conformance check
slither . --print erc-conformance

# Possible upgrade paths (for proxies)
slither . --print upgradeability-summary

# Data dependency
slither . --print data-dependency
```

### Convert DOT to Image

```bash
# Install graphviz
apt-get install graphviz  # Linux
brew install graphviz     # macOS

# Convert to PNG
dot -Tpng call-graph.dot -o call-graph.png

# Convert to SVG
dot -Tsvg inheritance-graph.dot -o inheritance.svg
```

---

## Configuration

### slither.config.json

```json
{
    "detectors_to_run": [
        "reentrancy-eth",
        "reentrancy-no-eth",
        "arbitrary-send-eth",
        "arbitrary-send-erc20",
        "controlled-delegatecall",
        "suicidal",
        "unprotected-upgrade",
        "unchecked-transfer",
        "locked-ether",
        "divide-before-multiply",
        "incorrect-equality"
    ],
    "printers_to_run": [],
    "detectors_to_exclude": [
        "naming-convention",
        "solc-version",
        "assembly"
    ],
    "exclude_informational": false,
    "exclude_low": false,
    "exclude_medium": false,
    "exclude_high": false,
    "exclude_optimization": true,
    "filter_paths": [
        "test/",
        "lib/",
        "node_modules/",
        "script/"
    ],
    "solc_remaps": [
        "@openzeppelin/=lib/openzeppelin-contracts/",
        "@solmate/=lib/solmate/src/"
    ],
    "compile_force_framework": "foundry"
}
```

### .slitherignore

```
# Ignore test files
test/
tests/

# Ignore mock contracts
mocks/
Mock*.sol

# Ignore external libraries
lib/
node_modules/

# Ignore scripts
script/
scripts/

# Ignore specific files
src/deprecated/OldContract.sol
```

---

## Triaging Results

### Understanding Output

```json
{
    "success": true,
    "error": null,
    "results": {
        "detectors": [
            {
                "check": "reentrancy-eth",
                "impact": "High",
                "confidence": "Medium",
                "elements": [
                    {
                        "type": "function",
                        "name": "withdraw",
                        "source_mapping": {
                            "filename": "src/Vault.sol",
                            "start": 1234,
                            "length": 200,
                            "lines": [45, 46, 47, 48, 49]
                        }
                    }
                ],
                "description": "Reentrancy in Vault.withdraw()..."
            }
        ]
    }
}
```

### Triage Process

```markdown
## Slither Triage Checklist

### Step 1: Filter Known False Positives
- [ ] Test/mock contracts filtered?
- [ ] Library code filtered?
- [ ] Known safe patterns excluded?

### Step 2: Sort by Severity
- [ ] Review all HIGH first
- [ ] Review MEDIUM second
- [ ] Batch review LOW/INFO

### Step 3: Verify Each Finding
For each finding:
- [ ] Read the flagged code
- [ ] Understand the detector logic
- [ ] Trace data/control flow
- [ ] Determine if exploitable
- [ ] Write PoC if needed
- [ ] Document decision

### Step 4: Categorize
- TRUE POSITIVE: Real bug, create finding
- FALSE POSITIVE: Safe, document why
- NEEDS REVIEW: Uncertain, investigate more
```

### Common False Positives

```markdown
## False Positive Patterns

### reentrancy-benign
Often triggers on:
- View function calls
- Events after external calls
- Non-critical state updates

Verify: Does the state change enable exploitation?

### low-level-calls
Often triggers on:
- Intentional low-level calls
- Gas-controlled sends
- Assembly optimizations

Verify: Is the low-level call intentional and safe?

### timestamp
Often triggers on:
- Any block.timestamp usage
- Time-based logic

Verify: Can timestamp manipulation cause meaningful harm?

### assembly
Often triggers on:
- All assembly blocks
- Gas optimizations
- Low-level operations

Verify: Is assembly necessary and correct?
```

### Suppression Comments

```solidity
// Suppress specific detector
// slither-disable-next-line reentrancy-benign
function safeFunction() external {
    // ...
}

// Suppress multiple
// slither-disable-next-line reentrancy-benign,low-level-calls
function anotherFunction() external {
    // ...
}

// Suppress for entire function
// slither-disable-start reentrancy-benign
function multiLineFunction() external {
    // multiple lines
    // all suppressed
}
// slither-disable-end reentrancy-benign
```

---

## Custom Detectors

### Detector Template

```python
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
)
from slither.core.declarations import Function

class CustomDetector(AbstractDetector):
    """
    Documentation for detector
    """
    
    ARGUMENT = "custom-detector"  # slither --detect custom-detector
    HELP = "One-line description"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    
    WIKI = "https://github.com/example/wiki"
    WIKI_TITLE = "Custom Detector Title"
    WIKI_DESCRIPTION = "Detailed description of what this detects"
    WIKI_EXPLOIT_SCENARIO = """
    Example exploit scenario
    """
    WIKI_RECOMMENDATION = "How to fix this issue"
    
    def _detect(self) -> list:
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if self._is_vulnerable(function):
                    info = self._create_info(function)
                    res = self.generate_result(info)
                    results.append(res)
        
        return results
    
    def _is_vulnerable(self, function: Function) -> bool:
        # Detection logic
        return False
    
    def _create_info(self, function: Function) -> list:
        return [
            function,
            " is vulnerable to X\n",
        ]
```

### Example: Detect Missing Access Control

```python
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
)
from slither.slithir.operations import SolidityCall

class MissingAccessControl(AbstractDetector):
    ARGUMENT = "missing-access-control"
    HELP = "Detect critical functions without access control"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    
    WIKI = "https://example.com"
    WIKI_TITLE = "Missing Access Control"
    WIKI_DESCRIPTION = "Critical functions should have access control"
    WIKI_RECOMMENDATION = "Add onlyOwner or similar modifier"
    
    CRITICAL_FUNCTIONS = ["withdraw", "pause", "unpause", "upgrade", "setFee"]
    
    def _detect(self):
        results = []
        
        for contract in self.compilation_unit.contracts_derived:
            for function in contract.functions:
                if self._is_vulnerable(function):
                    info = [
                        function,
                        " is a critical function without access control\n"
                    ]
                    results.append(self.generate_result(info))
        
        return results
    
    def _is_vulnerable(self, function):
        # Check if function name matches critical patterns
        if not any(cf in function.name.lower() for cf in self.CRITICAL_FUNCTIONS):
            return False
        
        # Check if external/public
        if function.visibility not in ["external", "public"]:
            return False
        
        # Check for access control modifiers
        access_modifiers = ["onlyOwner", "onlyAdmin", "onlyRole", "auth"]
        for modifier in function.modifiers:
            if any(am in modifier.name for am in access_modifiers):
                return False
        
        # Check for require with msg.sender
        for node in function.nodes:
            if any("msg.sender" in str(ir) and "require" in str(node) 
                   for ir in node.irs):
                return False
        
        return True
```

### Running Custom Detectors

```bash
# Single plugin file
slither . --detect custom-detector --solc-plugin ./custom_detector.py

# Plugin directory
slither . --plugin-path ./my_detectors/
```

---

## Integration with Foundry

### foundry.toml Configuration

```toml
[profile.default]
src = 'src'
out = 'out'
libs = ['lib']
remappings = [
    '@openzeppelin/=lib/openzeppelin-contracts/',
    '@solmate/=lib/solmate/src/'
]

# For slither compatibility
build_info = true
extra_output = ['storageLayout']
```

### Run Slither on Foundry Project

```bash
# Compile first
forge build

# Run slither
slither . --compile-force-framework foundry

# With foundry profile
FOUNDRY_PROFILE=default slither .
```

---

## Integration with Hardhat

### hardhat.config.js

```javascript
module.exports = {
    solidity: "0.8.19",
    networks: {
        hardhat: {}
    },
    paths: {
        sources: "./contracts",
        tests: "./test",
        cache: "./cache",
        artifacts: "./artifacts"
    }
};
```

### Run Slither on Hardhat Project

```bash
# With compilation
slither .

# Skip compilation
slither . --hardhat-ignore-compile

# Cache artifacts
slither . --hardhat-cache-directory ./cache
```

---

## Reporting

### Generate Markdown Report

```bash
# Basic markdown
slither . --checklist > checklist.md

# With triage notes
slither . --json - | python3 slither_report.py > report.md
```

### Report Generator Script

```python
#!/usr/bin/env python3
# slither_report.py

import json
import sys

def generate_report(data):
    print("# Slither Security Analysis Report\n")
    print("## Summary\n")
    
    findings = data.get("results", {}).get("detectors", [])
    
    # Count by severity
    counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in findings:
        impact = f.get("impact", "Informational")
        counts[impact] = counts.get(impact, 0) + 1
    
    print("| Severity | Count |")
    print("|----------|-------|")
    for sev, count in counts.items():
        print(f"| {sev} | {count} |")
    
    print("\n## Findings\n")
    
    for i, finding in enumerate(findings, 1):
        print(f"### [{finding['impact'][0]}-{i:02d}] {finding['check']}\n")
        print(f"**Severity**: {finding['impact']}")
        print(f"**Confidence**: {finding['confidence']}\n")
        print(finding['description'])
        print("\n**Location**:")
        for elem in finding.get('elements', []):
            sm = elem.get('source_mapping', {})
            if sm:
                print(f"- {sm.get('filename')}:{sm.get('lines', [0])[0]}")
        print()

if __name__ == "__main__":
    data = json.load(sys.stdin)
    generate_report(data)
```

---

## Best Practices

### Pre-Audit Setup

1. Configure solc version correctly
2. Set up remappings
3. Filter test/mock files
4. Run printers to understand codebase

### During Audit

1. Run all detectors first
2. Triage systematically by severity
3. Verify each finding manually
4. Write PoC for confirmed issues

### Post-Audit

1. Document all suppressions
2. Add to CI/CD pipeline
3. Update slither.config.json
4. Share false positive patterns

