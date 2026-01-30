# Tool Configuration

Configuration files and commands for static analysis tools used in Solidity security auditing.

---

## Slither Configuration

### Basic Configuration (slither.config.json)

```json
{
  "detectors_to_exclude": [
    "naming-convention",
    "solc-version",
    "too-many-digits"
  ],
  "exclude_informational": false,
  "exclude_low": false,
  "exclude_medium": false,
  "exclude_high": false,
  "exclude_dependencies": true,
  "filter_paths": [
    "node_modules",
    "lib",
    "test"
  ],
  "solc_remaps": [
    "@openzeppelin/=node_modules/@openzeppelin/"
  ]
}
```

### Comprehensive Slither Commands

```bash
# Full analysis with all detectors
slither . --json slither-full.json

# Security-focused detectors only
slither . --detect \
  reentrancy-eth,\
  reentrancy-no-eth,\
  reentrancy-benign,\
  reentrancy-events,\
  unprotected-upgrade,\
  arbitrary-send-erc20,\
  arbitrary-send-eth,\
  controlled-delegatecall,\
  delegatecall-loop,\
  msg-value-loop,\
  suicidal,\
  uninitialized-state,\
  uninitialized-storage,\
  uninitialized-local,\
  locked-ether,\
  tx-origin,\
  unchecked-lowlevel,\
  unchecked-send,\
  unchecked-transfer

# Printers for analysis
slither . --print contract-summary
slither . --print function-summary
slither . --print modifiers
slither . --print require
slither . --print variable-order
slither . --print vars-and-auth
slither . --print call-graph
slither . --print cfg

# Human-readable summary
slither . --print human-summary
```

### Slither Custom Detector Template

```python
# custom_detector.py
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

class CustomVulnerabilityDetector(AbstractDetector):
    ARGUMENT = "custom-vulnerability"
    HELP = "Detect custom vulnerability pattern"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    
    WIKI = "https://example.com/wiki"
    WIKI_TITLE = "Custom Vulnerability"
    WIKI_DESCRIPTION = "Description of the vulnerability"
    WIKI_EXPLOIT_SCENARIO = "Attack scenario"
    WIKI_RECOMMENDATION = "How to fix"
    
    def _detect(self):
        results = []
        
        for contract in self.compilation_unit.contracts:
            for function in contract.functions:
                # Detection logic here
                if self._is_vulnerable(function):
                    info = [function, " is vulnerable\n"]
                    res = self.generate_result(info)
                    results.append(res)
        
        return results
    
    def _is_vulnerable(self, function):
        # Implement detection logic
        return False
```

---

## Foundry Configuration

### foundry.toml

```toml
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
solc = "0.8.20"
optimizer = true
optimizer_runs = 200
via_ir = false

# Testing configuration
fuzz = { runs = 10000 }
invariant = { runs = 256, depth = 500 }

# Fork configuration (for integration tests)
# eth_rpc_url = "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"

[profile.ci]
fuzz = { runs = 50000 }
invariant = { runs = 512, depth = 1000 }

[profile.deep]
fuzz = { runs = 100000 }
invariant = { runs = 1000, depth = 2000 }

[fmt]
line_length = 100
tab_width = 4
bracket_spacing = true
```

### Foundry Testing Commands

```bash
# Run all tests
forge test

# Verbose output
forge test -vvvv

# Run specific test
forge test --match-test testFunctionName

# Fuzz testing with more runs
forge test --fuzz-runs 50000

# Invariant testing
forge test --match-test invariant

# Gas report
forge test --gas-report

# Coverage
forge coverage
forge coverage --report lcov

# Fork testing
forge test --fork-url $ETH_RPC_URL

# Debug specific test
forge test --debug testFunctionName
```

### Invariant Test Template

```solidity
// test/invariants/VaultInvariant.t.sol
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../src/Vault.sol";

contract VaultHandler is Test {
    Vault public vault;
    
    constructor(Vault _vault) {
        vault = _vault;
    }
    
    function deposit(uint256 amount) public {
        amount = bound(amount, 1, 1e24);
        deal(address(this), amount);
        vault.deposit{value: amount}();
    }
    
    function withdraw(uint256 amount) public {
        uint256 balance = vault.balanceOf(address(this));
        amount = bound(amount, 0, balance);
        if (amount > 0) {
            vault.withdraw(amount);
        }
    }
}

contract VaultInvariantTest is Test {
    Vault public vault;
    VaultHandler public handler;
    
    function setUp() public {
        vault = new Vault();
        handler = new VaultHandler(vault);
        
        targetContract(address(handler));
    }
    
    function invariant_totalAssetsGteTotalSupply() public {
        assertGe(
            address(vault).balance,
            vault.totalSupply(),
            "Total assets must be >= total supply"
        );
    }
    
    function invariant_solvency() public {
        assertGe(
            vault.totalAssets(),
            vault.totalLiabilities(),
            "Protocol must be solvent"
        );
    }
}
```

---

## Echidna Configuration

### echidna.yaml

```yaml
# Test configuration
testMode: assertion  # property, assertion, optimization
testLimit: 50000
seqLen: 100
shrinkLimit: 5000

# Corpus settings
corpusDir: "corpus"

# Coverage
coverage: true
coverageFormats: ["html", "txt"]

# Contract settings
contractAddr: "0x00a329c0648769A73afAc7F9381E08FB43dBEA72"
deployer: "0x30000"
sender: ["0x10000", "0x20000", "0x30000"]

# Multi-abi mode
allContracts: true

# Prefix for test functions
prefix: "echidna_"

# Filter functions
filterFunctions: []
filterBlacklist: true

# Execution settings
workers: 4
timeout: 300

# Logging
quiet: false
format: "text"
```

### Echidna Test Template

```solidity
// test/echidna/VaultEchidna.sol
pragma solidity ^0.8.20;

import "../../src/Vault.sol";

contract VaultEchidna is Vault {
    address internal echidna_caller = msg.sender;
    
    constructor() {
        // Initial state setup
    }
    
    // Property: total supply never exceeds max
    function echidna_max_supply() public view returns (bool) {
        return totalSupply() <= MAX_SUPPLY;
    }
    
    // Property: user cannot withdraw more than deposited
    function echidna_no_free_money() public view returns (bool) {
        return balanceOf(echidna_caller) <= totalDeposits[echidna_caller];
    }
    
    // Property: contract should always have enough balance
    function echidna_solvency() public view returns (bool) {
        return address(this).balance >= totalSupply();
    }
    
    // Assertion-based test
    function test_deposit_increases_balance(uint256 amount) public {
        uint256 balanceBefore = balanceOf(msg.sender);
        
        if (amount > 0 && amount < type(uint128).max) {
            try this.deposit{value: amount}() {
                assert(balanceOf(msg.sender) > balanceBefore);
            } catch {
                // Deposit can fail for valid reasons
            }
        }
    }
}
```

### Echidna Commands

```bash
# Run with config
echidna . --contract VaultEchidna --config echidna.yaml

# Quick run
echidna . --contract VaultEchidna --test-limit 10000

# With coverage
echidna . --contract VaultEchidna --coverage

# Multi-contract mode
echidna . --all-contracts --test-limit 50000
```

---

## Semgrep Configuration

### .semgrep.yml

```yaml
rules:
  - id: reentrancy-eth
    patterns:
      - pattern: |
          $TARGET.call{value: $VALUE}($DATA);
          ...
          $VAR = $EXPR;
    message: "Potential reentrancy: state change after external call"
    languages: [solidity]
    severity: ERROR
    metadata:
      category: security
      cwe: "CWE-841"
  
  - id: unprotected-selfdestruct
    pattern: selfdestruct($ADDR)
    message: "Unprotected selfdestruct found"
    languages: [solidity]
    severity: ERROR
  
  - id: tx-origin-auth
    patterns:
      - pattern: require(tx.origin == $ADDR, ...)
      - pattern: if (tx.origin == $ADDR) { ... }
    message: "tx.origin used for authentication - vulnerable to phishing"
    languages: [solidity]
    severity: WARNING
  
  - id: unchecked-call
    patterns:
      - pattern: $TARGET.call{...}($DATA);
      - pattern-not: |
          (bool $SUCCESS, ...) = $TARGET.call{...}($DATA);
          require($SUCCESS, ...);
    message: "Unchecked return value of low-level call"
    languages: [solidity]
    severity: WARNING
  
  - id: arbitrary-delegatecall
    patterns:
      - pattern: |
          function $FUNC(..., address $TARGET, ...) {
            ...
            $TARGET.delegatecall($DATA);
            ...
          }
    message: "Delegatecall with user-controlled target"
    languages: [solidity]
    severity: ERROR
```

### Semgrep Commands

```bash
# Run with config
semgrep --config .semgrep.yml .

# Use community rules
semgrep --config "p/smart-contracts" .

# Multiple rule sets
semgrep --config "p/smart-contracts" --config .semgrep.yml .

# JSON output
semgrep --config .semgrep.yml --json -o semgrep-output.json .

# Verbose with metrics
semgrep --config .semgrep.yml --verbose --metrics=on .
```

---

## Mythril Configuration

### Basic Commands

```bash
# Analyze single file
myth analyze contracts/Vault.sol

# With timeout
myth analyze --execution-timeout 300 contracts/Vault.sol

# Specific checks
myth analyze --modules ether,delegatecall contracts/Vault.sol

# Verbose output
myth analyze -v 4 contracts/Vault.sol

# JSON output
myth analyze --json contracts/Vault.sol > mythril-output.json

# On-chain analysis
myth analyze --rpc infura-mainnet -a 0x CONTRACT_ADDRESS
```

### Mythril Docker

```bash
# Using Docker
docker run -v $(pwd):/src mythril/myth analyze /src/contracts/Vault.sol
```

---

## Combined Analysis Script

### analyze.sh

```bash
#!/bin/bash

# Combined static analysis script
set -e

echo "=== Starting Security Analysis ==="
echo ""

# Create output directory
mkdir -p analysis-output

# 1. Slither
echo "Running Slither..."
slither . --json analysis-output/slither.json 2>/dev/null || true
slither . --print human-summary > analysis-output/slither-summary.txt 2>/dev/null

# 2. Foundry Tests
echo "Running Foundry Tests..."
forge test --gas-report > analysis-output/forge-tests.txt 2>&1 || true

# 3. Foundry Coverage
echo "Running Coverage..."
forge coverage > analysis-output/coverage.txt 2>&1 || true

# 4. Semgrep
echo "Running Semgrep..."
semgrep --config "p/smart-contracts" --json -o analysis-output/semgrep.json . 2>/dev/null || true

# 5. Summary
echo ""
echo "=== Analysis Complete ==="
echo "Results in analysis-output/"
echo ""
echo "Files generated:"
ls -la analysis-output/
```

### PowerShell Version (analyze.ps1)

```powershell
# Combined static analysis script for Windows
$ErrorActionPreference = "Continue"

Write-Host "=== Starting Security Analysis ===" -ForegroundColor Green

# Create output directory
New-Item -ItemType Directory -Force -Path analysis-output | Out-Null

# 1. Slither
Write-Host "Running Slither..." -ForegroundColor Yellow
slither . --json analysis-output/slither.json 2>$null
slither . --print human-summary > analysis-output/slither-summary.txt 2>$null

# 2. Foundry Tests
Write-Host "Running Foundry Tests..." -ForegroundColor Yellow
forge test --gas-report > analysis-output/forge-tests.txt 2>&1

# 3. Foundry Coverage
Write-Host "Running Coverage..." -ForegroundColor Yellow
forge coverage > analysis-output/coverage.txt 2>&1

# 4. Semgrep
Write-Host "Running Semgrep..." -ForegroundColor Yellow
semgrep --config "p/smart-contracts" --json -o analysis-output/semgrep.json . 2>$null

Write-Host ""
Write-Host "=== Analysis Complete ===" -ForegroundColor Green
Write-Host "Results in analysis-output/"
Get-ChildItem analysis-output/
```

---

## Tool Installation

### One-liner installs

```bash
# Slither
pip install slither-analyzer

# Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Echidna (Linux)
curl -L https://github.com/crytic/echidna/releases/latest/download/echidna-x86_64-linux.tar.gz | tar xz

# Mythril
pip install mythril

# Semgrep
pip install semgrep
```

### Windows (using Chocolatey/scoop)

```powershell
# Install scoop first if not present
# irm get.scoop.sh | iex

# Foundry
scoop install foundry

# Python tools
pip install slither-analyzer mythril semgrep

# Echidna - download from releases
# https://github.com/crytic/echidna/releases
```

