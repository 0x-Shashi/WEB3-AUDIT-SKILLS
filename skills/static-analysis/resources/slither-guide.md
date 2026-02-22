# Slither Configuration & Usage Guide

## Installation
```bash
pip install slither-analyzer
# or
pipx install slither-analyzer
```

## Basic Usage
```bash
# Run all detectors
slither .

# Run specific detector
slither . --detect reentrancy-eth,reentrancy-no-eth

# JSON output for parsing
slither . --json output.json

# Exclude dependencies
slither . --filter-paths "node_modules|lib"
```

## Key Detectors by Severity

### High
| Detector | ID | Description |
|----------|----|-------------|
| Reentrancy (ETH) | `reentrancy-eth` | State change after ETH transfer |
| Arbitrary send | `arbitrary-send-eth` | Unprotected ETH transfer |
| Suicidal | `suicidal` | Unprotected selfdestruct |
| Uninitialized state | `uninitialized-state` | Storage vars not initialized |
| Controlled delegatecall | `controlled-delegatecall` | User-controlled delegatecall target |

### Medium
| Detector | ID | Description |
|----------|----|-------------|
| Reentrancy (no ETH) | `reentrancy-no-eth` | State change after external call (no ETH) |
| Tx.origin | `tx-origin` | Authentication via tx.origin |
| Unchecked transfer | `unchecked-transfer` | ERC20 transfer without return check |
| Dangerous strict equality | `incorrect-equality` | `==` with balance/supply |
| Locked ether | `locked-ether` | Contract receives ETH but can't send |

### Low / Informational
| Detector | ID | Description |
|----------|----|-------------|
| Shadowing state | `shadowing-state` | Local shadows state variable |
| Missing zero check | `missing-zero-check` | No zero-address validation |
| Naming convention | `naming-convention` | Non-standard naming |
| Pragma version | `pragma` | Floating pragma |
| Dead code | `dead-code` | Unreachable functions |

## Custom Configuration (.slither.config.json)
```json
{
  "detectors_to_run": "all",
  "exclude_informational": false,
  "exclude_low": false,
  "filter_paths": "node_modules|lib|test",
  "solc_remaps": [
    "@openzeppelin=node_modules/@openzeppelin"
  ]
}
```

## Triage Process

### True Positive Indicators
- State change after external call with no reentrancy guard
- `transfer`/`transferFrom` return value unchecked on non-OZ tokens
- `tx.origin` used for authentication (not just logging)
- User-controlled `delegatecall` target address

### Common False Positives
- Reentrancy on view-only callbacks
- "Arbitrary send" on owner-only withdraw functions
- Shadowing in constructors for immutable values
- Naming convention on interface implementations

## Slither Printers (Code Analysis)
```bash
# Call graph
slither . --print call-graph

# Contract summary
slither . --print contract-summary

# Function summary with modifiers
slither . --print function-summary

# Inheritance graph
slither . --print inheritance-graph

# Variable ordering (storage layout)
slither . --print variable-order
```

## Integration with Audit Workflow
1. Run Slither FIRST on new codebase
2. Triage all High/Medium findings
3. Use findings to prioritize manual review areas
4. Re-run after reviewing fixes
5. Document false positives with reasoning
