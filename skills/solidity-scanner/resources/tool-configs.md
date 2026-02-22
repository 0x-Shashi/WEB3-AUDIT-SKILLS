# Static Analysis Tool Configurations

## Slither
```yaml
# slither.config.json
{
  "detectors_to_exclude": "naming-convention,solc-version",
  "exclude_informational": false,
  "exclude_low": false,
  "filter_paths": "node_modules|lib",
  "solc_remaps": ["@openzeppelin/=lib/openzeppelin-contracts/"]
}
```

### Key Detectors
| Detector | Severity | Description |
|----------|----------|-------------|
| reentrancy-eth | HIGH | Reentrancy with ETH transfer |
| reentrancy-no-eth | MEDIUM | Reentrancy without ETH |
| uninitialized-state | HIGH | Uninitialized state variables |
| arbitrary-send-eth | HIGH | Arbitrary ETH send |
| suicidal | HIGH | Unprotected selfdestruct |
| unchecked-transfer | HIGH | Missing return value check |
| locked-ether | MEDIUM | Contract locks ETH |

## Aderyn (Cyfrin)
```bash
# Run Aderyn
aderyn . --output report.md

# Aderyn detects:
# - Centralization risks
# - Unsafe ERC20 operations
# - Missing zero-address checks
# - Unused state variables
```

## Mythril
```bash
# Deep symbolic analysis
myth analyze contracts/Target.sol --solc-json mythril.config.json

# Focus areas: integer overflow, unprotected selfdestruct, delegatecall
```

## 4naly3er
```bash
# Automated gas and security report
4naly3er . --output analysis.md
# Generates: Gas optimizations, low/NC findings
```

## Recommended Workflow
1. Run Slither first (fast, broad coverage)
2. Run Aderyn (Cyfrin-specific patterns)
3. Review results, filter false positives
4. Deep analysis with Mythril on flagged contracts
5. Manual review of remaining code
