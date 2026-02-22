# Solidity Scanner Skill

## Purpose
Analyze Solidity smart contracts for security vulnerabilities across all EVM-compatible chains.

## Supported Chains
Ethereum, Arbitrum, Optimism, Base, Polygon, BSC, Avalanche, Scroll, Linea, zkSync

## Detection Capabilities
- Reentrancy (classic, cross-function, cross-contract, read-only)
- Access control (missing modifiers, tx.origin, unprotected initialize)
- Integer overflow/underflow (unchecked blocks, unsafe casting)
- External call safety (return values, delegatecall, low-level calls)
- Token handling (fee-on-transfer, rebasing, non-standard ERC-20)
- Oracle manipulation (spot price, stale price, missing validation)
- Flash loan attack vectors
- MEV/front-running exposure
- Proxy/upgrade safety (storage collisions, uninitialized)
- Gas optimization issues

## Workflows
- [Quick Scan](workflows/quick-scan.md) - Fast 15-minute vulnerability scan
- [Comprehensive Audit](workflows/comprehensive-audit.md) - Full in-depth audit
- [Competitive Audit](workflows/competitive-audit.md) - Contest/bounty focused

## Resources
- [Vulnerability Patterns](resources/vulnerability-patterns.md)
- [Severity Guide](resources/severity-guide.md)
- [Tool Configs](resources/tool-configs.md)
- [False Positives](resources/false-positives.md)

## Usage
```
1. Load Solidity contract(s)
2. Identify compiler version and dependencies
3. Select workflow (quick/comprehensive/competitive)
4. Scanner analyzes against pattern database
5. Findings classified by severity
6. Report generated
```
