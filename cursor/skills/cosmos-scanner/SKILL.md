# Cosmos Scanner Skill

## Purpose
Analyze Cosmos SDK modules and CosmWasm smart contracts for security vulnerabilities.

## Detection Capabilities
- IBC packet source validation
- Keeper authorization bypass
- Unbounded state iteration (gas DoS)
- Module account permission issues
- BeginBlocker/EndBlocker exploitation
- CosmWasm SubMessage reply handler bugs
- AuthZ overly broad grants
- Governance parameter manipulation

## Resources
- [CosmWasm Patterns](resources/cosmwasm-patterns.md)
- [IBC Security](resources/ibc-security.md)

## Workflows
- [CosmWasm Audit](workflows/cosmwasm-audit.md)
