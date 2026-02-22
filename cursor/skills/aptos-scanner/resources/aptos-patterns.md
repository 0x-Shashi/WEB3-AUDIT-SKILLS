# Aptos Vulnerability Patterns

## Critical
- **Capability leak**: AdminCap/MintCap accessible by unauthorized users
- **Missing signer**: Public function modifies state without signer check
- **Coin registration**: Incorrect CoinType registration allowing fake coins

## High
- **Module upgrade**: Upgrade authority not restricted or transferable
- **Resource move_from**: Extracting resources without proper authorization
- **Table overflow**: Unbounded Table growth causes gas issues

## Medium
- **Event ordering**: Events emitted in wrong order for indexers
- **Acquires missing**: Function accesses global storage without annotation
- **Friend abuse**: Friend modules bypass intended access restrictions

## Aptos-Specific Checklist
- [ ] All public entry functions validate signer
- [ ] Capability objects stored securely (not in shared resources)
- [ ] Module upgrade policy set appropriately (immutable if possible)
- [ ] Coin operations use aptos_framework::coin correctly
- [ ] Table/SmartTable growth bounded
- [ ] Resource initialization checked before access
