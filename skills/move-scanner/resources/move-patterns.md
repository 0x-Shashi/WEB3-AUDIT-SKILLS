# Move Vulnerability Patterns

## Critical
- **Capability leak**: AdminCap or MintCap stored in accessible location
- **Missing signer check**: Function doesn't validate caller identity
- **Resource duplication**: copy ability on value-holding resources

## High
- **Module upgrade**: Unprotected upgrade authority
- **Friend function abuse**: Friend modules can bypass internal logic
- **Integer overflow**: Move integers wrap on overflow without abort

## Medium
- **Missing abort codes**: Generic aborts make debugging difficult
- **Acquires missing**: Resource access without proper annotation
- **Event emission**: State changes without corresponding events

## Move Type System Security
- `key`: Required for global storage (Aptos) or objects (Sui)
- `store`: Can be stored inside other resources
- `copy`: Can be duplicated (DANGEROUS for value types)
- `drop`: Can be discarded (CAREFUL with capabilities)
