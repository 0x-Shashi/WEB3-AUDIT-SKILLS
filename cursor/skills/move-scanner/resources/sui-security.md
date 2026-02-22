# Sui Security Considerations

## Object Model (Different from Aptos!)
- Objects instead of account-based resources
- Owned, shared, immutable, wrapped objects
- Owned objects = parallel execution (fast)
- Shared objects = consensus required (slower)

## Common Sui Issues
- Shared object contention (performance DoS)
- Dynamic field overflow (unbounded growth)
- Missing TxContext sender validation
- Object wrapping/unwrapping logic errors
- UpgradeCap not properly secured
- One-Time Witness not used for singleton init

## Sui-Specific Checklist
- [ ] Object ownership model correct
- [ ] Shared objects only where necessary
- [ ] Dynamic fields bounded
- [ ] TxContext.sender checked for access control
- [ ] UpgradeCap secured or burned
- [ ] One-Time Witness for initialization
