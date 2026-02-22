# Sui Vulnerability Patterns

## Critical
- **Object ownership bypass**: Shared object accessed without authorization
- **UpgradeCap leak**: Upgrade capability not properly secured
- **Dynamic field manipulation**: Attacker modifies object fields

## High
- **Missing sender check**: TxContext.sender not validated on privileged ops
- **OTW not used**: Module init can be replayed
- **Shared object contention**: Performance DoS via spam

## Medium
- **Object wrapping bugs**: Wrapped objects not properly unwrapped
- **Transfer policy bypass**: Using transfer instead of public_transfer
- **Clock dependency**: Time-sensitive logic with Clock shared object

## Sui Object Model Checklist
- [ ] Owned objects: only owner can access
- [ ] Shared objects: concurrent access handled
- [ ] Immutable objects: truly read-only
- [ ] Wrapped objects: lifecycle managed correctly
- [ ] Dynamic fields: bounded growth
- [ ] Object IDs: collision-free generation
