# Aptos Security Considerations

## Account Model
- Resources stored under account addresses (global storage)
- `move_to`, `move_from`, `borrow_global`, `borrow_global_mut`
- Resources must have `key` ability for global storage

## Module Upgrades
- Modules can be upgraded by default
- Upgrade policy: compatible, immutable
- Check who holds upgrade authority
- Immutable modules provide strongest guarantees

## Common Aptos Issues
- Missing `acquires` annotation when accessing resources
- Capability objects (AdminCap) not properly guarded
- `signer` parameter not used for authorization
- Resource initialization conflicts
- Coin registration and transfer safety

## Aptos-Specific Checklist
- [ ] Module upgrade policy appropriate
- [ ] Capability objects secured
- [ ] Signer used for authentication
- [ ] Resource lifecycle (create, read, update, delete) correct
- [ ] Coin operations use aptos_framework correctly
