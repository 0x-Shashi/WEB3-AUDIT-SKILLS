# Aptos Audit Workflow

## Steps
1. **Module mapping**: List all modules, structs, and public functions
2. **Ability audit**: Check `key`, `store`, `copy`, `drop` on all types
3. **Signer validation**: Verify all entry functions check signer
4. **Capability review**: Trace AdminCap/MintCap creation, storage, usage
5. **Upgrade policy**: Check module upgrade authority and policy
6. **Coin safety**: Validate coin registration, mint, burn, transfer
7. **Global storage**: Review `move_to`, `move_from`, `borrow_global` usage
8. **Friend modules**: Audit friend function access patterns
9. **Math review**: Check integer operations for overflow
10. **Report**: Document findings with Aptos-specific context
