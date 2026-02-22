# Move Audit Workflow

## Steps
1. **Module Structure**: Map modules, structs, and public functions
2. **Ability Analysis**: Check abilities (key, store, copy, drop) on all types
3. **Access Control**: Verify signer checks and capability management
4. **Resource Lifecycle**: Trace create/read/update/delete for all resources
5. **Module Upgrades**: Check upgrade policy and authority
6. **Friend Functions**: Audit friend module interactions
7. **Math Review**: Check integer arithmetic for overflow
8. **Platform-Specific**: Apply Aptos or Sui specific checks
9. **Events**: Verify event emission for state changes
10. **Report**: Document findings with Move-specific context
