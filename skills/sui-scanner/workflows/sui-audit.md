# Sui Audit Workflow

## Steps
1. **Module mapping**: List all modules, structs, and public functions
2. **Object model**: Classify all objects (owned/shared/immutable/wrapped)
3. **Access control**: Verify TxContext.sender checks on privileged functions
4. **Dynamic fields**: Check for unbounded growth
5. **Object lifecycle**: Trace creation, transfer, wrapping, unwrapping, and deletion
6. **UpgradeCap**: Verify upgrade capability is properly secured
7. **OTW pattern**: Check init functions use One-Time Witness
8. **Transfer policies**: Verify public_transfer vs internal transfer usage
9. **Math review**: Check integer operations for overflow
10. **Report**: Document findings with Sui-specific context
