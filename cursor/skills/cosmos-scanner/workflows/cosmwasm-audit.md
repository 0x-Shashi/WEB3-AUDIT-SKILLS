# CosmWasm Audit Workflow

## Steps
1. **Contract Structure**: Map Instantiate/Execute/Query entry points
2. **Authorization**: Check `info.sender` validation on all Execute handlers
3. **State Management**: Review storage operations for iteration bounds
4. **Cross-Contract**: Analyze SubMessage patterns and reply handlers
5. **IBC Integration**: If IBC-enabled, validate packet handling
6. **Math Review**: Check Uint128/Uint256 arithmetic
7. **Migration**: Verify migrate entry point access control
8. **Query Safety**: Ensure queries don't enable expensive computation
9. **Admin Powers**: Assess admin/governance capabilities
10. **Report**: Document findings with Cosmos/CosmWasm context
