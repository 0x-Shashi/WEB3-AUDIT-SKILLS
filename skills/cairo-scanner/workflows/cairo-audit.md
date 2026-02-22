# Cairo Audit Workflow

## Steps
1. **Contract Structure**: Map components, traits, and storage variables
2. **Access Control**: Check all external functions for caller validation
3. **Felt Arithmetic**: Review all math operations for overflow/wrapping
4. **Storage Safety**: Verify no storage address collisions
5. **Upgrade Path**: Check `replace_class_syscall` protection
6. **L1-L2 Messaging**: Validate message handling and replay protection
7. **Reentrancy**: Check cross-contract call patterns
8. **Events**: Verify important state changes emit events
9. **Account Abstraction**: If account contract, validate `__validate__` logic
10. **Report**: Document findings with Cairo-specific context
