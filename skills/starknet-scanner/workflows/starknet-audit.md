# Starknet Audit Workflow

## Steps
1. **Contract mapping**: List all contracts, components, and interfaces
2. **Storage analysis**: Map all storage variables and check for collisions
3. **Access control**: Check external functions for caller validation
4. **Felt safety**: Review all arithmetic for field element wrapping
5. **Upgrade security**: Verify replace_class_syscall protection
6. **L1-L2 messaging**: Validate message handling and replay protection
7. **Account abstraction**: If account contract, audit __validate__/__execute__
8. **Component review**: Check component interactions and storage isolation
9. **Syscall usage**: Review all syscall invocations for correctness
10. **Report**: Document findings with Starknet-specific context
