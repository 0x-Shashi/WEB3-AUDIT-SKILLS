# Compliance Audit Workflow

## Steps
1. **Identify standards**: List all EIPs/ERCs the protocol claims compliance with
2. **Interface check**: Verify all required functions are implemented
3. **Behavior check**: Verify each function behaves per specification
4. **Event check**: Verify correct events emitted at correct times
5. **Edge cases**: Test boundary conditions specified in the standard
6. **Return values**: Verify return types and values match specification
7. **Revert conditions**: Verify correct revert behavior per standard
8. **Extension safety**: Custom extensions don't break base standard
9. **Report**: Document compliance status per function/requirement
