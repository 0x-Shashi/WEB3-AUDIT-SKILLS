# Aztec Audit Workflow

## Steps
1. **Contract structure**: Map public/private functions and state
2. **Privacy analysis**: Verify private data doesn't leak to public state
3. **Note management**: Check note creation, encryption, and destruction
4. **Nullifier safety**: Verify nullifiers are unique and collision-resistant
5. **Circuit review**: Check Noir circuit constraints are complete
6. **Oracle review**: Validate oracle callback data
7. **Access control**: Verify private function access restrictions
8. **State sync**: Check public/private state consistency
9. **Encryption**: Verify note encryption for correct recipients
10. **Report**: Document findings with Aztec/privacy context
