# Anchor Program Audit Workflow

## Steps
1. **Setup**: Identify Anchor version, dependencies, and program structure
2. **Account Validation**: Review all `#[derive(Accounts)]` structs for constraints
3. **Instruction Logic**: Review each instruction handler for business logic bugs
4. **CPI Analysis**: Trace all cross-program invocations
5. **PDA Verification**: Validate all PDA seed derivations
6. **Math Review**: Check all arithmetic for overflow/underflow
7. **State Transitions**: Verify state machine correctness
8. **Access Control**: Ensure signer checks on all privileged instructions
9. **Token Operations**: Validate SPL token interactions
10. **Report**: Document findings with severity and fix recommendations
