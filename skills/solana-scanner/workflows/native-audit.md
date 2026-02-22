# Native Solana Program Audit Workflow

## Steps
1. **Entrypoint**: Review `process_instruction` and instruction routing
2. **Account Deserialization**: Check manual account parsing (borsh/custom)
3. **Owner Checks**: Verify every account has owner validation
4. **Signer Checks**: Verify `is_signer` on privileged accounts
5. **PDA Validation**: Check `find_program_address` and bump usage
6. **State Management**: Review pack/unpack of account data
7. **CPI Safety**: Validate `invoke` and `invoke_signed` targets
8. **Error Handling**: Check all `ProgramResult` return paths
9. **Integer Safety**: Verify `checked_*` methods used for arithmetic
10. **Account Closing**: Verify data zeroed and lamports fully drained

## Key Differences from Anchor
- No automatic account validation (must check everything manually)
- No automatic discriminator (type confusion risk higher)
- No automatic serialization (custom pack/unpack bugs possible)
- Must manually implement all security checks that Anchor provides
