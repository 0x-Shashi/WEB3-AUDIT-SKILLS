# Fuel Audit Workflow

## Steps
1. **Contract structure**: Map contract, script, predicate, and library files
2. **Access control**: Check msg_sender() on all privileged functions
3. **Asset handling**: Verify asset ID validation and transfer logic
4. **Predicate review**: Analyze predicate conditions and edge cases
5. **Storage analysis**: Check storage key uniqueness and access
6. **Math review**: Verify integer operations use checked arithmetic
7. **UTXO model**: Understand UTXO consumption and creation patterns
8. **Script review**: Validate script-to-contract interactions
9. **Cross-contract**: Check inter-contract call safety
10. **Report**: Document findings with Fuel/Sway context
