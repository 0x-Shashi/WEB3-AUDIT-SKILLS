# Starknet-Specific Vulnerability Patterns

## Critical
- **Felt comparison bug**: Comparing negative felt values (large positive in field)
- **Unprotected class replacement**: replace_class without access control
- **Account __validate__ bypass**: Validation logic can be circumvented

## High  
- **Storage collision**: Pedersen hash of different keys produces same address
- **L1 handler spoofing**: Not validating L1 message sender
- **Reentrancy**: call_contract_syscall allows re-entry

## Medium
- **Library call misuse**: library_call_syscall to untrusted class
- **Missing events**: State changes without event emission
- **Component conflicts**: Multiple components writing same storage

## Starknet Checklist
- [ ] Felt arithmetic uses u256/u128 where appropriate
- [ ] replace_class_syscall protected by access control
- [ ] L1 handler validates message source
- [ ] Account contracts: __validate__ logic reviewed
- [ ] Component storage keys don't collide
- [ ] Critical functions have reentrancy protection
