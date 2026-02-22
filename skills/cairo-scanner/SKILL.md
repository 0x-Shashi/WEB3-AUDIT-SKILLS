# Cairo Scanner Skill

## Purpose
Analyze Cairo smart contracts for Starknet security vulnerabilities.

## Detection Capabilities
- Felt arithmetic overflow/underflow (field element wrapping)
- Missing access control on `replace_class_syscall`
- Storage address collisions
- Reentrancy via `call_contract_syscall`
- L1-L2 message replay
- Account abstraction validation flaws
- Component interaction vulnerabilities

## Resources
- [Cairo Patterns](resources/cairo-patterns.md)
- [Starknet Security](resources/starknet-security.md)
- [Messaging Security](resources/messaging-security.md)

## Workflows
- [Cairo Audit](workflows/cairo-audit.md)
