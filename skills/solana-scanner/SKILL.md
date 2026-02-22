# Solana Scanner Skill

## Purpose
Analyze Solana programs (Rust/Anchor) for security vulnerabilities.

## Detection Capabilities
- Missing account validation (owner, signer, type, seeds)
- PDA derivation errors (wrong seeds, bump validation)
- CPI (Cross-Program Invocation) privilege escalation
- Integer overflow in release mode (unchecked arithmetic)
- Account closing vulnerabilities (revival attacks)
- Duplicate account injection
- Type confusion / deserialization attacks
- Signer checks missing on privileged operations

## Workflows
- [Anchor Audit](workflows/anchor-audit.md) - Anchor framework programs
- [Native Audit](workflows/native-audit.md) - Native Solana programs

## Resources
- [Account Validation](resources/account-validation.md)
- [Anchor Security](resources/anchor-security.md)
- [Solana Patterns](resources/solana-patterns.md)
