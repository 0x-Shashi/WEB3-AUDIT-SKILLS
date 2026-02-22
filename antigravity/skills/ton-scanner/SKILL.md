# TON Scanner Skill

## Purpose
Analyze TON (The Open Network) smart contracts written in FunC/Tact for security vulnerabilities.

## Detection Capabilities
- Message handling vulnerabilities (bounce, non-bounce)
- Gas management issues (out of gas in message chain)
- Storage fee attacks (bloating contract storage)
- Missing replay protection in messages
- Incorrect cell serialization/deserialization
- Sharding-related race conditions
- Workchain ID validation

## Resources
- [TON Patterns](resources/ton-patterns.md)

## Workflows
- [TON Audit](workflows/ton-audit.md)
