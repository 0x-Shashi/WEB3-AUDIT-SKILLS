# Static Analysis Skill

## Purpose
Integrate automated static analysis tools (Slither, Mythril, Aderyn) into the audit workflow to catch low-hanging vulnerabilities before manual review.

## Detection Capabilities
- Reentrancy (all variants)
- Unchecked external calls
- Uninitialized storage pointers
- Shadowed state variables
- Dangerous delegatecall usage
- tx.origin authentication
- Hardcoded gas amounts
- Floating pragma
- Missing zero-address checks
- Unused return values

## Tool Integration
| Tool | Strength | Speed |
|------|----------|-------|
| Slither | Broad detection, low FP | Fast |
| Mythril | Symbolic execution | Slow |
| Aderyn | Rust-based, modern | Fast |
| Semgrep | Custom rules | Fast |

## Resources
- [Slither Guide](resources/slither-guide.md)

## Workflows
- [Static Analysis](workflows/static-analysis.md)
