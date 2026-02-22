# Security Policy

## Scope
This document covers the security considerations for the Web3 Audit Skills project itself, not the smart contracts it helps audit.

## Responsible Disclosure
If you discover a security vulnerability in this project, please report it responsibly:
- **Email**: Open a GitHub Security Advisory on the repository
- **Do NOT** open a public issue for security vulnerabilities
- Allow 90 days for remediation before public disclosure

## Security Considerations

### Skill Content Integrity
- All vulnerability patterns and checklists are reviewed for accuracy
- Incorrect patterns could cause false negatives (missing real vulnerabilities)
- Community contributions are reviewed before merging
- Pattern sources are cited for verification

### API Key Management
- Solodit API keys should never be committed to the repository
- Use environment variables for API credentials
- The `.env` file is in `.gitignore`

### Dependency Security
- Core module dependencies are minimal (`@modelcontextprotocol/sdk` only)
- Dependencies are regularly audited for known vulnerabilities
- Use `npm audit` to check for issues

### Data Privacy
- No user code is stored or transmitted by the skills system
- Pattern matching happens locally within the AI platform
- Cyfrin findings queries use public API endpoints only
- No telemetry or usage tracking

## Limitations
This tool assists with security auditing but does NOT guarantee:
- Complete vulnerability coverage
- Zero false negatives
- Correctness of all patterns
- That following all checklists makes a contract secure

Smart contract security auditing requires human expertise. This tool augments but does not replace professional auditors.

## Updates
- Vulnerability patterns are updated as new exploits are discovered
- Chain guides are updated when chain-specific security properties change
- Checklists are refined based on community feedback and new attack vectors

## License
MIT - This project is provided as-is with no warranty. See LICENSE for details.
