# Frequently Asked Questions

## General

### What is Web3 Audit Skills?
A comprehensive AI-powered smart contract security audit toolkit that provides vulnerability detection patterns, protocol-specific checklists, attack chain analysis, and audit report generation across multiple blockchain platforms.

### What blockchains are supported?
- **EVM**: Ethereum, Arbitrum, Optimism, Base, Polygon, BSC, Avalanche, Scroll, Linea, zkSync
- **Non-EVM**: Solana, Cosmos/CosmWasm, Sui, Aptos, StarkNet, TON, Fuel, Aztec

### What AI platforms does this work with?
- **Claude Code** (Anthropic)
- **Cursor** (AI-enhanced IDE)
- **Antigravity** (Plugin system)

## Usage

### How do I start an audit?
1. Load the skills into your AI platform
2. Describe the protocol type (lending, DEX, bridge, etc.)
3. The system auto-selects appropriate checklists and scanners
4. Follow the skill chain (Quick Scan → Deep Dive → Full Audit)

### What's the difference between Quick Scan, Deep Dive, and Full Audit?
| Mode | Duration | Coverage | Use Case |
|------|----------|----------|----------|
| Quick Scan | 1-2 hours | Surface | Triage, initial assessment |
| Deep Dive | 1-2 days | Focused | Specific module analysis |
| Full Audit | 1-2 weeks | Complete | Full engagement |

### How are severities determined?
Severity follows a standardized framework:
- **Critical**: Direct fund loss, no user interaction needed
- **High**: Fund loss with conditions, or governance takeover
- **Medium**: Conditional fund loss, value leak, griefing
- **Low**: Best practice violations, informational

### Can I customize the checklists?
Yes. All checklists are markdown files. Add, remove, or modify items to match your audit methodology.

## Technical

### How does pattern matching work?
The intelligence module compares code against 200+ known vulnerability patterns extracted from real-world exploits and audit findings from Cyfrin, Code4rena, Sherlock, and Cantina.

### What static analysis tools are integrated?
- **Slither** (Trail of Bits) — Fast, broad detection
- **Mythril** (ConsenSys) — Symbolic execution
- **Aderyn** (Cyfrin) — Rust-based, modern detection

### How is the Cyfrin findings database used?
Historical findings are searchable by vulnerability type, protocol category, and severity. Use them for:
- Pre-audit research on similar protocols
- Variant analysis (find all instances of a pattern)
- Learning from past exploits

## Troubleshooting

### Skills not loading?
- Verify the skills directory path is correct
- Check that SKILL.md files exist in each skill directory
- Ensure INDEX.md maps to all available skills

### Pattern matching returning too many false positives?
- Use the false-positives guide in static-analysis/resources/
- Triage with context — many patterns need manual verification
- Focus on High/Critical findings first
