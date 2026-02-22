# Web3 Audit Skills - Cursor Integration

## Overview
Cursor IDE integration for the Web3 Audit Skills system. This provides comprehensive smart contract security audit capabilities directly within Cursor's AI-assisted development environment.

## Installation
1. Clone this repository into your Cursor workspace
2. Skills in the `skills/` directory are automatically available to Cursor's AI
3. Reference skills via `@skills` or by describing the audit task

## Features
- **Multi-Chain Scanning**: Solidity, Solana, Cairo, Move, CosmWasm, TON, and more
- **Attack Chain Detection**: Multi-step exploit sequence identification
- **Protocol Templates**: Pre-built audit templates for lending, DEX, bridge, staking, NFT
- **Variant Analysis**: Systematic vulnerability pattern hunting
- **Static Analysis Integration**: Slither, Mythril, Aderyn tool workflows
- **Token Analysis**: Weird ERC20 detection and compatibility checking
- **Report Writing**: Structured finding templates with severity classification
- **Cyfrin Findings**: Historical vulnerability pattern database

## Skill Structure
```
skills/
├── SKILL.md                    # Root skill
├── MASTER_CHECKLIST.md         # Full audit checklist
├── INDEX.md                    # Skill directory
├── solidity-scanner/           # EVM analysis
├── solana-scanner/             # Solana analysis
├── cairo-scanner/              # StarkNet analysis
├── move-scanner/               # Aptos/Sui analysis
├── cosmos-scanner/             # CosmWasm analysis
├── ton-scanner/                # TON analysis
├── audit-context-building/     # Pre-audit context
├── cyfrin-findings/            # Historical findings
├── report-writer/              # Report generation
├── token-analyzer/             # Token compatibility
├── static-analysis/            # Tool integration
├── variant-analysis/           # Pattern hunting
├── differential-review/        # Diff review
├── fix-review/                 # Fix verification
├── spec-compliance/            # ERC/EIP compliance
├── advanced/                   # Advanced workflows
├── attack-chains/              # Attack references
├── chain-guides/               # Chain security guides
├── checklists/                 # Protocol checklists
├── consolidated/               # Pattern references
├── severity/                   # Severity guides
├── methodology/                # Methodology docs
├── patterns/                   # Vulnerability patterns
├── sources/                    # External references
└── commands/                   # Command definitions
```

## Usage in Cursor
Use Cursor's AI chat to invoke skills naturally:
- "Audit this Solidity file for security issues"
- "Run the bridge security checklist on this contract"
- "What weird ERC20 behaviors should I watch for?"
- "Search Cyfrin findings for oracle manipulation"
- "Write an audit report for the issues found"

## License
MIT
