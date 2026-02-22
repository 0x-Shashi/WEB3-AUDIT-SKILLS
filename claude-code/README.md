# Web3 Audit Skills - Claude Code Plugin

## Overview
Claude Code plugin configuration for the Web3 Audit Skills system. This plugin integrates comprehensive smart contract security audit capabilities directly into Claude Code.

## Installation
1. Clone this repository
2. Point Claude Code to this directory as a skill source
3. Skills are automatically loaded from the `skills/` directory

## Features
- **Multi-Chain Scanning**: Solidity, Solana, Cairo, Move, CosmWasm, TON, and more
- **Attack Chain Detection**: Multi-step exploit identification
- **Protocol Templates**: Pre-built audit checklists for lending, DEX, bridge, staking, NFT
- **Variant Analysis**: Find all instances of a vulnerability pattern
- **Static Analysis Integration**: Slither, Mythril, Aderyn workflows
- **Token Analysis**: Weird ERC20 detection, fee-on-transfer, rebasing
- **Report Writing**: Structured finding templates and severity classification
- **Cyfrin Findings Database**: Historical vulnerability search

## Skill Structure
```
skills/
├── SKILL.md                    # Root skill definition
├── MASTER_CHECKLIST.md         # Comprehensive audit checklist
├── INDEX.md                    # Skill navigation
├── solidity-scanner/           # EVM smart contract analysis
├── solana-scanner/             # Solana program analysis
├── cairo-scanner/              # StarkNet contract analysis
├── move-scanner/               # Aptos/Sui Move analysis
├── cosmos-scanner/             # CosmWasm analysis
├── ton-scanner/                # TON FunC/Tact analysis
├── audit-context-building/     # Pre-audit context gathering
├── cyfrin-findings/            # Historical findings database
├── report-writer/              # Audit report generation
├── token-analyzer/             # Token compatibility analysis
├── static-analysis/            # Automated tool integration
├── variant-analysis/           # Pattern variant hunting
├── differential-review/        # Code diff review
├── fix-review/                 # Post-fix verification
├── spec-compliance/            # ERC/EIP compliance checking
├── advanced/                   # Multi-step audit workflows
│   ├── attack-chains/          # Exploit chain detection
│   ├── context-detection/      # Auto protocol identification
│   ├── protocol-templates/     # Protocol-specific templates
│   └── skill-chains/           # Composable audit workflows
├── attack-chains/              # Attack chain references
├── chain-guides/               # Chain-specific security guides
├── checklists/                 # Protocol-type checklists
├── consolidated/               # Consolidated pattern references
├── severity/                   # Severity classification
├── methodology/                # Audit methodology guides
├── patterns/                   # Vulnerability pattern library
├── sources/                    # External reference sources
└── commands/                   # Plugin command definitions
```

## Usage
Once installed, use natural language to invoke audit skills:
- "Scan this Solidity contract for vulnerabilities"
- "Run the lending protocol checklist"
- "Check this token for weird ERC20 behavior"
- "Find all reentrancy variants in this codebase"
- "Generate an audit report for my findings"

## License
MIT
