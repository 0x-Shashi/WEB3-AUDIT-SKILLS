# Web3 Audit Skills - Cursor Integration

## Overview
Cursor IDE integration for the Web3 Audit Skills system. This provides comprehensive smart contract security audit capabilities directly within Cursor's AI-assisted development environment.

## Architecture

This folder contains **only platform-specific configuration** for Cursor. All skill content lives in the shared `skills/` directory at the repository root, which is the single source of truth for all platforms.

```
repo-root/
  skills/          <-- shared skill files (465 files)
  cursor/          <-- this folder (config only)
    .cursorrules
    README.md
```

## Installation
1. Clone this repository into your Cursor workspace
2. Skills in the shared `skills/` directory at repo root are available to Cursor's AI
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

All skills live in the shared `../skills/` directory:

```
../skills/
├── SKILL.md                    # Root skill definition
├── MASTER_CHECKLIST.md         # Full audit checklist
├── INDEX.md                    # Skill navigation
├── patterns/                   # 155 vulnerability patterns
├── consolidated/               # Mega-reference pattern files
├── anti-patterns/              # Bad code pattern catalog
├── attack-trees/               # 13 protocol attack trees
├── exploit-forensics/          # 30 real hack analyses
├── protocol-playbooks/         # 19 integration guides
├── checklists/                 # Protocol-type checklists
├── methodology/                # Audit methodology guides
├── chain-guides/               # Chain-specific security
├── solidity-scanner/           # EVM analysis
├── solana-scanner/             # Solana analysis
├── cairo-scanner/              # StarkNet analysis
├── move-scanner/               # Aptos/Sui Move analysis
├── cosmos-scanner/             # CosmWasm analysis
├── ton-scanner/                # TON analysis
└── ...                         # 40+ skill categories total
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
