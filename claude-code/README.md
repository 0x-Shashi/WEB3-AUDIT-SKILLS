# Web3 Audit Skills - Claude Code Plugin

## Overview
Claude Code plugin configuration for the Web3 Audit Skills system. This plugin integrates comprehensive smart contract security audit capabilities directly into Claude Code.

## Architecture

This folder contains **only platform-specific configuration** for Claude Code. All skill content lives in the shared `skills/` directory at the repository root, which is the single source of truth for all platforms.

```
repo-root/
  skills/          <-- shared skill files (465 files)
  claude-code/     <-- this folder (config only)
    plugin.json
    README.md
```

## Installation
1. Clone this repository
2. Point Claude Code to this directory as a skill source
3. Skills are loaded from `../skills/` (configured in `plugin.json`)

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

All skills live in the shared `../skills/` directory:

```
../skills/
├── SKILL.md                    # Root skill definition
├── MASTER_CHECKLIST.md         # Comprehensive audit checklist
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
├── solidity-scanner/           # EVM smart contract analysis
├── solana-scanner/             # Solana program analysis
├── cairo-scanner/              # StarkNet contract analysis
├── move-scanner/               # Aptos/Sui Move analysis
├── cosmos-scanner/             # CosmWasm analysis
├── ton-scanner/                # TON FunC/Tact analysis
└── ...                         # 40+ skill categories total
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
