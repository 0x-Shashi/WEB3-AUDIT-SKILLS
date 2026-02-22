# Advanced Skills Architecture

## Overview
The advanced skills module provides higher-order audit capabilities that compose multiple base skills into sophisticated analysis workflows.

## Module Structure

```
advanced/
├── ARCHITECTURE.md          # This file
├── attack-chains/           # Multi-step exploit chain detection
│   ├── SKILL.md
│   ├── bridge-chains.md     # Bridge-specific attack sequences
│   ├── flash-loan-chains.md # Flash loan combo attacks
│   ├── governance-chains.md # Governance takeover sequences
│   └── oracle-chains.md     # Oracle manipulation chains
├── context-detection/       # Automatic protocol type detection
│   └── SKILL.md
├── protocol-templates/      # Protocol-specific audit templates
│   ├── SKILL.md
│   ├── amm-dex-template.md
│   ├── bridge-template.md
│   ├── lending-template.md
│   ├── nft-marketplace-template.md
│   └── staking-template.md
└── skill-chains/            # Composable audit workflows
    ├── SKILL.md
    ├── quick-scan-chain.md
    ├── deep-dive-chain.md
    └── full-audit-chain.md
```

## Design Principles

### 1. Composability
Each advanced skill is built from base skills. Attack chains combine vulnerability detection skills. Protocol templates combine relevant checklists and scanners. Skill chains orchestrate multiple skills in sequence.

### 2. Context-Awareness
The context-detection module identifies protocol type automatically, enabling the system to select appropriate templates and checklists without manual configuration.

### 3. Depth Levels
- **Quick Scan**: Surface-level check using static analysis + top-10 vulnerabilities
- **Deep Dive**: Focused analysis of specific contract areas with full pattern matching
- **Full Audit**: Comprehensive multi-pass audit using all available skills

## Data Flow
```
Input Codebase
    → Context Detection (identify protocol type)
    → Template Selection (load appropriate checklist)
    → Skill Chain Execution (run skills in order)
    → Attack Chain Analysis (check multi-step exploits)
    → Report Generation
```

## Integration Points
- Base scanners (solidity-scanner, solana-scanner, etc.) provide raw findings
- Attack chains compose findings into exploit narratives
- Protocol templates provide domain-specific checklists
- Skill chains orchestrate the overall audit flow
- Report writer formats all output
