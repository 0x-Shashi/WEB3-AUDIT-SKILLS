# Advanced Skill Architecture

## Overview

This architecture enables intelligent, composable, and context-aware security auditing.

```
┌─────────────────────────────────────────────────────────────────┐
│                    SKILL ORCHESTRATION LAYER                     │
├─────────────────────────────────────────────────────────────────┤
│  Context Detection → Skill Selection → Execution → Aggregation  │
└─────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│   SCANNER     │    │   ANALYZER    │    │   REPORTER    │
│   SKILLS      │    │   SKILLS      │    │   SKILLS      │
├───────────────┤    ├───────────────┤    ├───────────────┤
│ solidity      │    │ impact        │    │ severity      │
│ solana        │    │ exploit-gen   │    │ report-writer │
│ sui           │    │ attack-chain  │    │ remediation   │
│ ...           │    │ ...           │    │ ...           │
└───────────────┘    └───────────────┘    └───────────────┘
```

---

## Core Components

### 1. Context Detection (`/context-detection/`)
Automatically identifies:
- Chain/Language (Solidity, Move, Cairo, etc.)
- Protocol Type (DEX, Lending, Bridge, etc.)
- Risk Profile (TVL, complexity, attack surface)

### 2. Skill Chains (`/skill-chains/`)
Pre-defined skill sequences:
- `full-audit` → context → scan → analyze → report
- `quick-scan` → context → scan
- `deep-dive` → context → scan → exploit-gen → attack-chain

### 3. Attack Chains (`/attack-chains/`)
Multi-vulnerability exploit paths:
- Flash loan + oracle manipulation
- Reentrancy + access control
- Bridge + signature replay

### 4. Protocol Templates (`/protocol-templates/`)
Deep patterns for specific protocol types:
- AMM/DEX patterns
- Lending protocol patterns
- Bridge patterns
- Staking patterns

---

## Usage

### Automatic Mode
```
"Audit this codebase"
→ Context Detection: Solidity, Uniswap V2 Fork, DEX
→ Skills Loaded: solidity-scanner, defi-patterns, amm-template
→ Attack Chains: flash-loan-paths, price-manipulation
→ Output: Prioritized findings with exploit scenarios
```

### Manual Mode
```
"Run attack-chain analysis on the lending module"
→ Skills: lending-template, attack-chain-mapper
→ Output: Multi-step exploit paths
```

---

## File Structure

```
skills/
├── advanced/
│   ├── ARCHITECTURE.md          # This file
│   ├── context-detection/
│   │   ├── SKILL.md
│   │   ├── chain-detector.md
│   │   ├── protocol-detector.md
│   │   └── risk-profiler.md
│   ├── skill-chains/
│   │   ├── SKILL.md
│   │   ├── full-audit-chain.md
│   │   ├── quick-scan-chain.md
│   │   └── deep-dive-chain.md
│   ├── attack-chains/
│   │   ├── SKILL.md
│   │   ├── flash-loan-chains.md
│   │   ├── oracle-chains.md
│   │   ├── bridge-chains.md
│   │   └── governance-chains.md
│   └── protocol-templates/
│       ├── SKILL.md
│       ├── amm-dex-template.md
│       ├── lending-template.md
│       ├── bridge-template.md
│       ├── staking-template.md
│       └── nft-marketplace-template.md
```

---

## Integration Points

### With Existing Skills
- Consolidated patterns feed into attack chains
- Scanner outputs feed into context detection
- Protocol templates extend base patterns

### With External Tools
- Static analysis results (Slither, etc.)
- On-chain data (Etherscan, etc.)
- Historical exploits (Solodit, etc.)
