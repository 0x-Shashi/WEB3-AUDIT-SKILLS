# How It Works

## Overview

This is a **skill-based AI audit system** that enhances LLM capabilities for Web3 security auditing. Instead of relying on generic AI knowledge, it provides structured, expert-curated patterns that guide the AI through comprehensive security analysis.

```
┌─────────────────────────────────────────────────────────────────┐
│                    HOW THE SYSTEM WORKS                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   YOUR CODE                    SKILL SYSTEM                      │
│   ─────────                    ────────────                      │
│   ┌─────────┐                  ┌─────────────────────┐          │
│   │ Smart   │                  │  Context Detection  │          │
│   │ Contract│─────────────────▶│  (Auto-identify     │          │
│   │ Code    │                  │   chain, protocol)  │          │
│   └─────────┘                  └──────────┬──────────┘          │
│                                           │                      │
│                                           ▼                      │
│                                ┌─────────────────────┐          │
│                                │  Load Relevant      │          │
│                                │  Skills & Patterns  │          │
│                                └──────────┬──────────┘          │
│                                           │                      │
│                                           ▼                      │
│   ┌─────────┐                  ┌─────────────────────┐          │
│   │ Audit   │◀─────────────────│  AI + Skills =      │          │
│   │ Report  │                  │  Expert Analysis    │          │
│   └─────────┘                  └─────────────────────┘          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## The Problem It Solves

### Without This System
```
Developer: "Audit this Solidity contract"
Generic AI: *Uses general knowledge*
           *Misses protocol-specific issues*
           *No systematic coverage*
           *Inconsistent depth*
```

### With This System
```
Developer: "Audit this Solidity contract"
AI + Skills: *Detects: Solidity + Lending Protocol*
            *Loads: solidity-scanner + lending-template*
            *Applies: 500+ specific vulnerability patterns*
            *Checks: Attack chains (flash loan, oracle, etc.)*
            *Output: Structured report with severity ratings*
```

---

## Core Components

### 1. Scanners (Chain-Specific)
```
scanners/
├── solidity-scanner/    # EVM chains (Ethereum, BSC, Polygon, etc.)
├── solana-scanner/      # Solana (Rust/Anchor)
├── sui-scanner/         # Sui (Move)
├── aptos-scanner/       # Aptos (Move)
├── starknet-scanner/    # Starknet (Cairo)
├── aztec-scanner/       # Aztec (Noir - private contracts)
├── fuel-scanner/        # FuelVM (Sway)
├── ton-scanner/         # TON (FunC/Tact)
├── cosmos-scanner/      # Cosmos (CosmWasm/Rust)
├── move-scanner/        # Generic Move
└── cairo-scanner/       # Generic Cairo
```

Each scanner contains:
- Language-specific vulnerability patterns
- Detection commands (grep, regex)
- Code examples of vulnerable vs secure code
- Chain-specific attack vectors

### 2. Protocol Templates (DeFi-Specific)
```
protocol-templates/
├── amm-dex-template.md       # Uniswap, Curve forks
├── lending-template.md       # Aave, Compound forks
├── bridge-template.md        # Cross-chain bridges
├── staking-template.md       # Staking protocols
└── nft-marketplace-template.md  # OpenSea-style marketplaces
```

Each template contains:
- Protocol architecture diagram
- Critical functions to audit
- Protocol-specific vulnerabilities (with real exploit examples)
- Audit checklists

### 3. Attack Chains (Multi-Vulnerability Exploits)
```
attack-chains/
├── flash-loan-chains.md      # Flash loan attack combinations
├── oracle-chains.md          # Price manipulation attacks
├── bridge-chains.md          # Cross-chain attacks
└── governance-chains.md      # Governance takeover attacks
```

Maps how individual vulnerabilities combine into devastating exploits.

### 4. Consolidated Patterns (Expert Knowledge Base)
```
patterns/
├── access-control-patterns.md      # 50+ access control issues
├── defi-integration-patterns.md    # 100+ DeFi vulnerabilities
├── reentrancy-patterns.md          # All reentrancy variants
├── oracle-price-patterns.md        # Oracle manipulation
└── ... (13 consolidated files)
```

Contains 1000+ vulnerability patterns extracted from:
- Real audit reports
- Past exploits ($10B+ in documented losses)
- Security researcher findings

---

## Workflow Example

### Step 1: User Provides Code
```
User: "Audit this lending protocol"
[Provides Solidity files]
```

### Step 2: Context Detection
System automatically detects:
```yaml
chain: ethereum
language: solidity
protocol_type: lending
similar_to: [Aave, Compound]
risk_level: high
```

### Step 3: Skill Loading
Based on context, loads:
```
✓ solidity-scanner
✓ lending-template
✓ flash-loan-chains
✓ oracle-chains
✓ defi-integration-patterns
```

### Step 4: Pattern Application
Runs 500+ checks:
```
□ Reentrancy in withdraw functions
□ Oracle manipulation in price feeds
□ Flash loan attacks on liquidation
□ Interest rate manipulation
□ Collateral valuation issues
□ ... (hundreds more)
```

### Step 5: Attack Chain Analysis
Identifies combined exploits:
```
Finding 1: Spot price oracle (Medium)
Finding 2: Instant liquidation (Low)
Finding 3: Flash loan integration (Info)

→ Combined: Flash Loan Oracle Attack (CRITICAL)
  "Attacker can flash borrow, manipulate price,
   liquidate users unfairly, profit $X"
```

### Step 6: Report Generation
```markdown
# Security Audit Report

## Critical (1)
- Flash loan + oracle manipulation attack path

## High (3)
- Missing reentrancy guard in withdraw()
- Unbounded loop in reward distribution
- ...

## Medium (5)
...
```

---

## Integration Methods

### 1. Cursor IDE
```
cursor/skills/ → Cursor reads as custom instructions
```

### 2. Claude Code (Anthropic)
```
claude-code/skills/ → Claude uses as context
```

### 3. Antigravity
```
antigravity/skills/ → Custom skill integration
```

### 4. Any LLM
Copy relevant skill files into context window.

---

## Why Skills > Fine-Tuning

| Aspect | Fine-Tuning | Skill System |
|--------|-------------|--------------|
| Update speed | Weeks/months | Instant |
| Transparency | Black box | Readable files |
| Customization | Requires retraining | Edit markdown |
| Cost | Expensive | Free |
| Specificity | General patterns | Exact patterns |
| Verifiability | Can't verify training | Can audit skills |

---

## Data Sources

Skills are built from:
- **Solodit**: 10,000+ real audit findings
- **Code4rena**: Competition findings
- **Immunefi**: Bug bounty reports
- **Rekt.news**: Post-mortem analyses
- **Academic papers**: Formal verification research
- **Original research**: Novel pattern discovery

---

## Metrics

```
Total Skills:          50+ skill files
Vulnerability Patterns: 1,000+
Chain Coverage:        11 blockchains
Protocol Templates:    5 major DeFi types
Attack Chains:         29 multi-step exploits
Lines of Knowledge:    50,000+
```
