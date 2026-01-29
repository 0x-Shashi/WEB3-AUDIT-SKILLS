# Web3 Security Audit Plugin - Claude Code

The most comprehensive Web3 security audit assistant for **Claude Code IDE**.

## 🚀 Installation

1. Copy this folder to your Claude Code plugins directory
2. Set your Cyfrin API key:
   ```bash
   export CYFRIN_API_KEY="your_api_key"
   ```
3. Restart Claude Code

## 📚 Features

### Multi-Chain Support (6 Blockchains)
| Chain | Language | Skill |
|-------|----------|-------|
| Ethereum | Solidity | `solidity-scanner` |
| Solana | Rust/Anchor | `solana-scanner` |
| StarkNet | Cairo | `cairo-scanner` |
| Aptos/Sui | Move | `move-scanner` |
| Cosmos | CosmWasm | `cosmos-scanner` |
| TON | FunC/Tact | `ton-scanner` |

### Integrated Vulnerability Database
- **50,000+** real audit findings from Cyfrin Solodit
- Searchable by pattern, category, protocol type
- Attack vectors with proof-of-concepts

### 📚 Comprehensive Knowledge Base (NEW)
| Category | Content |
|----------|---------|
| **Vulnerability Patterns** | 30+ Solidity patterns, DeFi exploits, protocol-specific |
| **Protocol-Specific** | GMX, Synthetix, MIMSwap, Orderly patterns |
| **L2 Security** | Arbitrum, Optimism, zkSync, Base-specific checks |
| **Bridge Security** | Cross-chain vulnerabilities, message passing |
| **Checklists** | 50+ audit items, severity rubrics, SWC mappings |
| **Methodology** | 5-phase workflow, SCAN modes, learning paths |

### Professional Audit Workflows
- Context Building & Threat Modeling
- Vulnerability Scanning (100+ patterns)
- Token Analysis (30+ weird ERC20 behaviors)
- Spec Compliance (EIP/ERC verification)
- Static Analysis (Slither/Mythril)
- Fix Review & Differential Analysis
- Professional Report Generation

## 🔧 Commands

| Command | Description |
|---------|-------------|
| `/audit-start <name>` | Initialize new audit |
| `/audit-scan` | Scan current file |
| `/audit-search <query>` | Search Solodit |
| `/audit-report` | Generate report |
| `/check-reentrancy` | Check reentrancy |
| `/check-access` | Check access control |
| `/check-tokens` | Check token safety |
| `/checklist [category]` | Run comprehensive checklist |
| `/l2-check <chain>` | L2-specific security check |
| `/defi-check` | DeFi vulnerability patterns |
| `/finding <severity> <title>` | Log finding |
| `/findings` | List findings |
| `/slither` | Run Slither |
| `/diff <v1> <v2>` | Compare versions |

## 📁 Structure

```
claude-code/
├── plugin.json           # Claude Code manifest
├── README.md
├── SKILL.md              # Main plugin skill
└── skills/
    ├── INDEX.md              # 📚 Master navigation (NEW)
    ├── patterns/             # 📚 Vulnerability patterns (NEW)
    │   ├── vulnerability-patterns.md
    │   ├── vulnerability-taxonomy.md
    │   ├── severity-scoring.md
    │   ├── defi-vulnerabilities.md
    │   ├── protocol-specific-patterns.md
    │   ├── l2-security.md
    │   ├── bridge-security.md
    │   ├── evm-gas-dos.md
    │   └── invariant-testing.md
    ├── checklists/           # 📚 Comprehensive checklists (NEW)
    │   └── comprehensive-checklist.md
    ├── methodology/          # 📚 Audit methodology (NEW)
    │   ├── llm-audit-workflow.md
    │   └── learning-path-attack-vectors.md
    ├── cyfrin-findings/      # Solodit API integration
    ├── audit-context/        # Protocol analysis
    ├── solidity-scanner/     # Ethereum security
    ├── solana-scanner/       # Solana security
    ├── cairo-scanner/        # StarkNet security
    ├── move-scanner/         # Aptos/Sui security
    ├── cosmos-scanner/       # Cosmos security
    ├── ton-scanner/          # TON security
    ├── token-analyzer/       # Weird tokens
    ├── spec-compliance/      # EIP/ERC verification
    ├── static-analysis/      # Tool integration
    ├── variant-analysis/     # Similar bugs
    ├── fix-review/           # Fix verification
    ├── differential-review/  # Version comparison
    ├── report-writer/        # Report templates
    └── commands/             # Plugin commands
```

## 🎯 Quick Start

```
# Start a new audit
/audit-start my-protocol

# Scan for vulnerabilities
/audit-scan --deep

# Search known vulnerabilities
/audit-search "flash loan oracle"

# Generate report
/audit-report --format=md
```

## 📄 License

MIT License
