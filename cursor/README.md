# Web3 Security Audit Plugin - Cursor

The most comprehensive Web3 security audit assistant for **Cursor IDE**.

## 🚀 Installation

### Method 1: Project-Level Rules
1. Copy `.cursorrules` to your project root
2. Cursor will automatically load the rules

### Method 2: Global Rules
1. Open Cursor Settings
2. Go to "Rules for AI"
3. Paste the contents of `.cursorrules`

### Method 3: Full Plugin (with skills)
1. Copy entire `cursor/` folder to your workspace
2. Reference skills in your conversations

## 📚 Features

### Multi-Chain Support (6 Blockchains)
| Chain | Language | Detection |
|-------|----------|-----------|
| Ethereum | Solidity | `pragma solidity` |
| Solana | Rust/Anchor | `use anchor_lang` |
| StarkNet | Cairo | `#[starknet::contract]` |
| Aptos/Sui | Move | `module address::` |
| Cosmos | CosmWasm | `cosmos-sdk` |
| TON | FunC/Tact | `recv_internal` |

### Integrated Vulnerability Patterns
- **100+** vulnerability patterns across platforms
- Real-world exploit methodologies
- Platform-specific security checks

### Security Analysis Features
- Automatic platform detection
- Vulnerability pattern matching
- Severity classification
- Finding documentation format
- Remediation suggestions

## 🔧 Commands

Use these commands in Cursor chat:

| Command | Description |
|---------|-------------|
| `/audit-scan` | Scan current file |
| `/audit-search <query>` | Search vulnerabilities |
| `/check-reentrancy` | Check reentrancy |
| `/check-access` | Check access control |
| `/check-tokens` | Check token safety |
| `/finding` | Format as finding |

## 📁 Structure

```
cursor/
├── .cursorrules          # Main Cursor rules file
├── README.md
└── skills/               # Reference documentation
    ├── cyfrin-findings/  # Solodit patterns
    ├── solidity-scanner/ # Ethereum patterns
    ├── solana-scanner/   # Solana patterns
    ├── cairo-scanner/    # StarkNet patterns
    ├── move-scanner/     # Aptos/Sui patterns
    ├── cosmos-scanner/   # Cosmos patterns
    ├── ton-scanner/      # TON patterns
    ├── token-analyzer/   # Weird tokens
    ├── spec-compliance/  # EIP/ERC
    ├── static-analysis/  # Tool guides
    └── report-writer/    # Report templates
```

## 🎯 Quick Start

### Scan a File
```
Scan this contract for security vulnerabilities
```

### Search for Patterns
```
/audit-search "flash loan oracle manipulation"
```

### Get Finding Format
```
/finding - format this issue as a professional finding
```

### Check Specific Patterns
```
/check-reentrancy - check this function for reentrancy
```

## ⚙️ Customization

Edit `.cursorrules` to:
- Add custom vulnerability patterns
- Modify severity thresholds
- Add project-specific rules
- Customize response format

### Example Custom Rule
```markdown
## Project-Specific Rules

This project uses:
- Custom access control via AccessManager
- Time-locked operations require 48h delay
- All token transfers use SafeERC20
```

## 📋 Severity Levels

| Level | Description | Color |
|-------|-------------|-------|
| CRITICAL | Direct fund loss | 🔴 |
| HIGH | Significant damage | 🟠 |
| MEDIUM | Limited impact | 🟡 |
| LOW | Minor issues | 🟢 |
| INFO | Suggestions | ℹ️ |

## 🔗 Skills Reference

The `skills/` folder contains detailed documentation:
- Vulnerability patterns with code examples
- Detection methodologies
- Remediation strategies
- Tool integration guides

Reference these in conversations:
```
Using the patterns from skills/solidity-scanner, analyze this contract
```

## 📄 License

MIT License
