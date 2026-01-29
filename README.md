# Web3 Security Audit Plugin

**The Most Comprehensive Smart Contract Security Audit Assistant**

A complete security audit plugin supporting **3 AI IDEs** and **6 blockchain platforms**.

---

## 📦 Available Versions

| Folder | Platform | Config File |
|--------|----------|-------------|
| [claude-code/](./claude-code/) | Claude Code | `plugin.json` |
| [antigravity/](./antigravity/) | Antigravity | `antigravity.yaml` |
| [cursor/](./cursor/) | Cursor IDE | `.cursorrules` |

Choose the version matching your IDE and follow the installation instructions in each folder's README.

---

## 🎯 Features

### Multi-Chain Security (6 Blockchains)

| Blockchain | Language | Patterns |
|------------|----------|----------|
| Ethereum/EVM | Solidity | 25+ vulnerability patterns |
| Solana | Rust/Anchor | 6 critical patterns |
| StarkNet | Cairo | 6 patterns |
| Aptos/Sui | Move | 5 patterns |
| Cosmos | CosmWasm | 9 patterns |
| TON | FunC/Tact | 3 patterns |

### Vulnerability Database
- **50,000+** real audit findings from Cyfrin Solodit
- Attack vectors with proof-of-concepts
- Remediation strategies

### 17 Specialized Skills

| Category | Skills |
|----------|--------|
| **Core** | Cyfrin Findings, Audit Context, Report Writer |
| **Scanners** | Solidity, Solana, Cairo, Move, Cosmos, TON |
| **Analysis** | Token Analyzer, Spec Compliance, Static Analysis |
| **Review** | Variant Analysis, Fix Review, Differential Review |
| **Tooling** | Commands & Hooks |

### Professional Workflows
- Context Building & Threat Modeling
- Vulnerability Scanning (100+ patterns)
- Token Analysis (30+ weird ERC20 behaviors)
- EIP/ERC Compliance Verification
- Static Analysis Integration (Slither/Mythril)
- Fix Review & Differential Analysis
- Professional Report Generation

---

## 🚀 Quick Start

### 1. Choose Your IDE Version

```
claude-code/   → For Claude Code IDE
antigravity/   → For Antigravity
cursor/        → For Cursor IDE
```

### 2. Install

Follow the README in your chosen folder.

### 3. Use Commands

```
/audit-start my-protocol    # Initialize audit
/audit-scan                  # Scan current file
/audit-search "reentrancy"   # Search vulnerabilities
/audit-report               # Generate report
```

---

## 📁 Project Structure

```
WEB 3 AUDIT PLUGIN/
│
├── claude-code/              # Claude Code version
│   ├── plugin.json           # Plugin manifest
│   ├── README.md
│   └── skills/               # 17 skills (71 files)
│
├── antigravity/              # Antigravity version
│   ├── antigravity.yaml      # Config file
│   ├── README.md
│   └── skills/               # 17 skills (71 files)
│
├── cursor/                   # Cursor version
│   ├── .cursorrules          # Cursor rules
│   ├── README.md
│   └── skills/               # 17 skills (71 files)
│
└── REPO/                     # Reference materials
    ├── Audits/               # Example audits
    ├── ETAAcademy-Audit/     # Learning resources
    └── ...
```

---

## 📊 Statistics

| Metric | Value |
|--------|-------|
| **IDE Platforms** | 3 |
| **Blockchain Platforms** | 6 |
| **Skills** | 17 |
| **Total Files** | 213+ |
| **Vulnerability Patterns** | 100+ |
| **Solodit Findings Access** | 50,000+ |

---

## 🔧 Commands Reference

| Command | Description |
|---------|-------------|
| `/audit-start <name>` | Initialize new audit project |
| `/audit-scan [--deep]` | Scan current file |
| `/audit-search <query>` | Search Solodit database |
| `/audit-report [format]` | Generate report |
| `/check-reentrancy` | Check reentrancy vulnerabilities |
| `/check-access` | Analyze access control |
| `/check-tokens` | Check token integration safety |
| `/finding <severity> <title>` | Log new finding |
| `/findings [--filter]` | List all findings |
| `/slither [--detector]` | Run Slither |
| `/diff <v1> <v2>` | Compare versions |

---

## 🔒 Severity Classification

| Severity | Description | Examples |
|----------|-------------|----------|
| 🔴 **CRITICAL** | Direct fund loss | Reentrancy, access control bypass |
| 🟠 **HIGH** | Significant damage | Oracle manipulation, yield theft |
| 🟡 **MEDIUM** | Limited impact | Conditional DoS, rounding errors |
| 🟢 **LOW** | Minor issues | Gas inefficiency, missing events |
| ℹ️ **INFO** | Suggestions | Code quality, best practices |

---

## 📚 Skills Overview

### Core Skills
- **cyfrin-findings**: 50,000+ real audit findings from Solodit
- **audit-context**: Deep code analysis & threat modeling
- **report-writer**: Professional report templates

### Blockchain Scanners
- **solidity-scanner**: Ethereum/EVM vulnerabilities
- **solana-scanner**: Rust/Anchor security
- **cairo-scanner**: StarkNet patterns
- **move-scanner**: Aptos/Sui security
- **cosmos-scanner**: CosmWasm patterns
- **ton-scanner**: FunC/Tact security

### Specialized Analysis
- **token-analyzer**: 30+ weird ERC20 behaviors
- **spec-compliance**: EIP/ERC verification
- **static-analysis**: Slither/Mythril integration
- **variant-analysis**: SCARV methodology
- **fix-review**: CORRECT methodology
- **differential-review**: Version comparison

---

## 🙏 Acknowledgments

- [Cyfrin](https://cyfrin.io) for Solodit vulnerability database
- The Web3 security research community
- Open-source security tooling contributors

---

## 📄 License

MIT License - See LICENSE for details.
