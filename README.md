# Web3 Audit Skills

A knowledge base that turns your AI coding assistant into a smart contract security auditor. Built from 50,530 real vulnerability findings extracted from professional security audits.

---

## What Is This?

This repository contains organized security knowledge that AI assistants can read and learn from. When you open this alongside your smart contract project, your AI gains the ability to:

- Detect 207 different types of vulnerabilities
- Reference real exploits from professional audits
- Suggest fixes based on what actually worked
- Generate professional audit reports

Think of it as giving your AI the experience of 30+ security audit firms without the cost.

---

## Table of Contents

- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
- [Supported Platforms](#supported-platforms)
- [What You Get](#what-you-get)
- [Repository Structure](#repository-structure)
- [Example Usage](#example-usage)
- [Statistics](#statistics)
- [Contributing](#contributing)
- [License](#license)

---

## Quick Start

### Step 1: Clone the Repository

Clone this repo into your project folder or anywhere accessible:

```bash
git clone https://github.com/0x-Shashi/WEB3-AUDIT-SKILLS.git
```

### Step 2: Open in Your IDE

Open the appropriate folder based on your AI coding assistant:

| Your IDE | Folder to Use | Setup Guide |
|----------|---------------|-------------|
| Cursor | `cursor/` | [Cursor Setup](cursor/README.md) |
| Antigravity | `antigravity/` | [Antigravity Setup](antigravity/README.md) |
| Claude Code | `claude-code/` | [Claude Code Setup](claude-code/README.md) |

### Step 3: Start Auditing

Ask your AI to audit your contracts. Example:

```
Read the security skills from the skills/ folder, then audit my contracts for vulnerabilities.
```

That is it. Your AI now has access to 50,530 vulnerability patterns.

---

## How It Works

The system is simple:

```
Your Smart Contract
        |
        v
   AI Assistant  <--reads--  Skills Folder (50,530 patterns)
        |
        v
  Security Findings
```

The `skills/` folder contains markdown files organized by:

1. **Vulnerability Patterns** - What the bug looks like and how to find it
2. **Severity Levels** - High, Medium, Low, Gas optimization findings
3. **Audit Sources** - Patterns from specific firms like OpenZeppelin, Trail of Bits, Sherlock

When you ask your AI to audit code, it references these patterns to identify issues in your contracts.

---

## Supported Platforms

### Cursor IDE

Cursor reads the `.cursorrules` file and the `skills/` folder to understand security patterns.

| Feature | Support |
|---------|---------|
| Auto-detection | Yes, via .cursorrules |
| Skills folder | cursor/skills/ |
| Setup time | Under 1 minute |

See [cursor/README.md](cursor/README.md) for detailed setup.

---

### Antigravity

Antigravity uses `antigravity.yaml` for configuration and reads skills from the folder.

| Feature | Support |
|---------|---------|
| Auto-detection | Yes, via antigravity.yaml |
| Skills folder | antigravity/skills/ |
| Setup time | Under 1 minute |

See [antigravity/README.md](antigravity/README.md) for detailed setup.

---

### Claude Code

Claude Code uses `plugin.json` for configuration.

| Feature | Support |
|---------|---------|
| Auto-detection | Yes, via plugin.json |
| Skills folder | claude-code/skills/ |
| Setup time | Under 1 minute |

See [claude-code/README.md](claude-code/README.md) for detailed setup.

---

## What You Get

### Vulnerability Patterns (147 files)

Real vulnerability patterns extracted from professional audits:

| Category | Examples | Count |
|----------|----------|-------|
| DeFi Specific | Flash loans, oracle manipulation, liquidation bugs | 25+ |
| Access Control | Missing modifiers, privilege escalation | 15+ |
| Reentrancy | Classic, read-only, cross-function | 10+ |
| Token Issues | Fee-on-transfer, rebasing, weird ERC20 | 20+ |
| Math Errors | Precision loss, rounding, overflow | 15+ |
| L2 Specific | Sequencer downtime, Arbitrum/Optimism quirks | 10+ |
| Bridge Security | Cross-chain replay, message verification | 8+ |
| And more | Timing, storage, initialization, etc. | 40+ |

---

### Severity Classifications (4 files)

Findings organized by impact:

| File | Description |
|------|-------------|
| high-severity.md | Direct fund loss, protocol insolvency |
| medium-severity.md | Conditional exploits, limited impact |
| low-severity.md | Edge cases, minor issues |
| gas-optimizations.md | Efficiency improvements |

---

### Audit Firm Knowledge (15 files)

Patterns from specific security firms:

| Firm | Findings |
|------|----------|
| Code4rena | Community audit findings |
| Sherlock | Contest-based audit findings |
| OpenZeppelin | Enterprise audit findings |
| Trail of Bits | Research-focused findings |
| Spearbit | Protocol-specific findings |
| Cyfrin | Educational audit findings |
| Consensys | Enterprise findings |
| Quantstamp | Automated + manual findings |
| Halborn | Security research findings |
| OtterSec | Cross-chain audit findings |
| MixBytes | DeFi-focused findings |
| Cantina | Competitive audit findings |
| CodeHawks | Cyfrin contest findings |
| Pashov Audit Group | Independent audit findings |
| Zokyo | Blockchain security findings |

---

### Master Files

| File | Purpose |
|------|---------|
| MASTER_CHECKLIST.md | Complete audit checklist with all patterns |
| STATISTICS.md | Data analysis of all 50,530 findings |
| INDEX.md | Navigation guide for the skills folder |

---

## Repository Structure

```
WEB3-AUDIT-SKILLS/
|
|-- README.md                 # This file
|-- QUICK-START.md            # Fast setup guide
|-- AI-INSTRUCTIONS.md        # Instructions for AI assistants
|
|-- skills/                   # Master copy of all skills
|   |-- patterns/             # 147 vulnerability pattern files
|   |-- severity/             # 4 severity level files
|   |-- sources/              # 15 audit firm files
|   |-- checklists/           # Audit checklists
|   |-- methodology/          # Audit workflows
|   |-- MASTER_CHECKLIST.md   # Complete checklist
|   |-- STATISTICS.md         # Data analysis
|   |-- INDEX.md              # Navigation
|
|-- cursor/                   # Cursor IDE version
|   |-- .cursorrules          # Cursor configuration
|   |-- README.md             # Cursor-specific guide
|   |-- skills/               # Copy of skills for Cursor
|
|-- antigravity/              # Antigravity version
|   |-- antigravity.yaml      # Antigravity configuration
|   |-- README.md             # Antigravity-specific guide
|   |-- skills/               # Copy of skills for Antigravity
|
|-- claude-code/              # Claude Code version
|   |-- plugin.json           # Claude Code configuration
|   |-- README.md             # Claude Code-specific guide
|   |-- skills/               # Copy of skills for Claude Code
|
|-- core/                     # Shared utilities (optional)
```

---

## Example Usage

### Basic Audit Request

```
I want you to audit my smart contract for security vulnerabilities.

First, read the skills from the skills/ folder to understand vulnerability patterns.

Then analyze contracts/Vault.sol and report any issues you find.

Format findings as:
[SEVERITY] Title
- Description
- Impact  
- Recommendation
```

---

### Check for Specific Vulnerability

```
Using the reentrancy patterns from skills/patterns/reentrancy-patterns.md,
check if my withdraw function is vulnerable to reentrancy attacks.
```

---

### Full Protocol Audit

```
Perform a complete security audit of all contracts in the contracts/ folder.

Use the MASTER_CHECKLIST.md to ensure nothing is missed.

Generate a professional audit report with:
- Executive summary
- Findings by severity
- Recommendations
```

---

### Compare to Known Exploits

```
My contract uses Chainlink oracles.

Check skills/patterns/oracle-patterns.md and skills/patterns/chainlink-patterns.md
to see if my implementation has any known vulnerabilities.
```

---

## Statistics

Data from the 50,530 findings in this repository:

### Severity Breakdown

| Severity | Count | Percentage |
|----------|-------|------------|
| High | 8,022 | 15.88% |
| Medium | 13,814 | 27.34% |
| Low | 25,272 | 50.01% |
| Gas | 3,422 | 6.77% |

---

### Top 10 Vulnerability Types

| Rank | Type | Count |
|------|------|-------|
| 1 | Business Logic | 234 |
| 2 | Validation | 127 |
| 3 | Wrong Math | 107 |
| 4 | Front-Running | 106 |
| 5 | Fee On Transfer | 66 |
| 6 | DOS | 66 |
| 7 | Oracle | 59 |
| 8 | Reentrancy | 59 |
| 9 | Access Control | 48 |
| 10 | State Update Issues | 47 |

---

### Coverage

| Metric | Value |
|--------|-------|
| Total Findings | 50,530 |
| Vulnerability Types | 207 |
| Audit Firms | 30 |
| Protocols Covered | 2,844 |

---

## Data Source

All vulnerability data comes from [Cyfrin Solodit](https://solodit.xyz), the largest database of smart contract security findings. The findings are from real audits of production protocols.

---

## Contributing

Found a vulnerability pattern we missed? Want to add more examples?

1. Fork the repository
2. Add your patterns to the appropriate file in `skills/patterns/`
3. Follow the existing format
4. Submit a pull request

Please include:
- Clear description of the vulnerability
- Code example (vulnerable and fixed)
- Real-world reference if available

---

## Acknowledgments

- Cyfrin Solodit for the vulnerability database
- The security researchers who found these vulnerabilities
- The Web3 security community

---

## License

MIT License. Use freely in your audits.

---

## Need Help?

Check the platform-specific guides:

- [Cursor Setup Guide](cursor/README.md)
- [Antigravity Setup Guide](antigravity/README.md)
- [Claude Code Setup Guide](claude-code/README.md)

Or open an issue on GitHub.
