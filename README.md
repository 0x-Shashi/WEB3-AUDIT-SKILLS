# Web3 Audit Skills

**The Most Comprehensive Smart Contract Security Knowledge Base for AI Assistants**

Built from 50,530 real vulnerability findings extracted from professional security audits. This repository transforms any AI coding assistant into a battle-tested smart contract security auditor.

---

## Why This Repository?

Traditional smart contract audits cost $50,000 to $500,000 and take weeks. This repository gives your AI assistant the collective knowledge of 30+ elite security firms instantly.

**What makes this different:**

- **Real Data, Not Theory** - Every pattern comes from actual exploits that lost real money
- **Battle-Tested Knowledge** - Sourced from 2,844 audited protocols
- **Structured for AI** - YAML frontmatter enables precise pattern matching
- **Multi-Platform** - Works with Cursor, Antigravity, Claude Code, and any AI assistant
- **Constantly Updated** - Includes vulnerabilities up to January 2026

---

## Key Features

### 1. Vulnerability Pattern Library (149 Files)

Complete coverage of smart contract vulnerabilities organized by attack vector:

| Category | Patterns | Examples |
|----------|----------|----------|
| DeFi Attacks | 35+ | Flash loans, oracle manipulation, sandwich attacks |
| Reentrancy Variants | 6 | Classic, cross-function, cross-contract, read-only, callback hooks |
| Access Control | 15+ | Missing modifiers, privilege escalation, ownership hijacking |
| Token Vulnerabilities | 25+ | Fee-on-transfer, rebasing, weird ERC20 behaviors |
| Math Errors | 20+ | Precision loss, rounding errors, overflow/underflow |
| Bridge and Cross-Chain | 10+ | Message verification, replay attacks, sequencer issues |
| L2 Specific | 8+ | Arbitrum, Optimism, sequencer downtime handling |

### 2. Fractal Pattern Expansion (Deep-Dive Analysis)

Not just surface-level patterns. Each major vulnerability type includes:

**Reentrancy Deep-Dive:**
- Classic single-function reentrancy with state manipulation
- Cross-function reentrancy exploiting shared state
- Cross-contract reentrancy via external protocol calls
- Read-only reentrancy attacking view functions
- Callback hook reentrancy via ERC777/ERC1155/ERC721

### 3. Exploit Forensics (CSI-Style Case Studies)

Learn from the biggest hacks in DeFi history with transaction-level analysis:

| Exploit | Year | Loss | Root Cause |
|---------|------|------|------------|
| The DAO | 2016 | $60M | Classic reentrancy |
| Wormhole | 2022 | $326M | Signature verification bypass |
| Ronin Bridge | 2022 | $624M | Validator key compromise |

Each case study includes:
- Block-by-block attack timeline
- Vulnerable code with annotations
- Attacker transaction traces
- What auditors missed and why

### 4. Protocol Integration Playbooks

Security guidance for integrating with major DeFi protocols:

| Protocol | Coverage |
|----------|----------|
| Uniswap V3 | Tick manipulation, TWAP attacks, concentrated liquidity risks |
| Aave V3 | Flash loan patterns, liquidation MEV, oracle dependencies |
| Lido | stETH/wstETH handling, rebasing token accounting, withdrawal queue |

### 5. Evolution Timelines

Track how vulnerabilities evolved and defenses improved:

| Timeline | Period | Key Milestones |
|----------|--------|----------------|
| Reentrancy | 2016-2026 | DAO hack to transient storage reentrancy |
| Oracle Manipulation | 2020-2026 | bZx attacks to sophisticated TWAP manipulation |
| Bridge Security | 2021-2026 | Wormhole to Multichain, defense evolution |

### 6. Structured Learning Paths

Progressive curriculum from beginner to expert:

| Path | Duration | Focus |
|------|----------|-------|
| Beginner | 20 hours | Solidity basics, common vulnerabilities, first audit |
| Intermediate | 40 hours | DeFi mechanics, oracles, flash loans, token standards |
| Advanced | 80 hours | Cross-chain, formal verification, novel attack research |

### 7. Severity Classification System

Four-tier severity system aligned with industry standards:

| Severity | Findings | Criteria |
|----------|----------|----------|
| HIGH | 8,022 | Direct fund loss, protocol insolvency |
| MEDIUM | 13,814 | Conditional exploits, limited impact |
| LOW | 25,272 | Edge cases, best practices |
| GAS | 3,422 | Optimization opportunities |

### 8. Audit Firm Knowledge Base (15 Sources)

Aggregated patterns from the top security firms:

| Firm | Findings | Specialty |
|------|----------|-----------|
| Code4rena | 12,292 | Community competitive audits |
| Sherlock | 3,017 | Protocol-focused contests |
| OpenZeppelin | 3,237 | Enterprise security |
| Trail of Bits | 2,094 | Research-driven analysis |
| Spearbit | 2,224 | Senior auditor network |
| Cyfrin | 2,133 | Educational focus |
| And 9 more firms | 15,000+ | Various specialties |

### 9. Master Audit Checklist

A prioritized checklist covering all 207 vulnerability types, organized by:
- Likelihood of occurrence
- Severity of impact
- Ease of detection

### 10. YAML-Structured Metadata

Every file includes machine-readable frontmatter:

```yaml
---
id: VULN-REENTRANCY-001
title: Classic Reentrancy Attack
category: reentrancy
severity: critical
chains: [ethereum, arbitrum, optimism]
protocols: [any-protocol-with-external-calls]
last_updated: 2026-01-31
---
```

This enables AI assistants to precisely match patterns to your code.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Supported Platforms](#supported-platforms)
- [Repository Structure](#repository-structure)
- [Example Usage](#example-usage)
- [Statistics](#statistics)
- [Data Source](#data-source)
- [Contributing](#contributing)
- [License](#license)

---

## Quick Start

### Step 1: Clone the Repository

```bash
git clone https://github.com/0x-Shashi/WEB3-AUDIT-SKILLS.git
```

### Step 2: Open in Your IDE

| Your IDE | Folder to Use | Setup Guide |
|----------|---------------|-------------|
| Cursor | `cursor/` | [Cursor Setup](cursor/README.md) |
| Antigravity | `antigravity/` | [Antigravity Setup](antigravity/README.md) |
| Claude Code | `claude-code/` | [Claude Code Setup](claude-code/README.md) |
| Other AI | `skills/` | Use the master skills folder directly |

### Step 3: Start Auditing

```
Read the security skills from the skills/ folder, then audit my contracts for vulnerabilities.
```

Your AI now has access to 50,530 vulnerability patterns.

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

## Repository Structure

```
WEB3-AUDIT-SKILLS/
|
|-- README.md                    # This file
|-- QUICK-START.md               # Fast setup guide
|-- AI-INSTRUCTIONS.md           # Instructions for AI assistants
|
|-- skills/                      # Master copy of all skills
|   |-- patterns/                # 149 vulnerability pattern files
|   |   |-- reentrancy/          # Reentrancy deep-dive (6 files)
|   |-- exploit-forensics/       # CSI-style case studies (4 files)
|   |-- protocol-playbooks/      # Integration guides (4 files)
|   |-- evolution-timelines/     # Vulnerability evolution (4 files)
|   |-- learning-paths/          # Structured curriculum (4 files)
|   |-- severity/                # 4 severity level files
|   |-- sources/                 # 15 audit firm files
|   |-- checklists/              # Audit checklists
|   |-- methodology/             # Audit workflows
|   |-- MASTER_CHECKLIST.md      # Complete checklist
|   |-- STATISTICS.md            # Data analysis
|   |-- INDEX.md                 # Navigation
|
|-- cursor/                      # Cursor IDE version
|   |-- .cursorrules             # Cursor configuration
|   |-- README.md                # Cursor-specific guide
|   |-- skills/                  # Copy of skills for Cursor
|
|-- antigravity/                 # Antigravity version
|   |-- antigravity.yaml         # Antigravity configuration
|   |-- README.md                # Antigravity-specific guide
|   |-- skills/                  # Copy of skills for Antigravity
|
|-- claude-code/                 # Claude Code version
|   |-- plugin.json              # Claude Code configuration
|   |-- README.md                # Claude Code-specific guide
|   |-- skills/                  # Copy of skills for Claude Code
|
|-- core/                        # Shared utilities (optional)
```

---

## Example Usage

### Basic Audit Request

```
Audit my smart contract for security vulnerabilities.
Read the skills from the skills/ folder and analyze contracts/Vault.sol.
Format findings as: [SEVERITY] Title - Description - Impact - Recommendation
```

### Deep-Dive on Specific Vulnerability

```
Using the reentrancy fractal patterns from skills/patterns/reentrancy/,
check if my withdraw function is vulnerable to any reentrancy variant.
```

### Learn from Real Exploits

```
Read skills/exploit-forensics/the-dao-2016.md and explain
how my contract might be vulnerable to similar attacks.
```

### Protocol Integration Review

```
I am integrating with Uniswap V3.
Read skills/protocol-playbooks/uniswap-v3.md and check
if my integration follows security best practices.
```

### Full Protocol Audit

```
Perform a complete security audit of all contracts in contracts/.
Use MASTER_CHECKLIST.md to ensure comprehensive coverage.
Generate a professional audit report with executive summary.
```

---

## Statistics

### Severity Breakdown

| Severity | Count | Percentage |
|----------|-------|------------|
| High | 8,022 | 15.88% |
| Medium | 13,814 | 27.34% |
| Low | 25,272 | 50.01% |
| Gas | 3,422 | 6.77% |

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

### Coverage

| Metric | Value |
|--------|-------|
| Total Findings | 50,530 |
| Vulnerability Types | 207 |
| Audit Firms | 30 |
| Protocols Covered | 2,844 |
| Pattern Files | 149 |
| Exploit Case Studies | 3 |
| Protocol Playbooks | 3 |
| Evolution Timelines | 3 |
| Learning Path Hours | 140 |

---

## Data Source

All vulnerability data comes from [Cyfrin Solodit](https://solodit.xyz), the largest database of smart contract security findings. The findings are from real audits of production protocols.

---

## Contributing

Found a vulnerability pattern we missed? Want to add more examples?

1. Fork the repository
2. Add your patterns to the appropriate file in `skills/patterns/`
3. Follow the existing YAML frontmatter format
4. Submit a pull request

Please include:
- Clear description of the vulnerability
- Code example (vulnerable and fixed)
- Real-world reference if available
- YAML metadata with severity, chains, and tags

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

