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

### 1. Attack Trees - Visual Attack Paths (NEW in v4.0)

Systematic decision trees showing how attackers explore protocol vulnerabilities:

| Attack Tree            | Branches                                                                          | Real Exploits Mapped                          |
| ---------------------- | --------------------------------------------------------------------------------- | --------------------------------------------- |
| Lending Protocol       | [A-G] Oracle, Liquidation, Accounting, Reentrancy, Flash Loan, Access, MEV        | Euler ($197M), Radiant ($4.5M), Cream ($130M) |
| DEX/AMM                | [A-G] Oracle, LP, Swaps, MEV, Concentrated Liquidity, Router, Governance          | Harvest ($24M), Warp ($7.7M)                  |
| Cross-Chain Bridge     | [A-G] Signatures, State Sync, Tokens, Relayer, Contracts, Economic                | Wormhole ($326M), Ronin ($625M), Poly ($610M) |
| Vault/Yield Aggregator | [A-H] Share Price, Strategy, Withdrawal, Oracle, ERC4626, Access, Tokens, Rewards | Yearn ($11M), Rari ($80M)                     |

**Each tree includes:**

- Condition checks (when is this exploitable?)
- Attack actions (what does the attacker do?)
- Expected results (what happens if successful?)
- Pattern cross-references (links to detailed files)
- Real exploit mappings (which hacks used this?)

### 2. Anti-Patterns - What NOT to Do (NEW in v4.0)

Bad code examples from real exploits with working attack PoCs:

| Anti-Pattern Category        | Patterns   | Total Losses |
| ---------------------------- | ---------- | ------------ |
| Oracle Anti-Patterns         | 7 mistakes | $200M+       |
| Access Control Anti-Patterns | 7 mistakes | $1.4B+       |
| Reentrancy Anti-Patterns     | 7 mistakes | $115M+       |

**Each anti-pattern shows:**

- Vulnerable code (marked with [VULNERABLE])
- Why it's bad
- Real exploits that used it
- Working attack PoC
- Correct pattern (marked with [GOOD])

### 3. Smart Checklists - Role-Based (NEW in v4.0)

Context-aware checklists for specific roles and phases:

| Checklist                | Target Audience | Time Required | Copy-Pasteable           |
| ------------------------ | --------------- | ------------- | ------------------------ |
| Developer Pre-Deployment | Developers      | 15-30 min     | Yes (PR/Issue format)    |
| Auditor First Pass       | Auditors        | 30-60 min     | Yes (Quick scan)         |
| QA Integration Testing   | QA Testers      | 2-4 hours     | Yes (Test scenarios)     |
| Protocol Integration     | Developers      | 1-2 hours     | Yes (External protocols) |

### 4. Navigation Tools (NEW in v4.0)

Intelligent cross-referencing and file discovery:

| Tool         | Purpose                                                        | Lines |
| ------------ | -------------------------------------------------------------- | ----- |
| XREF.md      | Cross-reference index: vulnerability → pattern → exploit → fix | 500+  |
| TRIGGERS.md  | AI trigger phrases: user question → files to load              | 400+  |
| CHANGELOG.md | Pattern evolution over time, exploit timeline                  | 600+  |

### 5. Vulnerability Pattern Library (149 Files)

Complete coverage of smart contract vulnerabilities organized by attack vector:

| Category               | Patterns | Examples                                                           |
| ---------------------- | -------- | ------------------------------------------------------------------ |
| DeFi Attacks           | 35+      | Flash loans, oracle manipulation, sandwich attacks                 |
| Reentrancy Variants    | 6        | Classic, cross-function, cross-contract, read-only, callback hooks |
| Access Control         | 15+      | Missing modifiers, privilege escalation, ownership hijacking       |
| Token Vulnerabilities  | 25+      | Fee-on-transfer, rebasing, weird ERC20 behaviors                   |
| Math Errors            | 20+      | Precision loss, rounding errors, overflow/underflow                |
| Bridge and Cross-Chain | 10+      | Message verification, replay attacks, sequencer issues             |
| L2 Specific            | 8+       | Arbitrum, Optimism, sequencer downtime handling                    |

### 6. Fractal Pattern Expansion (Deep-Dive Analysis)

Not just surface-level patterns. Each major vulnerability type includes:

**Reentrancy Deep-Dive:**

- Classic single-function reentrancy with state manipulation
- Cross-function reentrancy exploiting shared state
- Cross-contract reentrancy via external protocol calls
- Read-only reentrancy attacking view functions
- Callback hook reentrancy via ERC777/ERC1155/ERC721

### 7. Exploit Forensics (CSI-Style Case Studies)

Learn from the biggest hacks in DeFi history with transaction-level analysis:

| Exploit      | Year | Loss  | Root Cause                    |
| ------------ | ---- | ----- | ----------------------------- |
| The DAO      | 2016 | $60M  | Classic reentrancy            |
| Wormhole     | 2022 | $326M | Signature verification bypass |
| Ronin Bridge | 2022 | $624M | Validator key compromise      |

Each case study includes:

- Block-by-block attack timeline
- Vulnerable code with annotations
- Attacker transaction traces
- What auditors missed and why

### 8. Protocol Integration Playbooks

Security guidance for integrating with major DeFi protocols:

| Protocol   | Coverage                                                           |
| ---------- | ------------------------------------------------------------------ |
| Uniswap V3 | Tick manipulation, TWAP attacks, concentrated liquidity risks      |
| Aave V3    | Flash loan patterns, liquidation MEV, oracle dependencies          |
| Lido       | stETH/wstETH handling, rebasing token accounting, withdrawal queue |

### 9. Evolution Timelines

Track how vulnerabilities evolved and defenses improved:

| Timeline            | Period    | Key Milestones                                 |
| ------------------- | --------- | ---------------------------------------------- |
| Reentrancy          | 2016-2026 | DAO hack to transient storage reentrancy       |
| Oracle Manipulation | 2020-2026 | bZx attacks to sophisticated TWAP manipulation |
| Bridge Security     | 2021-2026 | Wormhole to Multichain, defense evolution      |

### 6. Structured Learning Paths

Progressive curriculum from beginner to expert:

| Path         | Duration | Focus                                                   |
| ------------ | -------- | ------------------------------------------------------- |
| Beginner     | 20 hours | Solidity basics, common vulnerabilities, first audit    |
| Intermediate | 40 hours | DeFi mechanics, oracles, flash loans, token standards   |
| Advanced     | 80 hours | Cross-chain, formal verification, novel attack research |

### 7. Severity Classification System

Four-tier severity system aligned with industry standards:

| Severity | Findings | Criteria                              |
| -------- | -------- | ------------------------------------- |
| HIGH     | 8,022    | Direct fund loss, protocol insolvency |
| MEDIUM   | 13,814   | Conditional exploits, limited impact  |
| LOW      | 25,272   | Edge cases, best practices            |
| GAS      | 3,422    | Optimization opportunities            |

### 8. Audit Firm Knowledge Base (15 Sources)

Aggregated patterns from the top security firms:

| Firm             | Findings | Specialty                    |
| ---------------- | -------- | ---------------------------- |
| Code4rena        | 12,292   | Community competitive audits |
| Sherlock         | 3,017    | Protocol-focused contests    |
| OpenZeppelin     | 3,237    | Enterprise security          |
| Trail of Bits    | 2,094    | Research-driven analysis     |
| Spearbit         | 2,224    | Senior auditor network       |
| Cyfrin           | 2,133    | Educational focus            |
| And 9 more firms | 15,000+  | Various specialties          |

### 10. Master Audit Checklist

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

| Your IDE         | Folder to Use  | Setup Guide                                |
| ---------------- | -------------- | ------------------------------------------ |
| Claude Code      | `claude-code/` | [Claude Code Setup](claude-code/README.md) |
| Any AI Assistant | `skills/`      | Use the master skills folder directly      |

### Step 3: Start Auditing

```
Read the security skills from the skills/ folder, then audit my contracts for vulnerabilities.
```

Your AI now has access to 50,530 vulnerability patterns.

---

## Supported Platforms

### Claude Code (Primary)

Claude Code uses `plugin.json` for configuration and reads skills from the `skills/` folder.

| Feature        | Support              |
| -------------- | -------------------- |
| Auto-detection | Yes, via plugin.json |
| Skills folder  | skills/              |
| Setup time     | Under 1 minute       |

See [claude-code/README.md](claude-code/README.md) for detailed setup.

---

### Any AI Assistant

The `skills/` folder is the master knowledge base and works with any AI that can read markdown files. Simply point your AI assistant to the `skills/` folder and the `AI-INSTRUCTIONS.md` file.

| Feature                  | Support            |
| ------------------------ | ------------------ |
| Skills folder            | skills/            |
| AI instructions          | AI-INSTRUCTIONS.md |
| Platform-specific config | Not required       |

> **Coming soon:** Dedicated integrations for Cursor IDE, Antigravity, and other AI coding assistants.

---

## Repository Structure

```
WEB3-AUDIT-SKILLS/
|
|-- README.md                    # This file
|-- QUICK-START.md               # Fast setup guide
|-- AI-INSTRUCTIONS.md           # Instructions for AI assistants
|
|-- skills/                      # Master copy of all skills (42 subdirectories)
|   |-- attack-trees/            # Visual attack decision paths (13 files)
|   |-- anti-patterns/           # What NOT to do (12 files)
|   |-- checklists/              # Protocol + role-based checklists (19 files)
|   |-- patterns/                # 155 vulnerability pattern files
|   |-- exploit-forensics/       # CSI-style case studies (30 files)
|   |-- protocol-playbooks/      # Integration guides (13 protocols)
|   |-- methodology/             # Audit workflows (17 guides)
|   |-- solidity-scanner/        # EVM chain scanner
|   |-- solana-scanner/          # Solana scanner
|   |-- cairo-scanner/           # StarkNet scanner
|   |-- move-scanner/            # Aptos/Sui scanner
|   |-- cosmos-scanner/          # CosmWasm scanner
|   |-- evolution-timelines/     # Vulnerability evolution tracking
|   |-- learning-paths/          # Structured curriculum (140 hours)
|   |-- severity/                # 4 severity level files
|   |-- sources/                 # 15 audit firm pattern files
|   |-- XREF.md                  # Cross-reference index
|   |-- TRIGGERS.md              # AI trigger phrase mapping
|   |-- MASTER_CHECKLIST.md      # Complete audit checklist
|   |-- INDEX.md                 # Navigation
|
|-- claude-code/                 # Claude Code plugin config
|   |-- plugin.json              # Plugin configuration
|   |-- README.md                # Setup guide
|
|-- core/                        # MCP server + utilities (optional)
|-- docs/                        # FAQ, how-it-works, security
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

| Severity | Count  | Percentage |
| -------- | ------ | ---------- |
| High     | 8,022  | 15.88%     |
| Medium   | 13,814 | 27.34%     |
| Low      | 25,272 | 50.01%     |
| Gas      | 3,422  | 6.77%      |

### Top 10 Vulnerability Types

| Rank | Type                | Count |
| ---- | ------------------- | ----- |
| 1    | Business Logic      | 234   |
| 2    | Validation          | 127   |
| 3    | Wrong Math          | 107   |
| 4    | Front-Running       | 106   |
| 5    | Fee On Transfer     | 66    |
| 6    | DOS                 | 66    |
| 7    | Oracle              | 59    |
| 8    | Reentrancy          | 59    |
| 9    | Access Control      | 48    |
| 10   | State Update Issues | 47    |

### Coverage

| Metric               | Value  |
| -------------------- | ------ |
| Total Findings       | 50,530 |
| Vulnerability Types  | 207    |
| Audit Firms          | 30     |
| Protocols Covered    | 2,844  |
| Pattern Files        | 149    |
| Exploit Case Studies | 3      |
| Protocol Playbooks   | 3      |
| Evolution Timelines  | 3      |
| Learning Path Hours  | 140    |

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

- [Claude Code Setup Guide](claude-code/README.md)
- [Quick Start Guide](QUICK-START.md)
- [FAQ](docs/FAQ.md)
- [How It Works](docs/HOW-IT-WORKS.md)

Or open an issue on GitHub.

---

## Version History

Current Version: **4.0**

<details>
<summary><strong>v4.0</strong> - Attack Trees, Anti-Patterns & Smart Checklists (January 2025)</summary>

**Major New Features:**

**Attack Trees (5 files, 2,000+ lines)**

- Visual decision paths for systematic vulnerability discovery
- lending-attack-tree.md - Lending protocol attack surface mapping
- dex-attack-tree.md - DEX/AMM attack paths
- bridge-attack-tree.md - Cross-chain bridge vulnerabilities
- vault-attack-tree.md - Vault/yield aggregator attack surface
- Mapped to 70+ real exploits ($3B+ in losses)

**Anti-Patterns (4 files, 1,500+ lines)**

- What NOT to do - bad code examples with real exploit PoCs
- oracle-anti-patterns.md - 7 oracle mistakes ($200M+ losses)
- access-control-anti-patterns.md - 7 access control mistakes ($1.4B+ losses)
- reentrancy-anti-patterns.md - 7 reentrancy mistakes ($115M+ losses)
- Each includes vulnerable code, attack PoC, and correct pattern

**Smart Checklists (4 files, 1,400+ lines)**

- Role-based context-aware checklists
- developer-pre-deployment.md - Pre-deployment sanity checks
- auditor-first-pass.md - 30-60 min initial scan
- qa-integration-testing.md - Integration test scenarios
- protocol-integration.md - External protocol integration guide

**Navigation Tools (3 files, 1,500+ lines)**

- XREF.md - Cross-reference index: vulnerability → pattern → exploit → fix
- TRIGGERS.md - AI trigger phrases: user question → files to load
- CHANGELOG.md - Pattern evolution timeline with real exploits

**Improvements:**

- Removed all emoji characters for professional appearance
- Enhanced cross-linking between all resource types
- Added exploit statistics with dollar amounts and dates
- Improved markdown formatting and link structure

**Files Added:** 16 new files, 6,400+ lines
**Total Repository:** 1,600+ files, professional formatting

</details>

<details>
<summary><strong>v3.5</strong> - Advanced Methodology (Jan 2026)</summary>

**New Methodology Files:**

- `fix-verification-patterns.md` - How to verify fixes don't reintroduce bugs
- `gas-optimization-security.md` - When gas optimizations become vulnerabilities
- `audit-report-templates.md` - Professional finding formats
- `exploit-case-studies.md` - $1.5B+ in analyzed hacks (Ronin, Wormhole, Euler, Nomad, Mango, Cream)
- `upgrade-migration-patterns.md` - Proxy and storage collision vulnerabilities
- `composability-attacks.md` - Cross-protocol DeFi attack surfaces

**Stats:** 24 files, 14,532 lines added

</details>

<details>
<summary><strong>v3.0</strong> - Navigation & Methodology (Dec 2025)</summary>

**New Files:**

- `ROUTE-MAP.md` - Decision tree for 9 protocol types (Lending, DEX, Bridge, Vault, Staking, NFT, Governance, Perps, Intents)
- `poc-writing-guide.md` - How to write effective PoCs
- `secure-pattern-reference.md` - What secure implementations look like

**Improvements:**

- YAML frontmatter with triggers for AI discoverability
- Protocol-specific reading paths
- Severity classification guidance

**Stats:** 12 files, 4,656 lines added

</details>

<details>
<summary><strong>v2.0</strong> - Multi-Chain Expansion (Nov 2025)</summary>

**Chain Guides:**

- Solana, CosmWasm, Move (Aptos/Sui), TON, StarkNet, zkSync guides
- Chain-specific vulnerability patterns
- Cross-chain bridge security

**Protocol Playbooks:**

- Uniswap V3, Aave V3, Lido integration security
- Evolution timelines (Reentrancy, Oracle, Bridge attacks)

**Deep Analysis:**

- Fractal pattern expansion (reentrancy deep-dive)
- Exploit forensics (DAO, Wormhole, Ronin)
- Learning path curriculum

**Stats:** 72 files, 39,796 lines added

</details>

<details>
<summary><strong>v1.0</strong> - Foundation (Oct 2025)</summary>

**Initial Release:**

- 149 vulnerability pattern files
- 50,530 findings from 15 audit firms
- Master checklist with 207 vulnerability types
- YAML-structured metadata for AI parsing
- Claude Code plugin support

**Coverage:**

- 2,844 audited protocols
- 8,022 High severity findings
- 13,814 Medium severity findings
- 25,272 Low severity findings

**Stats:** Base repository with core patterns

</details>

---

### Versioning Guide

| Version Type    | When to Use                                 | Example     |
| --------------- | ------------------------------------------- | ----------- |
| **Major (X.0)** | Big feature additions, structural changes   | v4.0 → v5.0 |
| **Minor (X.Y)** | Small updates, bug fixes, pattern additions | v4.0 → v4.1 |

**Upcoming in v4.1+:**

- Additional protocol-specific checklists
- More chain guides
- Community-contributed patterns
