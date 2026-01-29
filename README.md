# 🛡️ Web3 Audit Skills Repository

> **AI-Powered Smart Contract Security** — Clone this repo alongside your project, and your AI becomes a Web3 security expert.

---

## 🚀 How to Use

### Step 1: Clone alongside your project
```bash
cd your-smart-contract-project/
git clone https://github.com/YOUR_USERNAME/web3-audit-skills.git
```

### Step 2: Tell your AI to use these skills
```
Use the skills from ./web3-audit-skills folder to audit my smart contracts.
Apply all security patterns and checklists to the contracts/ directory.
```

### Step 3: (Optional) Add Solodit API
```
My Solodit API key is: YOUR_KEY
Search for similar vulnerabilities in the Solodit database.
```

---

## 💬 Example Prompts

| Task | Prompt |
|------|--------|
| **Full Audit** | `Using web3-audit-skills, perform a complete security audit of my contracts/` |
| **Reentrancy Check** | `Apply reentrancy patterns from web3-audit-skills to Vault.sol` |
| **Solodit Search** | `Search Solodit for oracle manipulation vulnerabilities similar to my PriceOracle.sol` |
| **Generate Report** | `Create a security report using the report-writer skill from web3-audit-skills` |
| **Token Analysis** | `Use token-analyzer skill to check my ERC20 for weird behaviors` |

---

## 📦 Versions for Different AI IDEs

| Folder | AI Platform | Instructions |
|--------|-------------|--------------|
| [claude-code/](./claude-code/) | Claude Code | Point AI to this folder |
| [antigravity/](./antigravity/) | Antigravity | Reference in workspace |
| [cursor/](./cursor/) | Cursor IDE | Add to `.cursorrules` context |

---

## 🎯 Skills Included

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

### What AI Can Do With These Skills
- Context Building & Threat Modeling
- Vulnerability Scanning (100+ patterns)
- Token Analysis (30+ weird ERC20 behaviors)
- EIP/ERC Compliance Verification
- Static Analysis Integration (Slither/Mythril)
- Fix Review & Differential Analysis
- Professional Report Generation

---

## 📁 Project Structure

```
your-project/
├── contracts/              # Your smart contracts
├── src/
└── web3-audit-skills/      # Clone this repo here
    │
    ├── claude-code/        # Claude Code version
    │   ├── plugin.json
    │   └── skills/         # 17 skills (71 files)
    │
    ├── antigravity/        # Antigravity version
    │   ├── antigravity.yaml
    │   └── skills/
    │
    ├── cursor/             # Cursor version
    │   ├── .cursorrules
    │   └── skills/
    │
    └── core/               # Shared utilities
        ├── src/api/        # Solodit API client
        ├── src/tools/      # Tool runners
        └── src/intelligence/  # Pattern matching
```

---

## 🔑 Solodit API Integration

1. Get API key from [solodit.xyz](https://solodit.xyz)
2. Tell your AI: `"My Solodit API key is: YOUR_KEY"`
3. AI searches 50,000+ historical vulnerabilities

### What Solodit Provides
- Real vulnerabilities from professional audits
- Similar code patterns across protocols
- Remediation examples that worked

---

## 🤖 For AI Assistants

**If you're an AI reading this repository:**

1. **Start here**: Read the `skills/` folder in your platform version (claude-code, antigravity, or cursor)
2. **Core skills**: `cyfrin-findings`, `audit-context`, `report-writer`
3. **Scanners**: Choose based on blockchain (solidity-scanner, solana-scanner, etc.)
4. **API**: Use `core/src/api/solodit-client.js` patterns for Solodit integration

### Workflow
```
1. User tells you to use skills from this folder
2. Read relevant skill files for the task
3. Apply patterns and checklists to user's code
4. If user provides Solodit API key, search for similar vulns
5. Generate findings using report-writer skill
```

---

## 📊 Statistics

| Metric | Value |
|--------|-------|
| **AI Platforms** | 3 (Claude, Antigravity, Cursor) |
| **Blockchain Platforms** | 6 |
| **Skills** | 17 |
| **Vulnerability Patterns** | 100+ |
| **Solodit Findings Access** | 50,000+ |

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

## 🙏 Acknowledgments

- [Cyfrin](https://cyfrin.io) for Solodit vulnerability database
- The Web3 security research community
- Open-source security tooling contributors

---

## 📄 License

MIT License - Use freely in your audits.
