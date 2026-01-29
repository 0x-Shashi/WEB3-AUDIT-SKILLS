# 🚀 Quick Start Guide

## Step 1: Clone This Repo

```bash
# In your project directory
git clone https://github.com/YOUR_USERNAME/web3-audit-skills.git
```

Your folder structure:
```
your-project/
├── contracts/           # Your smart contracts
└── web3-audit-skills/   # This repo
```

---

## Step 2: Tell Your AI

### Claude Code
```
Use the skills from ./web3-audit-skills/claude-code folder to audit my 
smart contracts in contracts/. Apply all security patterns and checklists.
```

### Cursor
```
Read .cursorrules from ./web3-audit-skills/cursor and use those skills 
to analyze my Solidity contracts for security vulnerabilities.
```

### Antigravity
```
Load the skills from ./web3-audit-skills/antigravity and perform a 
security audit of my project.
```

---

## Step 3: Solodit API (Optional)

Get your API key from [solodit.xyz](https://solodit.xyz), then:

```
My Solodit API key is: sk_your_key_here

Search Solodit for vulnerabilities similar to my Vault.sol contract.
```

---

## Example Prompts

### Full Audit
```
Using web3-audit-skills, perform a complete security audit of all 
contracts in my contracts/ folder. Check for reentrancy, access control, 
oracle manipulation, and all common vulnerabilities. Generate a report 
with findings by severity.
```

### Specific Check
```
Use the solidity-scanner skill from web3-audit-skills to check my 
Staking.sol for reentrancy vulnerabilities.
```

### Token Analysis
```
Apply the token-analyzer skill to check if the external token at 
0x123... has any weird ERC20 behaviors that could break my integration.
```

### Compare Versions
```
Using differential-review skill, compare contracts/v1/Vault.sol with 
contracts/v2/Vault.sol and identify any security regressions.
```

---

## What Happens

1. AI reads the skills from this repo
2. AI learns vulnerability patterns, checklists, methodologies
3. AI applies these to YOUR project
4. AI reports findings with severity, impact, and fixes
5. (Optional) AI searches Solodit for similar real-world vulnerabilities

---

## Supported Blockchains

| Your Code | AI Uses |
|-----------|---------|
| `.sol` files | solidity-scanner |
| Rust/Anchor | solana-scanner |
| Cairo | cairo-scanner |
| Move | move-scanner |
| CosmWasm | cosmos-scanner |
| FunC/Tact | ton-scanner |

---

## Need Help?

Tell your AI:
```
Read the AI-INSTRUCTIONS.md in web3-audit-skills for guidance on 
how to use these audit skills.
```
