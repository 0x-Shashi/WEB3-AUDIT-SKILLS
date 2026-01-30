# Web3 Audit Skills - Antigravity

This guide shows you how to use the Web3 Audit Skills with Antigravity IDE.

---

## Table of Contents

- [Installation](#installation)
- [How It Works](#how-it-works)
- [Configuration](#configuration)
- [Using the Skills](#using-the-skills)
- [Example Prompts](#example-prompts)
- [Skills Reference](#skills-reference)
- [Troubleshooting](#troubleshooting)

---

## Installation

### Option 1: Clone to Your Project (Recommended)

Clone the repository into your project folder:

```bash
cd your-smart-contract-project/
git clone https://github.com/0x-Shashi/WEB3-AUDIT-SKILLS.git
```

Your folder structure will look like:

```
your-project/
|-- contracts/
|-- src/
|-- WEB3-AUDIT-SKILLS/
    |-- antigravity/
        |-- antigravity.yaml
        |-- skills/
```

### Option 2: Clone Separately

Clone anywhere and open both folders in Antigravity:

```bash
git clone https://github.com/0x-Shashi/WEB3-AUDIT-SKILLS.git
```

Then open your project and add the WEB3-AUDIT-SKILLS folder to your workspace.

---

## How It Works

Antigravity AI reads the `antigravity.yaml` file and the `skills/` folder when you open the workspace. This gives the AI knowledge of:

| What It Learns | Count |
|----------------|-------|
| Vulnerability patterns | 147 files |
| Severity classifications | 4 files |
| Audit firm knowledge | 15 files |
| Total findings | 50,530 |

When you ask Antigravity to audit code, it uses this knowledge to find vulnerabilities.

---

## Configuration

The `antigravity.yaml` file in this folder configures the plugin. Antigravity will automatically detect it when you open the folder.

If you want to customize settings, edit `antigravity.yaml`:

```yaml
name: web3-security-audit
version: 1.0.0
description: Web3 Security Audit Skills

skills:
  - path: ./skills
    auto_load: true

settings:
  severity_threshold: low
  output_format: markdown
```

---

## Using the Skills

### Step 1: Tell the AI to Load Skills

Start your conversation with:

```
Read the security skills from WEB3-AUDIT-SKILLS/antigravity/skills/ folder. 
Use this knowledge for all security analysis.

Confirm when you have loaded the skills.
```

### Step 2: Audit Your Code

Now ask for an audit:

```
Audit contracts/MyContract.sol for security vulnerabilities.
```

### Step 3: Get Detailed Findings

The AI will return findings like:

```
[HIGH] Reentrancy in withdraw function
- Description: The function sends ETH before updating state
- Impact: Attacker can drain all funds  
- Pattern Reference: skills/patterns/reentrancy-patterns.md
- Recommendation: Move state update before external call
```

---

## Example Prompts

### Full Contract Audit

```
Using the skills from the skills/ folder, perform a complete 
security audit of all contracts in my contracts/ directory.

Check for all vulnerability patterns and generate a report.
```

---

### Check Specific Vulnerability

```
Check my Vault.sol contract for first-depositor attack vulnerability.
Reference skills/patterns/first-depositor-issue-patterns.md for the pattern.
```

---

### Create and Audit in One Go

```
1. Read the security skills from skills/ folder

2. Create a SimpleVault.sol contract with:
   - ETH deposit/withdraw with share tokens
   - Owner fee mechanism
   - User balance tracking

3. Audit the contract you created for vulnerabilities

Format findings as [HIGH/MEDIUM/LOW] with description, impact, and fix.
```

---

### DeFi Protocol Audit

```
This is a lending protocol. Using the relevant DeFi patterns from the skills folder:
- Check oracle integration
- Check liquidation logic  
- Check for flash loan attacks
- Check for precision loss in interest calculations
```

---

### Generate Audit Report

```
Create a professional security audit report for this codebase.

Include:
- Executive summary
- Findings organized by severity
- Code references
- Recommendations

Use the format from skills/MASTER_CHECKLIST.md
```

---

### Compare to Known Exploits

```
I am using Chainlink price feeds.
Check skills/patterns/chainlink-patterns.md and skills/patterns/oracle-patterns.md
to see if my implementation matches any known vulnerability patterns.
```

---

### Token Security Review

```
Audit my ERC20 token implementation.

Check against:
- skills/patterns/erc20-patterns.md
- skills/patterns/weird-erc20-patterns.md
- skills/patterns/fee-on-transfer-patterns.md
- skills/patterns/rebasing-tokens-patterns.md
```

---

### L2-Specific Audit

```
My contract will deploy on Arbitrum.

Check skills/patterns/arbitrum-patterns.md and skills/patterns/l2-security.md
for L2-specific vulnerabilities.
```

---

## Skills Reference

### Patterns Folder

Contains 147 vulnerability pattern files. Key files:

| File | Description |
|------|-------------|
| reentrancy-patterns.md | Classic, read-only, cross-function reentrancy |
| access-control-patterns.md | Missing modifiers, privilege issues |
| oracle-patterns.md | Price manipulation, stale prices |
| flash-loan-patterns.md | Flash loan attack vectors |
| first-depositor-issue-patterns.md | Vault share inflation |
| precision-loss-patterns.md | Rounding and truncation errors |
| front-running-patterns.md | MEV and sandwich attacks |
| liquidation-patterns.md | Liquidation logic bugs |

See [skills/INDEX.md](skills/INDEX.md) for the complete list.

---

### Severity Folder

| File | When To Use |
|------|-------------|
| high-severity.md | Direct fund loss, protocol insolvency |
| medium-severity.md | Conditional exploits, limited damage |
| low-severity.md | Edge cases, informational |
| gas-optimizations.md | Efficiency improvements |

---

### Sources Folder

Patterns from specific audit firms:

| File | Firm |
|------|------|
| code4rena.md | Code4rena contests |
| sherlock.md | Sherlock contests |
| openzeppelin.md | OpenZeppelin audits |
| trailofbits.md | Trail of Bits audits |
| spearbit.md | Spearbit audits |
| cyfrin.md | Cyfrin audits |

---

## Folder Structure

```
antigravity/
|-- antigravity.yaml          # Antigravity configuration
|-- README.md                 # This file
|-- skills/
    |-- INDEX.md              # Navigation guide
    |-- MASTER_CHECKLIST.md   # Complete audit checklist
    |-- STATISTICS.md         # Data analysis
    |-- patterns/             # 147 vulnerability patterns
    |-- severity/             # 4 severity files
    |-- sources/              # 15 audit firm files
    |-- checklists/           # Audit checklists
    |-- methodology/          # Audit workflows
```

---

## Tested Example

We tested this with Antigravity and got excellent results. The AI:

1. Created a vulnerable contract with 3 intentional bugs
2. Found all 3 bugs correctly (reentrancy, first-depositor, access control)
3. Referenced the exact pattern files
4. Provided step-by-step attack scenarios
5. Suggested correct fixes

See the main README for details on the test.

---

## Troubleshooting

### AI does not seem to know the patterns

Make sure you tell the AI to read the skills folder first:

```
Read all files in WEB3-AUDIT-SKILLS/antigravity/skills/ before auditing.
```

---

### AI gives generic security advice

Be specific about which pattern file to use:

```
Using skills/patterns/reentrancy-patterns.md, check my withdraw function.
```

---

### Skills folder is not being read

Check that Antigravity can see the folder:
- The folder should be in your workspace
- Try referencing the full path

---

### AI is not referencing pattern files

Explicitly ask it to:

```
When you find a vulnerability, reference the specific pattern file 
from skills/patterns/ that matches the issue.
```

---

## Back to Main

See the [main README](../README.md) for general information.

---

## Other Platforms

- [Cursor Setup](../cursor/README.md)
- [Claude Code Setup](../claude-code/README.md)

