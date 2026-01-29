# Web3 Audit Skills - Claude Code

This guide shows you how to use the Web3 Audit Skills with Claude Code IDE.

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
    |-- claude-code/
        |-- plugin.json
        |-- skills/
```

### Option 2: Clone Separately

Clone anywhere and open both folders in Claude Code:

```bash
git clone https://github.com/0x-Shashi/WEB3-AUDIT-SKILLS.git
```

Then open your project and add the WEB3-AUDIT-SKILLS folder to your workspace.

---

## How It Works

Claude Code reads the `plugin.json` file and the `skills/` folder when you open the workspace. This gives Claude knowledge of:

| What It Learns | Count |
|----------------|-------|
| Vulnerability patterns | 147 files |
| Severity classifications | 4 files |
| Audit firm knowledge | 15 files |
| Total findings | 50,530 |

When you ask Claude to audit code, it uses this knowledge to find vulnerabilities.

---

## Configuration

The `plugin.json` file in this folder configures the plugin. Claude Code will automatically detect it when you open the folder.

Current configuration:

```json
{
  "name": "web3-security-audit",
  "version": "1.0.0",
  "description": "Web3 Security Audit Skills for Claude Code",
  "skills": {
    "directory": "./skills",
    "auto_load": true
  }
}
```

---

## Using the Skills

### Step 1: Tell Claude to Load Skills

Start your conversation with:

```
Read the security skills from WEB3-AUDIT-SKILLS/claude-code/skills/ folder. 
Use this knowledge for all security analysis.
```

### Step 2: Audit Your Code

Now ask for an audit:

```
Audit contracts/MyContract.sol for security vulnerabilities.
```

### Step 3: Get Detailed Findings

Claude will return findings like:

```
[HIGH] Reentrancy in withdraw function

Description: The function sends ETH before updating state

Impact: Attacker can drain all funds

Pattern Reference: skills/patterns/reentrancy-patterns.md (Example 6)

Recommendation: Move _burn() before the external call
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

### Cross-Chain Security

```
My contract uses LayerZero for cross-chain messaging.

Check skills/patterns/layerzero-patterns.md and skills/patterns/bridge-patterns.md
for cross-chain vulnerabilities.
```

---

### Upgradeable Contract Review

```
My contract uses the UUPS proxy pattern.

Check skills/patterns/upgradable-patterns.md and skills/patterns/initializer-patterns.md
for upgrade-related vulnerabilities.
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
| bridge-patterns.md | Cross-chain vulnerabilities |

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
| consensys.md | Consensys Diligence |
| quantstamp.md | Quantstamp audits |

---

## Folder Structure

```
claude-code/
|-- plugin.json               # Claude Code configuration
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

## Claude-Specific Tips

### Use Claude's Strength with Long Context

Claude can read all the pattern files at once. Take advantage of this:

```
Read ALL files in the patterns/ folder, then audit my contract.
Cross-reference multiple patterns to find complex vulnerabilities.
```

---

### Ask for Detailed Analysis

Claude excels at detailed explanations:

```
For each vulnerability you find:
1. Quote the vulnerable code
2. Explain the attack step by step
3. Reference the pattern file that matches
4. Show the fixed code
5. Explain why the fix works
```

---

### Chain Multiple Audits

```
First, audit contracts/Token.sol
Then, audit contracts/Vault.sol  
Finally, check if there are any cross-contract vulnerabilities 
between the two contracts.
```

---

## Troubleshooting

### Claude does not seem to know the patterns

Make sure you tell Claude to read the skills folder first:

```
Read all files in WEB3-AUDIT-SKILLS/claude-code/skills/ before auditing.
```

---

### Claude gives generic security advice

Be specific about which pattern file to use:

```
Using skills/patterns/reentrancy-patterns.md, check my withdraw function.
```

---

### Skills folder is not being read

Check that Claude can see the folder:
- The folder should be in your workspace
- Try referencing the full path

---

### Claude is not referencing pattern files

Explicitly ask it to:

```
When you find a vulnerability, reference the specific pattern file 
from skills/patterns/ that matches the issue. Include the example number.
```

---

## Back to Main

See the [main README](../README.md) for general information.

---

## Other Platforms

- [Cursor Setup](../cursor/README.md)
- [Antigravity Setup](../antigravity/README.md)
