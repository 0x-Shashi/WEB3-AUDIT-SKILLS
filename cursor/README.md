# Web3 Audit Skills - Cursor IDE

Transform Cursor into a smart contract security auditor with 50,530 vulnerability patterns.

---

## What You Get

| Feature | Details |
|---------|---------|
| Vulnerability Patterns | 149 pattern files covering 207 vulnerability types |
| Reentrancy Deep-Dive | 6 specialized reentrancy variant patterns |
| Exploit Forensics | 3 CSI-style case studies (DAO, Wormhole, Ronin) |
| Protocol Playbooks | 3 integration guides (Uniswap V3, Aave V3, Lido) |
| Evolution Timelines | 3 historical vulnerability evolution tracks |
| Learning Paths | 3 structured curricula (140 hours total) |
| Severity Files | HIGH, MEDIUM, LOW, GAS classifications |
| Audit Firm Knowledge | 15 source files from top security firms |

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
    |-- cursor/
        |-- .cursorrules
        |-- skills/
```

### Option 2: Clone Separately

Clone anywhere and open both folders in Cursor:

```bash
git clone https://github.com/0x-Shashi/WEB3-AUDIT-SKILLS.git
```

Then open your project and add the WEB3-AUDIT-SKILLS folder to your workspace.

---

## How It Works

Cursor AI reads the `.cursorrules` file and the `skills/` folder when you open the workspace. This gives the AI knowledge of:

| What It Learns | Count |
|----------------|-------|
| Vulnerability patterns | 149 files |
| Reentrancy variants | 6 deep-dive files |
| Exploit case studies | 3 forensic analyses |
| Protocol playbooks | 3 integration guides |
| Evolution timelines | 3 historical tracks |
| Learning paths | 3 curricula (140 hours) |
| Severity classifications | 4 files |
| Audit firm knowledge | 15 files |
| Total findings | 50,530 |

When you ask Cursor to audit code, it uses this knowledge to find vulnerabilities.

---

## Configuration

### Using .cursorrules

The `.cursorrules` file in this folder tells Cursor how to behave. You can either:

**Option A: Copy to project root**

Copy `.cursorrules` to your project root:

```bash
cp WEB3-AUDIT-SKILLS/cursor/.cursorrules ./
```

**Option B: Reference in Cursor settings**

1. Open Cursor Settings
2. Go to "Rules for AI"
3. Add a reference to the skills folder

---

## Using the Skills

### Step 1: Tell the AI to Load Skills

Start your conversation with:

```
Read the security skills from WEB3-AUDIT-SKILLS/cursor/skills/ folder. 
Use this knowledge for all security analysis.
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

---

## Folder Structure

```
cursor/
|-- .cursorrules              # Cursor configuration
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

## Troubleshooting

### AI does not seem to know the patterns

Make sure you tell the AI to read the skills folder first:

```
Read all files in WEB3-AUDIT-SKILLS/cursor/skills/ before auditing.
```

---

### AI gives generic security advice

Be specific about which pattern file to use:

```
Using skills/patterns/reentrancy-patterns.md, check my withdraw function.
```

---

### Skills folder is not being read

Check that Cursor can see the folder:
- The folder should be in your workspace
- Try referencing the full path

---

## Back to Main

See the [main README](../README.md) for general information.

---

## Other Platforms

- [Antigravity Setup](../antigravity/README.md)
- [Claude Code Setup](../claude-code/README.md)

