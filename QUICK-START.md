# Quick Start Guide

Get your AI auditing smart contracts in under 2 minutes.

---

## Step 1: Clone This Repository

```bash
git clone https://github.com/0x-Shashi/WEB3-AUDIT-SKILLS.git
```

---

## Step 2: Open in Your IDE

Open the folder for your platform:

| Platform | Folder |
|----------|--------|
| Cursor | `WEB3-AUDIT-SKILLS/cursor/` |
| Antigravity | `WEB3-AUDIT-SKILLS/antigravity/` |
| Claude Code | `WEB3-AUDIT-SKILLS/claude-code/` |

---

## Step 3: Load the Skills

Copy and paste this into your AI chat:

```
Read the security skills from the skills/ folder.
These contain 50,000+ vulnerability patterns from real audits.
Use this knowledge for all security analysis.
Confirm when ready.
```

---

## Step 4: Audit Your Code

Now ask for an audit:

```
Audit contracts/MyContract.sol for security vulnerabilities.
Format findings as [SEVERITY] with description, impact, and fix.
```

---

## Done

Your AI now has access to:

- 50,530 real vulnerability findings
- 207 vulnerability types
- 147 pattern files
- 15 audit firm methodologies

---

## Example Prompts

### Full Audit

```
Perform a complete security audit of all contracts in contracts/.
Check all vulnerability patterns from the skills folder.
Generate a professional report.
```

### Specific Check

```
Check my withdraw function for reentrancy vulnerabilities.
Reference skills/patterns/reentrancy-patterns.md
```

### DeFi Audit

```
This is a lending protocol. Check for:
- Oracle manipulation
- Liquidation bugs
- Flash loan attacks
- Precision loss
```

---

## Need More Help?

- [Full README](README.md)
- [Cursor Guide](cursor/README.md)
- [Antigravity Guide](antigravity/README.md)
- [Claude Code Guide](claude-code/README.md)

