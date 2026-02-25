# Quick Start Guide

Get your AI auditing smart contracts in under 2 minutes.

---

## Step 1: Clone & Install

```bash
git clone https://github.com/0x-Shashi/WEB3-AUDIT-SKILLS.git
cd WEB3-AUDIT-SKILLS
npm install
```

`npm install` automatically runs setup validation. You'll see a checklist confirming:
- Node.js version ≥ 18
- Skills directory (patterns, scanners, checklists)
- Plugin configuration integrity
- Intelligence modules loaded
- Chain scanners active

---

## Step 2: Verify Installation

```bash
npm run verify
```

This runs the full test suite:
- Validates all 8 setup checks
- Runs a **live pattern-matching test** against known-vulnerable code
- Confirms the pattern matcher detects reentrancy in test code
- Shows pass/fail verdict

Expected output:
```
  ✔ Node.js v20.x.x
  ✔ Skills directory (30+ categories, 12 root files)
  ✔ Plugin v1.0.0 (17 capabilities, 18 chains)
  ✔ Pattern files (140+ .md files)
  ✔ Intelligence modules (4/4)
  ✔ AI instruction files (4/4)
  ✔ Chain scanners (9/9 active)
  ✔ Navigation files (5/5)
  ─────────────────────────────────
  ✔ 8 passed   ⚠ 0 warnings   ✘ 0 failed

Running live pattern-matching test...
  ✔ Pattern matcher found 2 vulnerabilities in test code

 ALL CHECKS PASSED
```

---

## Step 3: Launch MCP Server (Optional)

```bash
npm start
```

This starts the Model Context Protocol server for real-time AI integration.
AI assistants can query vulnerability patterns, calculate severity, and classify findings programmatically.

Or add to Claude Desktop config:
```json
{
  "mcpServers": {
    "web3-audit": {
      "command": "node",
      "args": ["/path/to/WEB3-AUDIT-SKILLS/core/src/mcp-server.js"]
    }
  }
}
```

---

## Step 4: Open in Your IDE

Open the folder for your platform:

| Platform | Folder |
|----------|--------|
| Cursor | `WEB3-AUDIT-SKILLS/cursor/` |
| Antigravity | `WEB3-AUDIT-SKILLS/antigravity/` |
| Claude Code | `WEB3-AUDIT-SKILLS/claude-code/` |

---

## Step 5: Audit Your Code

Now ask for an audit:

```
Audit contracts/MyContract.sol for security vulnerabilities.
Format findings as [SEVERITY] with description, impact, and fix.
```

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `npm install` | Install deps + auto-validate setup |
| `npm run verify` | Full verification with live pattern test |
| `npm run info` | Show capabilities, chains, and stats |
| `npm start` | Launch MCP server |
| `npx web3-audit doctor` | Diagnose issues with fix suggestions |

---

## Done

Your AI now has access to:

- 50,530 real vulnerability findings
- 207 vulnerability types
- 147 pattern files
- 15 audit firm methodologies
- Programmatic validation that everything works

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

## Troubleshooting

If setup fails, run:
```bash
npx web3-audit doctor
```

This shows exactly what's wrong and how to fix it.

---

## Need More Help?

- [Full README](README.md)
- [Cursor Guide](cursor/README.md)
- [Antigravity Guide](antigravity/README.md)
- [Claude Code Guide](claude-code/README.md)

