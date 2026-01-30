# Contributing to WEB3-AUDIT-SKILLS

First off, thanks for considering contributing! 🎉 This project thrives on community knowledge from security researchers, auditors, and developers.

---

## 🤝 How You Can Contribute

### 1. Add New Vulnerability Patterns

Found a bug pattern that's not covered? Add it!

**Location:** `skills/patterns/` or relevant scanner folder

**Format:**
```markdown
### PATTERN-ID: Pattern Name

**Severity:** Critical/High/Medium/Low
**Likelihood:** High/Medium/Low

**Description:**
What the vulnerability is and why it's dangerous.

**Vulnerable Code:**
```solidity
// Bad code example
```

**Secure Code:**
```solidity
// Fixed code example
```

**Detection:**
```bash
grep -rn "pattern" --include="*.sol"
```

**Real-World Example:**
- Protocol: [Name]
- Loss: $X
- Link: [Reference]
```

### 2. Add New Chain Support

Want to add a new blockchain? Create a scanner!

**Location:** `cursor/skills/[chain]-scanner/`

**Required Files:**
```
[chain]-scanner/
├── SKILL.md              # Main skill file
├── resources/
│   └── [chain]-patterns.md
└── workflows/
    └── [chain]-audit.md
```

### 3. Add Protocol Templates

Know a protocol type deeply? Create a template!

**Location:** `cursor/skills/advanced/protocol-templates/`

**Include:**
- Architecture diagram
- Critical functions
- Protocol-specific vulnerabilities
- Audit checklist
- Real exploit examples

### 4. Add Attack Chains

Discovered a multi-vulnerability exploit path? Document it!

**Location:** `cursor/skills/advanced/attack-chains/`

### 5. Improve Existing Content

- Fix errors or typos
- Add better code examples
- Update with new exploits
- Improve detection commands
- Add references

### 6. Report Issues

- False positives/negatives
- Missing patterns
- Outdated information
- Broken commands

---

## 📋 Contribution Process

### Step 1: Fork & Clone

```bash
# Fork the repo on GitHub, then:
git clone https://github.com/YOUR-USERNAME/WEB3-AUDIT-SKILLS.git
cd WEB3-AUDIT-SKILLS
```

### Step 2: Create Branch

```bash
git checkout -b feature/your-feature-name

# Examples:
git checkout -b pattern/new-reentrancy-variant
git checkout -b scanner/stellar-support
git checkout -b fix/typo-in-lending-template
```

### Step 3: Make Changes

Follow the existing format in similar files.

### Step 4: Test Your Changes

```bash
# Ensure markdown is valid
# Check grep commands work
# Verify code examples compile (if applicable)
```

### Step 5: Commit

```bash
git add .
git commit -m "Add: brief description of change"

# Commit message prefixes:
# Add: New feature or content
# Fix: Bug fix or correction
# Update: Improvement to existing content
# Docs: Documentation only
```

### Step 6: Push & Create PR

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub.

---

## ✅ Contribution Guidelines

### DO ✅

- **Use real examples** - Patterns should come from actual exploits
- **Include references** - Link to sources (audits, post-mortems, etc.)
- **Follow existing format** - Consistency makes the repo usable
- **Test detection commands** - Make sure grep/regex patterns work
- **Keep it practical** - Focus on actionable patterns

### DON'T ❌

- **No theoretical-only patterns** - Must have real-world basis
- **No proprietary content** - Don't copy paid audit reports verbatim
- **No malicious content** - No actual exploit code that could be weaponized
- **No low-quality submissions** - Take time to make it good

---

## 🏷️ Pattern Naming Convention

```
[CATEGORY]-[NUMBER]: [Name]

Examples:
RE-01: Classic Reentrancy
AC-05: Missing Role Check
OR-03: Stale Oracle Price
FL-02: Flash Loan Price Manipulation
```

### Categories:
| Prefix | Category |
|--------|----------|
| RE | Reentrancy |
| AC | Access Control |
| OR | Oracle |
| FL | Flash Loan |
| IV | Input Validation |
| AR | Arithmetic |
| DE | Denial of Service |
| FR | Front-running |
| UP | Upgrade |
| BR | Bridge |
| GV | Governance |
| TK | Token |
| LP | Liquidity Pool |
| ST | Staking |
| LN | Lending |

---

## 📊 Quality Checklist

Before submitting, ensure:

- [ ] Pattern is from real exploit or audit finding
- [ ] Description is clear and actionable
- [ ] Vulnerable code example is realistic
- [ ] Secure code example actually fixes the issue
- [ ] Detection command works
- [ ] Reference/source is included
- [ ] Follows existing format
- [ ] No spelling/grammar errors
- [ ] Tested in at least one AI tool

---

## 🎯 Priority Areas

We especially need contributions in:

1. **Emerging Chains** - Monad, Berachain, Sei, etc.
2. **New Attack Patterns** - 2024-2026 exploits
3. **ZK Patterns** - ZK rollup vulnerabilities
4. **Cross-chain** - Bridge and messaging patterns
5. **MEV Patterns** - Sandwich, JIT, etc.
6. **AI-Specific** - Patterns AI commonly misses

---

## 💬 Getting Help

- **Questions?** Open a GitHub Discussion
- **Found a bug?** Open an Issue
- **Want to discuss a pattern?** Open a Discussion first
- **Security issue in the repo itself?** Email maintainers privately

---

## 🏆 Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Credited in release notes
- Part of the security community helping everyone

---

## 📜 Legal

By contributing, you agree that your contributions will be licensed under the same license as this project (MIT License). You confirm that you have the right to submit the contribution.

---

Thank you for helping make Web3 more secure! 🛡️
