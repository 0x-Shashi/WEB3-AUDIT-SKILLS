# Frequently Asked Questions

## General Questions

### What is this exactly?
A collection of structured markdown files that enhance AI assistants (Claude, GPT, etc.) with expert-level Web3 security knowledge. Think of it as "expert knowledge plugins" for AI.

### How is this different from just asking ChatGPT to audit my code?
| Generic AI | AI + This System |
|------------|------------------|
| General knowledge | 1,000+ specific vulnerability patterns |
| May miss protocol-specific issues | Protocol templates (DEX, Lending, etc.) |
| No systematic coverage | Comprehensive checklists |
| Random depth | Consistent thoroughness |
| No attack chain mapping | Identifies multi-vulnerability exploits |

### Does this replace human auditors?
**No.** This is a force multiplier for auditors, not a replacement. Use it for:
- First-pass scanning
- Systematic coverage
- Consistency across audits
- Learning tool for junior auditors

### What chains are supported?
- **EVM**: Ethereum, BSC, Polygon, Arbitrum, Optimism, etc.
- **Solana**: Rust/Anchor programs
- **Move**: Sui, Aptos
- **Cairo**: Starknet
- **Others**: TON, Cosmos, FuelVM, Aztec (Noir)

---

## Technical Questions

### How do I use this?

**Option 1: Cursor IDE**
```bash
git clone https://github.com/[repo]
# Open in Cursor
# Skills auto-load from cursor/skills/
```

**Option 2: Claude/ChatGPT**
```
Copy relevant skill files into your conversation
"Here are my audit patterns: [paste skill content]"
"Now audit this contract: [paste code]"
```

**Option 3: Any LLM**
```
Include skill content in system prompt or context
```

### What's in a "skill" file?
```markdown
# Skill Name

## Purpose
What this skill does

## Patterns
Specific vulnerability patterns with:
- Description
- Vulnerable code example
- Secure code example
- Detection commands

## Checklist
Step-by-step audit items
```

### Can I add my own patterns?
Yes! Just add markdown files following the existing format:
```bash
# Create new pattern file
echo "# My Pattern" > skills/patterns/my-pattern.md

# Add your patterns
# Commit and use
```

### How are patterns updated?
- Monitor new exploits (Rekt, Immunefi, etc.)
- Extract patterns from audit reports
- Community contributions via PR
- Regular consolidation and deduplication

---

## Security Questions

### Is my code safe?
Your code goes to whatever AI provider you use (Claude, OpenAI, etc.). The skill system itself:
- Runs entirely locally
- Contains no executable code
- Makes no network requests
- Is fully readable markdown

### Can I use this for private audits?
Yes, but remember:
- AI providers may log conversations
- Review their privacy policies
- Consider self-hosted LLMs for sensitive code

### What if AI misses a bug?
- AI audits are not guarantees
- Always combine with other tools (Slither, etc.)
- Human review for critical findings
- Use as one layer of defense

### Has this system been audited?
The skill system is:
- Open source (audit it yourself)
- Only markdown files (no attack surface)
- Community reviewed
- Continuously improved

---

## Effectiveness Questions

### What's the detection rate?
For **known pattern types**: High (patterns are from real exploits)
For **novel vulnerabilities**: Lower (limited to pattern matching)
For **business logic bugs**: Moderate (context-dependent)

### What does this catch well?
 Reentrancy variants
 Access control issues
 Oracle manipulation patterns
 Common DeFi vulnerabilities
 Known attack vectors

### What might this miss?
 Novel attack vectors
 Complex economic exploits
 Protocol-specific edge cases
 Cross-contract interactions (context limits)
 Timing-based attacks

### How does it compare to static analysis?
| Aspect | Static Analysis | AI + Skills |
|--------|-----------------|-------------|
| Speed | Fast | Moderate |
| False positives | Higher | Lower |
| Context understanding | Limited | Better |
| Novel patterns | No | Sometimes |
| Business logic | No | Partial |
| Best for | CI/CD gates | Deep review |

**Recommendation**: Use both together.

---

## Business Questions

### Is this free?
Yes, the skill system is open source. You only pay for:
- AI API usage (Claude, OpenAI, etc.)
- Your time

### Can I use this commercially?
Check the license. Generally:
- Use for client audits: 
- Modify for internal use: 
- Attribution required: Check license
- Resell as product: Check license

### Who made this?
Security researchers and auditors who wanted to:
- Systematize their knowledge
- Scale their expertise
- Share with the community

---

## Comparison Questions

### vs. Slither/Mythril/etc.
Those are **static analyzers** - they parse code deterministically.
This is **AI augmentation** - enhances AI reasoning with patterns.

**Use both!**

### vs. Paid audit services
This is a **tool**, not a **service**.
- No liability coverage
- No audit certificate
- No human expert review
- Just enhanced AI capabilities

### vs. Fine-tuned security models
| Fine-tuning | Skill System |
|-------------|--------------|
| Black box | Transparent |
| Expensive to update | Edit markdown |
| Fixed patterns | Instant updates |
| Vendor lock-in | Portable |

---

## Getting Started

### Minimum viable usage:
1. Clone repo
2. Copy `skills/patterns/` content
3. Paste into Claude/ChatGPT
4. Ask to audit your code

### Recommended setup:
1. Use Cursor IDE with skills directory
2. Enable Claude integration
3. Run "full-audit chain" command
4. Review and verify findings

### Learning path:
1. Read `HOW-IT-WORKS.md`
2. Try `quick-scan-chain` on known vulnerable code
3. Study `attack-chains/` for exploit patterns
4. Practice on CTF challenges
5. Apply to real audits with human verification
