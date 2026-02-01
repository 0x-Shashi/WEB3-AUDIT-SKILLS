---
id: METHOD-AI-AUDITING
title: AI-Assisted Auditing Workflows
category: methodology
difficulty: intermediate
tags: [ai, llm, automation, workflow, prompts]
last_updated: 2026-01-31
---

# AI-Assisted Auditing Workflows

## Overview

AI/LLM tools can significantly accelerate smart contract auditing when used effectively. This guide covers optimal workflows, prompt engineering, and automation strategies.

```
┌─────────────────────────────────────────────────────────────────┐
│                  AI-ASSISTED AUDIT WORKFLOW                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │  Context    │  │  AI-Powered │  │  Human      │             │
│  │  Gathering  │─►│  Analysis   │─►│  Validation │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│        │                │                │                      │
│        ▼                ▼                ▼                      │
│  • Scope files     • Pattern detect  • Verify findings         │
│  • Dependencies    • Vuln suggest    • PoC exploits            │
│  • Documentation   • Code review     • Report writing          │
│                                                                 │
│  AI STRENGTHS            AI LIMITATIONS                         │
│  ────────────            ──────────────                         │
│  • Speed                 • Novel attacks                        │
│  • Pattern matching      • Complex logic                        │
│  • Code comprehension    • Economic analysis                    │
│  • Documentation         • Context nuance                       │
└─────────────────────────────────────────────────────────────────┘
```

---

## Effective AI Audit Workflow

### Phase 1: Context Building

```markdown
# Step 1: Feed the AI context

## Prompt Template for Initial Context
"""
I'm auditing a DeFi protocol. Here's the context:

**Protocol Type:** [Lending/DEX/Vault/Bridge/etc.]
**Main Contracts:** [List key contracts]
**External Dependencies:** [Chainlink, Uniswap, etc.]
**Key Mechanisms:** [How value flows, key operations]

Based on this, what are the highest-priority attack vectors to investigate?
"""

## Good Context Includes:
- Contract architecture overview
- Key state variables and their purpose
- External integrations
- Trust assumptions
- Known constraints
```

### Phase 2: Systematic Analysis

```markdown
# Step 2: Analyze each contract methodically

## Per-Contract Analysis Prompt
"""
Analyze this contract for security vulnerabilities:

```solidity
[PASTE CONTRACT CODE]
```

Focus on:
1. Access control issues
2. Reentrancy vulnerabilities  
3. Integer overflow/underflow
4. Logic errors
5. Oracle manipulation
6. Flash loan attack vectors

For each potential issue:
- Describe the vulnerability
- Explain the attack scenario
- Rate severity (Critical/High/Medium/Low)
- Suggest fix
"""
```

### Phase 3: Cross-Contract Analysis

```markdown
# Step 3: Analyze contract interactions

## Integration Analysis Prompt
"""
Given these two contracts that interact:

Contract A (Vault):
```solidity
[CODE]
```

Contract B (Strategy):
```solidity
[CODE]
```

Analyze potential vulnerabilities in their interaction:
1. Trust assumptions between contracts
2. Callback attack vectors
3. State inconsistency issues
4. Race conditions
5. Value extraction opportunities
"""
```

### Phase 4: Verification & PoC

```markdown
# Step 4: Validate findings with code

## PoC Generation Prompt
"""
I found a potential reentrancy vulnerability in this withdraw function:

```solidity
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    (bool success,) = msg.sender.call{value: amount}("");
    require(success);
    balances[msg.sender] -= amount;
}
```

Generate a Foundry test that demonstrates this exploit.
Include:
1. Attacker contract
2. Test setup
3. Attack execution
4. Assertions proving the exploit
"""
```

---

## Optimized Prompts for Common Tasks

### Vulnerability Pattern Detection

```markdown
## Prompt: Check for Reentrancy
"""
Check this function for reentrancy vulnerabilities.
Consider:
- Direct reentrancy (same function)
- Cross-function reentrancy
- Cross-contract reentrancy
- Read-only reentrancy

```solidity
[FUNCTION CODE]
```

If vulnerable, show the exact attack flow.
"""

## Prompt: Check for Access Control
"""
Audit this contract's access control:

```solidity
[CONTRACT CODE]
```

Check:
1. Are all sensitive functions protected?
2. Is modifier logic correct?
3. Can roles be escalated?
4. Are there any unprotected initializers?
5. tx.origin usage?
"""

## Prompt: Check for Oracle Issues
"""
Analyze oracle usage in this code:

```solidity
[CODE WITH ORACLE CALLS]
```

Check:
1. Staleness checks present?
2. Price bounds validation?
3. Flash loan manipulation possible?
4. Multiple oracle sources?
5. L2 sequencer downtime handling?
"""
```

### Code Understanding

```markdown
## Prompt: Explain Complex Logic
"""
Explain what this function does step by step:

```solidity
[COMPLEX FUNCTION]
```

Include:
1. Purpose of the function
2. Key calculations explained
3. State changes
4. External calls and their effects
5. Return values
"""

## Prompt: Trace Value Flow
"""
Trace how value (tokens/ETH) flows through this protocol:

[CONTRACT CODE OR ARCHITECTURE]

Show:
1. Entry points for value
2. Internal transfers
3. Exit points
4. Fee collection
5. Potential leakage points
"""
```

### Report Writing

```markdown
## Prompt: Format Finding
"""
Format this vulnerability as a professional audit finding:

Vulnerability: [DESCRIPTION]
Affected Code: [CODE SNIPPET]
Impact: [WHAT CAN GO WRONG]

Use this format:
- Title (Severity)
- Description
- Impact
- Proof of Concept
- Recommended Fix
"""

## Prompt: Executive Summary
"""
Based on these findings:
[LIST OF FINDINGS]

Write an executive summary including:
1. Overall security assessment
2. Critical issues summary
3. Key recommendations
4. Scope and methodology
"""
```

---

## Automation Scripts

### Batch Analysis Script

```python
#!/usr/bin/env python3
"""
Automated AI-assisted audit script
Analyzes all Solidity files in a directory
"""

import os
import openai
from pathlib import Path

# Configure your AI provider
openai.api_key = os.environ["OPENAI_API_KEY"]

ANALYSIS_PROMPT = """
Analyze this Solidity contract for security vulnerabilities:

```solidity
{code}
```

Output JSON with this structure:
{{
  "contract_name": "...",
  "vulnerabilities": [
    {{
      "title": "...",
      "severity": "Critical|High|Medium|Low",
      "description": "...",
      "affected_lines": [start, end],
      "recommendation": "..."
    }}
  ],
  "notes": "..."
}}
"""

def analyze_contract(file_path: str) -> dict:
    with open(file_path, 'r') as f:
        code = f.read()
    
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a smart contract security auditor."},
            {"role": "user", "content": ANALYSIS_PROMPT.format(code=code)}
        ],
        temperature=0.1  # Low temperature for consistent analysis
    )
    
    return response.choices[0].message.content

def audit_directory(contracts_dir: str):
    results = {}
    
    for sol_file in Path(contracts_dir).glob("**/*.sol"):
        print(f"Analyzing {sol_file}...")
        try:
            results[str(sol_file)] = analyze_contract(str(sol_file))
        except Exception as e:
            results[str(sol_file)] = {"error": str(e)}
    
    return results

if __name__ == "__main__":
    import sys
    import json
    
    if len(sys.argv) < 2:
        print("Usage: python audit.py <contracts_directory>")
        sys.exit(1)
    
    results = audit_directory(sys.argv[1])
    
    with open("audit_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print("Results saved to audit_results.json")
```

### Foundry Test Generator

```python
#!/usr/bin/env python3
"""
Generate Foundry tests for vulnerabilities
"""

POC_PROMPT = """
Generate a Foundry test that demonstrates this vulnerability:

Contract: {contract_name}
Vulnerability: {vulnerability}
Code:
```solidity
{code}
```

The test should:
1. Set up the vulnerable contract
2. Deploy an attacker contract if needed
3. Execute the attack
4. Assert the exploit succeeded

Output complete, runnable Solidity test code.
"""

def generate_poc(contract_name: str, vulnerability: str, code: str) -> str:
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a security researcher writing exploit PoCs."},
            {"role": "user", "content": POC_PROMPT.format(
                contract_name=contract_name,
                vulnerability=vulnerability,
                code=code
            )}
        ]
    )
    
    return response.choices[0].message.content
```

---

## AI Tool Comparison

| Tool | Best For | Limitations |
|------|----------|-------------|
| **GPT-4** | General analysis, report writing | Context window, cost |
| **Claude** | Long documents, nuanced analysis | Availability |
| **GitHub Copilot** | Code completion, quick fixes | Not audit-focused |
| **Slither** | Static analysis automation | Rule-based only |
| **Mythril** | Symbolic execution | Formal methods |

### Hybrid Workflow

```markdown
## Recommended Tool Chain

1. **Slither** - Initial static analysis
   - Run automated checks
   - Get function call graphs
   - Identify obvious issues

2. **AI (GPT-4/Claude)** - Deep analysis
   - Understand complex logic
   - Check business logic
   - Cross-contract analysis

3. **Foundry** - Validation
   - Write PoC tests
   - Fuzz testing
   - Invariant testing

4. **Human Review** - Final verification
   - Validate AI findings
   - Economic analysis
   - Novel attack vectors
```

---

## Prompt Engineering Best Practices

### 1. Be Specific

```markdown
## BAD Prompt:
"Check this contract for bugs"

## GOOD Prompt:
"Check this ERC4626 vault implementation for:
1. Share inflation attacks
2. Donation attacks
3. Rounding errors in deposit/withdraw
4. First depositor issues

Code:
```solidity
[CODE]
```
"
```

### 2. Provide Context

```markdown
## BAD Prompt:
"Is this function safe?"

## GOOD Prompt:
"This is a lending protocol's liquidation function.
It's called when a position's health factor drops below 1.0.
The protocol uses Chainlink for price feeds.

Is this function safe? Consider:
- Oracle manipulation
- Liquidation cascades
- MEV opportunities

```solidity
[FUNCTION]
```
"
```

### 3. Request Structured Output

```markdown
## BAD Prompt:
"Find vulnerabilities"

## GOOD Prompt:
"Find vulnerabilities and output as:

| Severity | Title | Location | Description | Fix |
|----------|-------|----------|-------------|-----|

Include only High and Critical findings.
"
```

### 4. Iterate on Findings

```markdown
## Follow-up Prompt:
"You identified a reentrancy issue. Let's validate:

1. Can the attacker actually call back into the contract?
2. What's the worst-case financial impact?
3. What's the attack sequence step by step?
4. Write Foundry test proving exploitability.
"
```

---

## Common AI Limitations

### False Positives
```markdown
AI often flags:
- Theoretical issues that aren't exploitable
- Issues mitigated elsewhere in code
- Patterns that look vulnerable but aren't

ALWAYS verify findings manually!
```

### Context Loss
```markdown
AI may miss:
- Cross-file dependencies
- Deployed vs. implementation differences
- Proxy patterns
- External protocol integrations

ALWAYS provide full context!
```

### Novel Attacks
```markdown
AI struggles with:
- New attack patterns not in training data
- Complex economic attacks
- Protocol-specific logic bugs
- Composability exploits

ALWAYS think creatively beyond AI suggestions!
```

---

## Integration with Audit Workflow

```markdown
## Daily Audit Workflow

### Morning (Context Building)
1. Read documentation
2. Map contract architecture
3. Feed context to AI
4. Get initial vulnerability suggestions

### Midday (Deep Analysis)
1. Analyze each contract with AI
2. Focus on AI-identified hot spots
3. Manual review of complex logic
4. Cross-reference with known patterns

### Afternoon (Validation)
1. Write PoC tests for findings
2. Have AI generate test scaffolding
3. Run tests, validate exploits
4. Rate severity accurately

### Evening (Documentation)
1. Use AI to format findings
2. Review and edit AI-generated text
3. Add manual insights
4. Prepare final report sections
```

---

## Security Considerations

```markdown
## When Using AI for Audits

### Data Privacy
- Don't share client code with public AI services without permission
- Use private/enterprise AI instances for sensitive audits
- Anonymize code if needed

### Verification
- NEVER submit AI findings without verification
- Always write PoC tests
- Understand the vulnerability yourself

### Liability
- AI is a tool, not a replacement for expertise
- Auditor is responsible for findings accuracy
- Document AI assistance in methodology
```

---

## Related Resources

- [OpenAI API Documentation](https://platform.openai.com/docs)
- [Anthropic Claude Documentation](https://docs.anthropic.com/)
- [LangChain for Agents](https://docs.langchain.com/)
- [Trail of Bits AI Research](https://blog.trailofbits.com/)
