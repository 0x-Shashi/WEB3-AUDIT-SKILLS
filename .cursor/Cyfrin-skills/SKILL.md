# Cyfrin Skill - Smart Contract Security Knowledge System

## Quick Start

This skill system leverages the **Cyfrin Solodit API** to provide intelligent smart contract security guidance based on **50,000+ real audit findings** from the world's top security firms.

**Purpose:** Help developers write secure smart contracts by learning from real vulnerabilities found in production code.

## Setup

### 1. Get Your Cyfrin API Key

1. Create an account at [solodit.cyfrin.io](https://solodit.cyfrin.io)
2. Click your profile dropdown in the top right corner
3. Open "API Keys" modal and generate a new API key

### 2. Set Environment Variable

**Linux/macOS:**
```bash
export CYFRIN_API_KEY="sk_your_api_key_here"
# Add to ~/.bashrc or ~/.zshrc for persistence
```

**Windows PowerShell:**
```powershell
$env:CYFRIN_API_KEY = "sk_your_api_key_here"
# For persistence, add to your PowerShell profile
```

### 3. Verify Setup

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{"page": 1, "pageSize": 1}'
```

## API Overview

**Base URL:** `https://solodit.cyfrin.io/api/v1/solodit`  
**Endpoint:** `/findings`  
**Method:** `POST`  
**Rate Limit:** 20 requests per 60 seconds

## Skill System Architecture

```
cyfrin-skill/
├── SKILL.md                    ← YOU ARE HERE (Orchestrator)
├── api-integration/            ← API usage and query building
├── vulnerability-tags/         ← Vulnerability type reference
├── protocol-categories/        ← Protocol-specific security
├── audit-firms/                ← Auditor expertise reference
├── workflows/                  ← Security workflow guides
├── examples/                   ← Real-world examples
└── languages/                  ← Language-specific guidance
```

## Sub-Skill Reference

| Folder | Purpose | When to Use |
|--------|---------|-------------|
| [api-integration/](api-integration/SKILL.md) | API queries, filtering, caching | Building or debugging API calls |
| [vulnerability-tags/](vulnerability-tags/SKILL.md) | Vulnerability types and patterns | Checking specific vulnerability types |
| [protocol-categories/](protocol-categories/SKILL.md) | DeFi, NFT, Lending, etc. | Building specific protocol types |
| [audit-firms/](audit-firms/SKILL.md) | Auditor expertise | Finding credible sources |
| [workflows/](workflows/SKILL.md) | Security processes | Pre-audit, code review |
| [examples/](examples/SKILL.md) | Real exploits and patterns | Learning from past issues |
| [languages/](languages/SKILL.md) | Solidity, Rust, Cairo, etc. | Language-specific security |

## Decision Tree: Which Skill to Use

```
User Request
    │
    ├─► "Check my code for vulnerabilities"
    │   └─► Use: vulnerability-tags/ + workflows/code-review.md
    │
    ├─► "I'm building a [DeFi/NFT/Lending] protocol"
    │   └─► Use: protocol-categories/[category].md
    │
    ├─► "What is [reentrancy/oracle/flash loan] vulnerability?"
    │   └─► Use: vulnerability-tags/[tag].md
    │
    ├─► "Show me best security practices"
    │   └─► Use: examples/best-practices.md + audit-firms/
    │
    ├─► "Prepare for an audit"
    │   └─► Use: workflows/audit-preparation.md
    │
    ├─► "Find issues like X from [Cyfrin/Trail of Bits]"
    │   └─► Use: audit-firms/[firm].md
    │
    ├─► "What security issues in [Solidity/Rust]?"
    │   └─► Use: languages/[language].md
    │
    └─► "How do I query the Solodit API?"
        └─► Use: api-integration/
```

## Claude Workflow: From Query to Advice

### Step 1: Identify Context

When a user asks for security help:

1. **Determine the protocol type** (DeFi, NFT, Lending, Bridge, etc.)
2. **Identify the specific functionality** (swap, withdraw, mint, stake)
3. **Note the programming language** (Solidity, Rust, Cairo)
4. **Assess the development phase** (design, development, pre-audit)

### Step 2: Select Relevant Skills

Based on context, consult:

1. **Primary skill** - Most relevant to the specific question
2. **Secondary skills** - Related vulnerability types
3. **Workflow skill** - If process guidance needed

### Step 3: Build API Query

Using [api-integration/query-construction.md](api-integration/query-construction.md):

```json
{
  "page": 1,
  "pageSize": 30,
  "filters": {
    "keywords": "[user's function/feature]",
    "impact": ["HIGH", "MEDIUM"],
    "protocolCategory": [{"value": "[relevant category]"}],
    "tags": [{"value": "[relevant vulnerability type]"}],
    "qualityScore": 3,
    "sortField": "Quality",
    "sortDirection": "Desc"
  }
}
```

### Step 4: Generate Advice

From API results, provide:

1. **Top 3-5 relevant vulnerabilities** with summaries
2. **Code patterns to avoid** (from finding content)
3. **Recommended mitigations** (from fix descriptions)
4. **Checklist of security considerations**

## Common Use Cases

### Use Case 1: Pre-Development Security Research

**User says:** "I'm building a lending protocol. What should I watch out for?"

**Action:**
1. Consult: `protocol-categories/lending.md`
2. Query API for lending-specific HIGH severity issues
3. Consult: `vulnerability-tags/oracle.md`, `vulnerability-tags/flash-loan.md`
4. Provide: Top vulnerabilities, security checklist, best practices

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 30,
    "filters": {
      "protocolCategory": [{"value": "Lending"}],
      "impact": ["HIGH"],
      "qualityScore": 4,
      "sortField": "Quality"
    }
  }'
```

### Use Case 2: Function-Level Security Check

**User says:** "Is my withdraw function secure?"

**Action:**
1. Consult: `vulnerability-tags/reentrancy.md`, `vulnerability-tags/access-control.md`
2. Query API with function-specific keywords
3. Consult: `workflows/function-security-check.md`
4. Provide: Specific vulnerabilities, code patterns, mitigation steps

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 25,
    "filters": {
      "keywords": "withdraw",
      "tags": [
        {"value": "Reentrancy"},
        {"value": "Access Control"}
      ],
      "impact": ["HIGH", "MEDIUM"]
    }
  }'
```

### Use Case 3: Learning from Past Exploits

**User says:** "Show me examples of oracle manipulation attacks."

**Action:**
1. Consult: `vulnerability-tags/oracle.md`, `vulnerability-tags/price-manipulation.md`
2. Consult: `examples/high-severity-exploits.md`
3. Query API for high-quality oracle findings
4. Provide: Real examples, attack patterns, prevention strategies

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 20,
    "filters": {
      "tags": [
        {"value": "Oracle"},
        {"value": "Price Manipulation"}
      ],
      "impact": ["HIGH"],
      "qualityScore": 4,
      "sortField": "Quality"
    }
  }'
```

### Use Case 4: Audit Preparation

**User says:** "Help me prepare for a security audit."

**Action:**
1. Consult: `workflows/audit-preparation.md`
2. Consult: `audit-firms/SKILL.md` for understanding auditor focus
3. Run comprehensive security queries
4. Provide: Preparation checklist, common issues, documentation requirements

## API Quick Reference

### Basic Query
```json
{"page": 1, "pageSize": 50, "filters": {"impact": ["HIGH"]}}
```

### Filter by Vulnerability Type
```json
{"filters": {"tags": [{"value": "Reentrancy"}]}}
```

### Filter by Protocol Category
```json
{"filters": {"protocolCategory": [{"value": "DeFi"}]}}
```

### Filter by Audit Firm
```json
{"filters": {"firms": [{"value": "Cyfrin"}]}}
```

### Sort by Quality
```json
{"filters": {"qualityScore": 4, "sortField": "Quality", "sortDirection": "Desc"}}
```

### Recent Findings
```json
{"filters": {"reported": {"value": "30"}, "sortField": "Recency"}}
```

## Quality and Impact Reference

### Impact Levels
- **HIGH** - Critical vulnerabilities, fund loss, protocol compromise
- **MEDIUM** - Significant issues, partial fund loss, functionality impact
- **LOW** - Minor issues, edge cases, best practice violations
- **GAS** - Optimization opportunities, efficiency improvements

### Quality Scores (0-5)
- **5** - Excellent documentation, clear exploit path, verified
- **4** - Well-documented, actionable
- **3** - Good quality, useful for production
- **2** - Acceptable, may need interpretation
- **1** - Basic documentation

**Recommendation:** Use `qualityScore: 3` minimum for production code guidance.

## Common Tags Reference

| Category | Tags |
|----------|------|
| **Access Control** | Access Control, Privilege Escalation, Missing Authorization |
| **Economic** | Flash Loan, Price Manipulation, Oracle, Front-running |
| **Memory/State** | Reentrancy, Integer Overflow/Underflow, Storage Collision |
| **Logic** | Logic Error, Validation, Edge Cases |
| **Availability** | DOS, Griefing, Gas Limit |

## Protocol Categories Reference

| Category | Sub-Categories |
|----------|---------------|
| **DeFi** | DEX, AMM, Yield Farming |
| **Lending** | Collateralized Lending, Flash Loans, NFT Lending |
| **NFT** | Marketplace, Minting, Royalties |
| **Staking** | Liquid Staking, Validator |
| **Governance** | DAO, Voting, Timelock |
| **Bridge** | Cross-Chain, Messaging |

## Audit Firms Reference

### Tier 1 (Highest Reputation)
- Trail of Bits
- OpenZeppelin
- Consensys Diligence

### Competitive Platforms
- Sherlock
- Code4rena
- Immunefi

### Specialized Firms
- Cyfrin (Modern DeFi)
- Spearbit (Complex protocols)
- ChainSecurity (Formal verification)

## Troubleshooting

### API Key Issues
```bash
# Verify key is set
echo $CYFRIN_API_KEY

# Test authentication
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"page": 1, "pageSize": 1}'
```

### Rate Limiting
- Check `rateLimit.remaining` in response
- Wait for `rateLimit.reset` timestamp if exhausted
- See [api-integration/rate-limiting.md](api-integration/rate-limiting.md)

### No Results
- Broaden filters (remove tags, expand impact)
- Check spelling of filter values
- Try keyword search instead of tags

## Checklist for Using This Skill

- [ ] API key is configured (`CYFRIN_API_KEY`)
- [ ] Identified user's context (protocol type, feature, phase)
- [ ] Selected appropriate sub-skills
- [ ] Built query with relevant filters
- [ ] Retrieved quality findings (score >= 3)
- [ ] Extracted actionable insights
- [ ] Provided specific, practical advice
- [ ] Included code patterns and mitigations
