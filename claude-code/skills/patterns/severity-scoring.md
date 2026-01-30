# Severity Scoring Guide - AI Reference

> **For AI Assistants:** Use this guide to assign accurate severity scores to vulnerabilities.

---

## Severity Levels

| Level | Score Range | Color | Description |
|-------|-------------|-------|-------------|
| CRITICAL | 9.0 - 10.0 |  | Direct, unconditional fund loss |
| HIGH | 7.0 - 8.9 |  | Significant damage possible |
| MEDIUM | 4.0 - 6.9 |  | Limited impact or conditional |
| LOW | 2.0 - 3.9 |  | Minor issues, best practices |
| INFO | 0.1 - 1.9 |  | Suggestions, no security impact |
| GAS | 0.0 - 0.5 |  | Gas optimization only |

---

## Quick Severity Decision Tree

```
Is there direct fund loss possible?
 YES  Is it unconditional (anyone can exploit)?
         YES  CRITICAL
         NO (needs conditions)  HIGH

 NO  Is there indirect fund loss or protocol damage?
         YES  Is the attack practical?
                 YES  HIGH
                 NO (theoretical)  MEDIUM
        
         NO  Does it affect protocol operation?
                 YES  MEDIUM
                 NO  Is it a code quality issue?
                         YES  LOW
                         NO  INFO/GAS
```

---

## Impact Weights

When calculating severity, weight these factors:

| Factor | Weight | Description |
|--------|--------|-------------|
| **Funds at Risk** | 3.0x | Can attacker steal/lock funds? |
| **Access Control** | 2.5x | Can attacker bypass authorization? |
| **Governance** | 2.0x | Can attacker manipulate governance? |
| **Data Integrity** | 2.0x | Can attacker corrupt state? |
| **Availability** | 1.5x | Can attacker DoS the protocol? |
| **Gas Efficiency** | 0.5x | Is there gas waste? |

---

## Category Base Severities

| Category | Typical Severity | Reason |
|----------|------------------|--------|
| reentrancy | CRITICAL/HIGH | Usually leads to fund theft |
| access-control | CRITICAL/HIGH | Unauthorized actions possible |
| arithmetic | HIGH/MEDIUM | Depends on affected values |
| oracle | HIGH/MEDIUM | Price manipulation risk |
| flash-loan | HIGH | Usually requires conditions |
| front-running | MEDIUM | Attack cost vs profit |
| signature | HIGH/MEDIUM | Depends on what's signed |
| data-validation | MEDIUM | Depends on impact |
| denial-of-service | MEDIUM | Funds usually safe |
| logic | Varies | Depends on business impact |
| upgradeability | CRITICAL/HIGH | Protocol takeover risk |
| centralization | MEDIUM | Trust assumption issue |
| gas | LOW/GAS | No security impact |
| best-practice | LOW/INFO | Code quality |

---

## Likelihood Modifiers

Adjust severity based on how easily exploited:

| Likelihood | Modifier | Examples |
|------------|----------|----------|
| Always exploitable | 1.0x | Anyone can call, no conditions |
| Requires specific conditions | 0.7x | Needs specific market state |
| Requires privileged access | 0.5x | Needs admin key (but admin is trusted) |
| Theoretical only | 0.3x | Requires extreme conditions |
| Unlikely in practice | 0.2x | Economic incentives prevent it |

---

## Context Modifiers

Adjust based on protocol context:

### Protocol Type
| Type | Modifier | Reason |
|------|----------|--------|
| Bridge | 1.5x | Cross-chain = higher risk |
| Oracle | 1.3x | Data integrity critical |
| DeFi (Lending/AMM) | 1.2x | Funds directly at risk |
| DAO | 1.1x | Governance attacks possible |
| NFT | 0.9x | Usually lower value at risk |
| General | 1.0x | Default |

### TVL (Total Value Locked)
| Range | Modifier |
|-------|----------|
| >$100M | 1.3x |
| $10M-$100M | 1.1x |
| <$10M | 0.9x |

### Audit Status
| Status | Modifier |
|--------|----------|
| Unaudited | 1.3x |
| Previously audited | 0.9x |
| Multiple audits | 0.8x |

---

## Severity Examples

### CRITICAL Examples
```
 Reentrancy allowing drain of all pool funds
 Missing access control on withdraw function
 Unprotected selfdestruct
 Arbitrary delegatecall to user-controlled address
 Storage collision in proxy allowing takeover
```

### HIGH Examples
```
 tx.origin authentication (phishing possible)
 Unchecked ERC20 transfer return value
 Missing zero address check on token address
 Oracle manipulation via flash loan
 First depositor vault inflation attack
```

### MEDIUM Examples
```
 Centralization risk (single admin key)
 Front-running on swap without slippage protection
 Block timestamp used for deadline
 Missing event emission on critical function
 Approve race condition (standard ERC20 approve)
```

### LOW Examples
```
 Floating pragma
 Outdated Solidity version (0.7.x)
 Variable shadowing
 Magic numbers without constants
 Missing NatSpec comments
```

### INFO/GAS Examples
```
 Storage read in loop (gas optimization)
 Long revert strings
 Public function could be external
 Unused imports
 Code style suggestions
```

---

## Severity Adjustment Keywords

**Increase severity if description contains:**
- "steal", "drain"  +20%
- "arbitrary"  +20%
- "bypass"  +15%
- "lock", "freeze"  +10%
- "anyone can"  +30%

**Decrease severity if description contains:**
- "requires admin"  -40%
- "requires owner"  -40%
- "edge case"  -30%
- "theoretical"  -50%
- "unlikely"  -60%

---

## Comparison Scoring

When prioritizing findings, compare:

```
Priority Score = Severity  Likelihood  Impact  Context

Where:
- Severity: 0-10 base score
- Likelihood: 0.2-1.0 multiplier  
- Impact: 0.5-3.0 based on funds/access affected
- Context: 0.8-1.5 based on protocol type/TVL
```

### Priority Ordering
1. CRITICAL with high likelihood  Fix immediately
2. HIGH with high likelihood  Fix before deployment
3. CRITICAL with low likelihood  Fix before deployment
4. HIGH with low likelihood  Fix recommended
5. MEDIUM  Acknowledge and consider
6. LOW  Best practice improvements
7. INFO/GAS  Optional optimizations

---

## Reporting Format

When reporting findings, include:

```markdown
## [SEVERITY] Title

**Severity:** CRITICAL | HIGH | MEDIUM | LOW | INFO
**Category:** reentrancy | access-control | ...
**Likelihood:** High | Medium | Low

**Score Breakdown:**
- Base: X/10 (from category)
- Impact: +/- Y (funds/access affected)
- Likelihood: Z (exploitability)
- Context: W (protocol type)
- **Final: X.X/10**

**Impact:**
What happens if exploited?

**Description:**
Technical details of the vulnerability.

**Recommendation:**
How to fix it.
```

---

## AI Guidelines

1. **Start with category default** severity
2. **Adjust for impact** - what's actually at risk?
3. **Adjust for likelihood** - how practical is the attack?
4. **Consider context** - protocol type, TVL, audit status
5. **Document reasoning** - explain severity choice
6. **Be consistent** - same issue = same severity across audits
7. **When in doubt** - err on higher severity, let team triage

