# Severity Classification Guide

Standards for classifying vulnerability severity in smart contract audits.

---

## Severity Levels

### Critical

**Definition:** Vulnerability that can lead to:
- Direct theft of user funds
- Permanent freezing of funds
- Complete protocol compromise
- Unauthorized minting/burning of tokens

**Characteristics:**
- Exploitable by anyone (no special access needed)
- No preconditions or very likely preconditions
- Immediate, direct financial impact
- Cannot be mitigated by protocol team quickly

**Examples:**
- Reentrancy leading to fund drain
- Unprotected initializer allowing ownership takeover
- Integer overflow allowing unlimited minting
- Missing access control on withdraw function

**CVSS-like Score:** 9.0 - 10.0

---

### High

**Definition:** Vulnerability that can lead to:
- Significant value at risk (but not complete loss)
- Temporary freezing of funds
- Theft requiring specific conditions
- Major protocol malfunction

**Characteristics:**
- May require specific preconditions
- May require attacker to have some access/tokens
- Significant but not total impact
- Protocol can potentially recover

**Examples:**
- Flash loan attack with profit cap
- Oracle manipulation with limited impact
- Price manipulation in specific scenarios
- Access control bypass for non-critical functions

**CVSS-like Score:** 7.0 - 8.9

---

### Medium

**Definition:** Vulnerability that can lead to:
- Limited value at risk
- Griefing attacks without profit
- Non-critical functionality disruption
- Potential for future issues

**Characteristics:**
- Requires specific, unlikely conditions
- Impact is limited or indirect
- May require significant cost to exploit
- Protocol continues to function

**Examples:**
- DoS on non-critical function
- Precision loss causing minor fund leakage
- Front-running with limited impact
- Missing event emissions

**CVSS-like Score:** 4.0 - 6.9

---

### Low

**Definition:** Issues that:
- Don't directly affect funds
- Cause inconvenience rather than loss
- Represent best practice violations
- Could become problematic in future upgrades

**Characteristics:**
- No direct financial impact
- Requires very specific circumstances
- Primarily about code quality
- Easy to fix, low urgency

**Examples:**
- Missing input validation (non-critical)
- Suboptimal gas usage
- Code style issues
- Redundant code

**CVSS-like Score:** 0.1 - 3.9

---

### Informational

**Definition:** Observations that:
- Are suggestions for improvement
- Note potential future concerns
- Highlight centralization risks
- Document design decisions

**Characteristics:**
- No exploitability
- Improvement opportunities
- Educational value
- May or may not be addressed

**Examples:**
- Centralization risks (by design)
- Documentation suggestions
- Alternative implementation approaches
- Minor optimizations

**CVSS-like Score:** N/A (0.0)

---

## Severity Matrix

Use this matrix to quickly determine severity:

| | Direct Fund Loss | Indirect Fund Loss | No Fund Loss |
|---|---|---|---|
| **Anyone can exploit** | Critical | High | Medium |
| **Specific conditions** | High | Medium | Low |
| **Unlikely conditions** | Medium | Low | Info |
| **Admin only impact** | Medium* | Low | Info |

*If admin is malicious/compromised, may be higher

---

## Impact Categories

### Financial Impact

| Level | Description | Approximate Value |
|-------|-------------|-------------------|
| Catastrophic | Total protocol loss | >$10M or 100% |
| Critical | Major fund loss | $1M-$10M or 50-100% |
| Significant | Notable fund loss | $100K-$1M or 10-50% |
| Moderate | Limited fund loss | $10K-$100K or 1-10% |
| Minor | Negligible loss | <$10K or <1% |

### Operational Impact

| Level | Description |
|-------|-------------|
| Complete | Protocol cannot function |
| Major | Core functionality broken |
| Partial | Some features unavailable |
| Minor | Inconvenience only |
| None | No operational impact |

### Reputation Impact

| Level | Description |
|-------|-------------|
| Severe | Project likely abandoned |
| Major | Significant user exodus |
| Moderate | Some users affected |
| Minor | Limited awareness |
| None | Not visible to users |

---

## Likelihood Assessment

### Probability Factors

| Factor | Increases Likelihood | Decreases Likelihood |
|--------|---------------------|----------------------|
| Complexity | Simple attack | Complex multi-step attack |
| Access | Anyone | Specific role needed |
| Cost | Low/free | High capital required |
| Conditions | Always possible | Rare circumstances |
| Detection | Unlikely to be noticed | Easily monitored |
| Reversibility | One-time opportunity | Can be retried |

### Likelihood Levels

| Level | Description | Probability |
|-------|-------------|-------------|
| Almost Certain | Expected to happen | >90% |
| Likely | More likely than not | 50-90% |
| Possible | Could reasonably occur | 10-50% |
| Unlikely | Not expected but possible | 1-10% |
| Rare | Only in extreme circumstances | <1% |

---

## Combined Severity Calculation

```
Final Severity = f(Impact, Likelihood)

Critical = High Impact + Likely/Almost Certain
High     = High Impact + Possible, OR Critical Impact + Unlikely
Medium   = Moderate Impact + Possible, OR High Impact + Unlikely
Low      = Minor Impact any likelihood, OR Moderate Impact + Rare
Info     = No Impact, OR improvement suggestions
```

### Quick Reference Table

| Likelihood ↓ / Impact → | Critical | High | Medium | Low |
|-------------------------|----------|------|--------|-----|
| Almost Certain | Critical | Critical | High | Medium |
| Likely | Critical | High | Medium | Low |
| Possible | High | Medium | Medium | Low |
| Unlikely | High | Medium | Low | Info |
| Rare | Medium | Low | Low | Info |

---

## Special Considerations

### Upgrade Severity

For upgradeable contracts:
- Storage collision: Critical (can corrupt all data)
- Missing gap: Low (future upgrade risk only)
- Initialization: Critical if exploitable

### Oracle Severity

- Manipulation affecting liquidations: Critical
- Manipulation for arbitrage: High
- Stale data for display: Low

### Access Control Severity

- Missing on value functions: Critical
- Missing on config functions: High
- Missing on view functions: Info (usually)

### MEV Severity

- Sandwich enabling fund loss: High
- Front-running for queue position: Medium
- Back-running for arbitrage: Low

---

## Documentation Requirements

### Critical/High Findings

Must include:
- [ ] Clear title describing the issue
- [ ] Detailed technical description
- [ ] Proof of concept (code or steps)
- [ ] Impact analysis with value estimates
- [ ] Specific remediation steps
- [ ] References to similar issues

### Medium Findings

Must include:
- [ ] Clear description
- [ ] Impact explanation
- [ ] Remediation recommendation
- [ ] Conditions required for exploitation

### Low/Info Findings

Should include:
- [ ] Brief description
- [ ] Why it matters
- [ ] Suggested improvement

---

## Severity Disputes

When uncertain about severity:

1. **Err on the side of caution** - Report higher severity
2. **Provide reasoning** - Explain your classification
3. **Note uncertainties** - "This could be X or Y depending on..."
4. **Consider context** - Protocol's specific circumstances matter

### Adjustment Factors

Reasons to **increase** severity:
- Protocol holds significant TVL
- No monitoring/alerting in place
- No upgrade capability to fix
- Attack is profitable

Reasons to **decrease** severity:
- Protocol has circuit breakers
- Limited TVL at risk
- Strong monitoring in place
- Attack cost exceeds profit

---

## Example Classifications

### Example 1: Reentrancy in Withdraw
```
Impact: Direct fund theft, full balance
Likelihood: Anyone can exploit, simple attack
→ Severity: CRITICAL
```

### Example 2: Missing Deadline Check
```
Impact: Stale transaction could execute at bad price
Likelihood: Requires mempool congestion + price movement
→ Severity: MEDIUM
```

### Example 3: Missing Event Emission
```
Impact: Off-chain indexing incomplete
Likelihood: Always (by definition)
→ Severity: LOW (no on-chain impact)
```

### Example 4: Centralized Owner Key
```
Impact: Owner can rug (if malicious)
Likelihood: Depends on team trust
→ Severity: INFORMATIONAL (design choice) or MEDIUM (if concern)
```

