# Finding Templates

## Standard Finding Format
```markdown
### [S-01] Title of Finding

**Severity:** Critical / High / Medium / Low / Informational

**Location:** `Contract.sol#L123-L145`

**Description:**
Brief description of the vulnerability and how it manifests.

**Impact:**
What an attacker can achieve by exploiting this vulnerability.

**Proof of Concept:**
```solidity
// Step-by-step exploit code
function testExploit() public {
    // 1. Attacker does X
    // 2. This causes Y
    // 3. Result: Z
}
```

**Recommended Mitigation:**
```solidity
// Fixed code
function fixedFunction() external {
    // Apply fix here
}
```
```

## Severity Justification Format
```
Likelihood: HIGH/MEDIUM/LOW (how easy to exploit)
Impact: HIGH/MEDIUM/LOW (damage if exploited)
→ Severity = Matrix(Likelihood × Impact)
```
