# Attack Chain Mapping

## Purpose

Map how individual vulnerabilities combine into devastating multi-step exploits.

---

## What is an Attack Chain?

Single vulnerabilities are often low/medium severity alone, but when combined:

```
Vulnerability A (Medium) + Vulnerability B (Medium) = Exploit (Critical)
```

**Example:**
```
Flash Loan Access (Info) 
  + Price Oracle Manipulation (Medium) 
  + Liquidation Logic Flaw (Medium)
  = Complete Protocol Drain (Critical)
```

---

## Attack Chain Categories

### 1. Flash Loan Chains
### 2. Oracle Manipulation Chains
### 3. Governance Attack Chains
### 4. Bridge Attack Chains
### 5. Reentrancy Chains
### 6. MEV Attack Chains

---

## How to Use

### Step 1: Identify Individual Vulnerabilities
Run scanner skills to find individual issues.

### Step 2: Map to Attack Chains
Check if found vulnerabilities can combine.

### Step 3: Assess Combined Impact
Rate the combined exploit severity.

### Step 4: Prioritize Fixes
Fix chain-breaking vulnerabilities first.

---

## Attack Chain Database

See individual files:
- `flash-loan-chains.md` - Flash loan-based attacks
- `oracle-chains.md` - Price manipulation attacks
- `governance-chains.md` - Governance takeover attacks
- `bridge-chains.md` - Cross-chain attacks

---

## Chain Identification Checklist

When you find a vulnerability, ask:

1. **Can this be amplified with flash loans?**
   - Borrow large amounts
   - Manipulate prices
   - Trigger liquidations
   - Repay in same tx

2. **Can this affect oracle prices?**
   - Spot price manipulation
   - TWAP manipulation
   - Stale price exploitation

3. **Can this lead to unauthorized access?**
   - Privilege escalation
   - Governance capture
   - Admin key compromise

4. **Can this be chained with other findings?**
   - Review all findings together
   - Look for dependency chains
   - Consider transaction ordering

---

## Reporting Attack Chains

### Format

```markdown
## Attack Chain: [Name]

### Vulnerabilities Involved
1. [V-01] Description (Severity)
2. [V-02] Description (Severity)
3. [V-03] Description (Severity)

### Combined Severity: Critical

### Attack Flow
1. Attacker does X using V-01
2. This enables Y via V-02
3. Finally exploits Z through V-03

### Proof of Concept
[Step by step attack]

### Impact
[Total damage possible]

### Mitigation
[Fix that breaks the chain]
```
