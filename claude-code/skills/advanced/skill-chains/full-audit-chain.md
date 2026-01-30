# Full Audit Chain

## Overview

Comprehensive security audit workflow covering all aspects.

**Duration:** 4-8 hours  
**Output:** Full audit report with prioritized findings

---

## Chain Steps

```

                    FULL AUDIT CHAIN                             

                                                                 
  Step 1: Context Detection                         [15 min]    
   Identify chain/language                                    
   Detect protocol type                                       
   Profile risk level                                         
                                                                 
  Step 2: Architecture Review                       [30 min]    
   Map contract relationships                                 
   Identify trust boundaries                                  
   Document external dependencies                             
                                                                 
  Step 3: Pattern Scanning                          [60 min]    
   Load chain-specific scanner                                
   Apply consolidated patterns                                
   Run detection queries                                      
                                                                 
  Step 4: Protocol-Specific Review                  [60 min]    
   Load protocol template                                     
   Check protocol-specific vulnerabilities                    
   Verify business logic                                      
                                                                 
  Step 5: Attack Chain Analysis                     [45 min]    
   Map individual findings to chains                          
   Identify combined exploits                                 
   Assess cascading impacts                                   
                                                                 
  Step 6: Access Control Audit                      [30 min]    
   Map privileged functions                                   
   Verify role separation                                     
   Check upgrade mechanisms                                   
                                                                 
  Step 7: Economic Analysis                         [30 min]    
   Token flow analysis                                        
   Fee/reward mechanisms                                      
   Value extraction paths                                     
                                                                 
  Step 8: Severity Assessment                       [20 min]    
   Rate each finding                                          
   Consider attack complexity                                 
   Estimate impact                                            
                                                                 
  Step 9: Report Generation                         [30 min]    
   Structure findings                                         
   Add recommendations                                        
   Create executive summary                                   
                                                                 

```

---

## Step 1: Context Detection

**Skills Loaded:** `context-detection/SKILL.md`

**Actions:**
1. Scan file extensions and imports
2. Identify blockchain (EVM, Solana, etc.)
3. Detect protocol type (DEX, Lending, etc.)
4. Assess risk profile

**Output:**
```yaml
context:
  chain: "ethereum"
  language: "solidity"
  protocol: "lending"
  risk_level: "high"
  recommended_scanner: "solidity-scanner"
  recommended_template: "lending-template"
```

---

## Step 2: Architecture Review

**Actions:**
1. Create contract dependency graph
2. Identify entry points
3. Map external calls
4. Document inherited contracts

**Commands:**
```bash
# Find all contracts
grep -rn "contract\s+\w+\s+is" --include="*.sol"

# Find external calls
grep -rn "\.call\|\.delegatecall\|\.staticcall" --include="*.sol"

# Find interfaces
grep -rn "interface\s+I" --include="*.sol"
```

**Output:**
```
 Core.sol (main entry)
    inherits Ownable
    inherits ReentrancyGuard
    calls Oracle.sol
 Oracle.sol
    calls Chainlink
 Token.sol
     inherits ERC20
```

---

## Step 3: Pattern Scanning

**Skills Loaded:** Based on context
- `solidity-scanner/SKILL.md` (for EVM)
- `solana-scanner/SKILL.md` (for Solana)
- etc.

**Actions:**
1. Load chain-specific patterns
2. Load consolidated patterns
3. Run all detection queries
4. Collect raw findings

**Commands:**
```bash
# Reentrancy
grep -rn "\.call{value" --include="*.sol" | 
  xargs -I {} grep -l "balances\[" {}

# Access control
grep -rn "onlyOwner\|require.*msg.sender" --include="*.sol"

# Oracle usage  
grep -rn "getPrice\|latestAnswer\|getReserves" --include="*.sol"
```

---

## Step 4: Protocol-Specific Review

**Skills Loaded:** Based on protocol type
- `lending-template.md` for lending
- `amm-dex-template.md` for DEX
- etc.

**Actions:**
1. Load protocol template
2. Check each protocol-specific vulnerability
3. Verify protocol-specific logic
4. Compare to reference implementations

---

## Step 5: Attack Chain Analysis

**Skills Loaded:** `attack-chains/SKILL.md`

**Actions:**
1. Review individual findings
2. Check which attack chains apply
3. Identify combined vulnerabilities
4. Map multi-step exploits

**Example:**
```
Finding: Oracle uses spot price (Medium)
Finding: Instant liquidation (Low)
Finding: Flash loan integration (Info)

 Attack Chain: Flash Loan + Oracle + Liquidation (CRITICAL)
```

---

## Step 6: Access Control Audit

**Actions:**
1. List all privileged functions
2. Map role hierarchy
3. Check upgrade mechanisms
4. Verify timelocks

**Commands:**
```bash
# Find access modifiers
grep -rn "onlyOwner\|onlyAdmin\|onlyRole" --include="*.sol"

# Find upgrades
grep -rn "upgradeTo\|_setImplementation" --include="*.sol"

# Find timelocks
grep -rn "timelock\|delay\|eta" --include="*.sol"
```

---

## Step 7: Economic Analysis

**Actions:**
1. Trace token flows
2. Analyze fee mechanisms
3. Check reward distribution
4. Identify value extraction

**Key Questions:**
- Where does value enter/exit?
- Who earns fees?
- Can rewards be manipulated?
- Are there MEV opportunities?

---

## Step 8: Severity Assessment

**Skills Loaded:** `severity/SKILL.md`

**Criteria:**

| Severity | Likelihood | Impact |
|----------|------------|--------|
| Critical | Likely | Fund loss |
| High | Possible | Significant damage |
| Medium | Possible | Limited damage |
| Low | Unlikely | Minimal impact |
| Info | N/A | Improvement suggestion |

---

## Step 9: Report Generation

**Skills Loaded:** `report-writer/SKILL.md`

**Report Structure:**
```markdown
# Security Audit Report

## Executive Summary
## Scope
## Methodology
## Findings Summary
## Detailed Findings
  ### Critical
  ### High
  ### Medium
  ### Low
  ### Informational
## Recommendations
## Appendix
```

---

## Full Chain Checklist

### Before Starting
- [ ] Codebase access confirmed
- [ ] Scope defined
- [ ] Documentation reviewed
- [ ] Previous audits reviewed

### During Audit
- [ ] Context detected
- [ ] Architecture mapped
- [ ] Patterns scanned
- [ ] Protocol template applied
- [ ] Attack chains analyzed
- [ ] Access control audited
- [ ] Economics reviewed
- [ ] Severity assessed

### After Completion
- [ ] Report generated
- [ ] Findings deduplicated
- [ ] Recommendations added
- [ ] Executive summary written

---

## Time Allocation

| Step | Minimum | Maximum |
|------|---------|---------|
| Context | 15 min | 30 min |
| Architecture | 30 min | 60 min |
| Pattern Scan | 60 min | 120 min |
| Protocol Review | 60 min | 120 min |
| Attack Chains | 30 min | 60 min |
| Access Control | 30 min | 45 min |
| Economics | 30 min | 60 min |
| Severity | 15 min | 30 min |
| Report | 30 min | 60 min |
| **Total** | **5 hours** | **10 hours** |
