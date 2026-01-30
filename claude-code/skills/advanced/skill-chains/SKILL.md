---
name: skill-chains
description: "Pre-defined skill sequences for different audit scenarios. These chains orchestrate multiple skills in optimal order for comprehensive coverage."
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
---

# Skill Chains

## Purpose

Orchestrate multiple skills in pre-defined sequences for different audit scenarios.

---

## Available Chains

| Chain | Skills Involved | Duration | Use Case |
|-------|----------------|----------|----------|
| full-audit | All | 4-8 hours | Comprehensive security review |
| quick-scan | Detect + Scan | 30 min | Initial assessment |
| deep-dive | Scan + Attack | 2-4 hours | Specific module analysis |
| gas-review | Pattern + Optimize | 1-2 hours | Optimization focus |
| pre-deploy | Scan + Static | 1 hour | Final check before mainnet |

---

## Chain Execution Flow

```

   START     

       
       
     
   CONTEXT    Detect chain, protocol  
   DETECT          Load appropriate skills 
     
       
       
     
   PATTERN    Apply consolidated      
   SCAN            vulnerability patterns  
     
       
       
     
   ATTACK     Map attack chains       
   CHAIN           Identify combined vulns 
     
       
       
     
   SEVERITY   Assess impact           
   ASSESS          Prioritize findings     
     
       
       
     
   REPORT     Generate structured     
   GENERATE        audit report            
     
       
       

    END      

```

---

## Loading a Chain

```
User: "Run full-audit chain on this codebase"

 Load: full-audit-chain.md
 Execute each step in sequence
 Pass context between steps
 Aggregate findings
```

---

## Chain vs Individual Skills

| Aspect | Individual Skills | Skill Chains |
|--------|------------------|--------------|
| Control | Fine-grained | Automated |
| Coverage | Targeted | Comprehensive |
| Speed | Fast | Thorough |
| Use Case | Known issues | Unknown codebase |

---

## Custom Chains

Combine skills for specific needs:

```yaml
custom_chain:
  name: "oracle-focused"
  steps:
    - context-detection
    - oracle-chains (from attack-chains)
    - lending-template (if lending)
    - severity-assessment
    - report-writer
```

---

## See Individual Chain Files

- `full-audit-chain.md` - Complete audit workflow
- `quick-scan-chain.md` - Fast initial scan
- `deep-dive-chain.md` - Focused deep analysis
