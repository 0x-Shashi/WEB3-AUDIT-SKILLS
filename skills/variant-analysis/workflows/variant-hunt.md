# Variant Hunt Workflow

## Trigger
Run this workflow whenever you find a vulnerability during audit.

## Step 1: Document the Found Bug
```
Pattern: [e.g., unchecked return value]
Root Cause: [e.g., missing validation of external call result]
Location: [contract:function:line]
```

## Step 2: Abstract the Pattern
Strip context to identify the core pattern:
- What makes this code vulnerable?
- What is the minimum code structure that exhibits the bug?
- What are the keywords/signatures to search for?

## Step 3: Define Search Queries
Create regex/grep patterns to find variants:
```bash
# Example: Find all unchecked low-level calls
grep -rn "\.call{" --include="*.sol" | grep -v "require\|if\|success"

# Example: Find state changes after external calls
# (potential reentrancy)
grep -rn -A5 "\.call\|\.transfer\|\.send\|safeTransfer" --include="*.sol"

# Example: Find missing access control
grep -rn "function.*external\|function.*public" --include="*.sol" | grep -v "onlyOwner\|onlyAdmin\|require\|modifier"
```

## Step 4: Search the Codebase
- Search ALL contracts, not just the one where bug was found
- Include test files (they may reveal intended behavior)
- Include inherited contracts and libraries
- Check interfaces match implementations

## Step 5: Validate Each Match
For each potential variant:
1. Is the pattern actually present? (not just similar-looking code)
2. Is it reachable? (can an attacker trigger this code path?)
3. Is it exploitable? (what's the impact?)
4. Is it already mitigated? (by modifiers, checks, or architecture)

## Step 6: Check Related Patterns
Expand from the specific to the general:
| Found Pattern | Related Variants |
|--------------|-----------------|
| Unchecked transfer | Unchecked approve, unchecked mint, unchecked burn |
| Missing access control on fn A | Check ALL external/public functions |
| Reentrancy in withdraw | Check deposit, claim, liquidate, any fn with external calls |
| Oracle manipulation in pool A | Check ALL pools using same oracle |
| Rounding error in calculation A | Check ALL division operations |

## Step 7: Cross-Reference Historical Exploits
Search for the same pattern class in:
- Cyfrin findings database
- Solodit vulnerability patterns
- DeFiHackLabs reproduce repo
- Code4rena/Sherlock/Cantina reports

## Step 8: Report All Variants
Group findings by root cause:
```
ROOT CAUSE: [description]
INSTANCES: [count]

Instance 1: [contract:function] - [severity]
Instance 2: [contract:function] - [severity]
...

RECOMMENDATION: [single fix that addresses all instances]
```

## Tips
- The best auditors find 1 bug and turn it into 5+ findings through variant analysis
- Don't stop at the first instance — the goal is comprehensive coverage
- Consider cross-contract variants (same pattern, different contract)
- Consider cross-chain variants (same pattern, different deployment)
