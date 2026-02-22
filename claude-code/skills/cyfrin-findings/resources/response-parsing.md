# Response Parsing Guide

## Extracting Useful Information
1. **Title**: Quick summary of the vulnerability
2. **Severity**: Mapped to standard scale (Critical/High/Medium/Low)
3. **Description**: Detailed explanation of the issue
4. **Impact**: What an attacker can achieve
5. **Recommendation**: How to fix the vulnerability
6. **Code References**: Specific lines/functions affected

## Pattern Matching
- Group similar findings to identify patterns
- Track frequency of specific vulnerability types
- Note which protocol types are most affected
- Build internal knowledge base from recurring findings

## Applying to Current Audit
1. Search for findings related to the protocol type being audited
2. Check if similar code patterns exist in the target codebase
3. Verify mitigations are properly implemented
4. Reference past findings in audit report for credibility
