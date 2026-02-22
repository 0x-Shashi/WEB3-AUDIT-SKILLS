# Command Implementation Guide

## Command Flow
```
User Input → Parse Command → Load Relevant Skills → Execute → Output
```

## Command Parsing
1. Detect command prefix (`/audit`, `/scan`, etc.)
2. Extract arguments (contract name, chain, protocol type)
3. Load appropriate scanner and checklist
4. Execute audit workflow
5. Return structured output

## Integration Points
- Scanner skills: called for vulnerability detection
- Checklists: loaded for protocol-specific checks
- Chain guides: loaded for chain-specific context
- Report writer: called for output formatting
- Severity guide: used for finding classification

## Error Handling
- Unknown command: suggest similar commands
- Missing contract: prompt for contract code
- Unsupported chain: list supported chains
- No findings: report clean result with confidence level
