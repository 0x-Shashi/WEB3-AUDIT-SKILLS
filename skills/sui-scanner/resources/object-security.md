# Sui Object Security

## Object Types and Security Implications

### Owned Objects
- Fast parallel processing (no consensus needed)
- Only owner can pass as transaction argument
- Risk: ownership transfer to wrong address is irreversible

### Shared Objects
- Require consensus for access
- Any transaction can reference them
- Risk: contention attacks, unauthorized modification
- Must validate caller permissions explicitly

### Immutable Objects
- Cannot be modified or deleted
- Safe for public constants and configuration
- Risk: none (by definition immutable)

### Wrapped Objects
- Contained within another object
- Not directly accessible, only through parent
- Risk: unwrapping logic bugs, dangling references

## Security Patterns
- Use owned objects for user-specific data (performance + security)
- Use shared objects only when cross-user access needed
- Freeze objects that should never change (make immutable)
- Store sensitive capabilities as owned objects
- Validate TxContext.sender before modifying shared objects
