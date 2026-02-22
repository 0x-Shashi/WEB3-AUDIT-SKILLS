# Fuel Vulnerability Patterns

## Critical
- **UTXO double spend**: Same UTXO consumed in multiple transactions
- **Predicate bypass**: Predicate logic allows unauthorized spending
- **Asset confusion**: Wrong asset ID used in transfer

## High
- **Missing ownership check**: Contract function lacks msg_sender() validation
- **Storage key collision**: Custom storage keys overlap
- **Integer overflow**: Sway integers can overflow without checked math

## Medium
- **Predicate DOS**: Complex predicate exceeds gas limit
- **Script interaction**: Incorrect script-to-contract call patterns
- **Asset metadata**: Trusting user-provided asset IDs

## Fuel Checklist
- [ ] msg_sender() validated on privileged functions
- [ ] Asset IDs explicitly checked (not assumed)
- [ ] Predicate logic handles all edge cases
- [ ] Storage keys unique and documented
- [ ] Integer arithmetic checked
- [ ] UTXO management correct in multi-call transactions
