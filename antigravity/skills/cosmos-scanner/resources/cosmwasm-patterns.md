# CosmWasm Vulnerability Patterns

## Critical
- **Unbounded iteration**: Iterating over entire state map without limit
- **Missing authorization**: Execute handler without sender validation
- **Arithmetic overflow**: Uint128/Uint256 overflow in reward calculation

## High
- **SubMessage reply**: Incorrect handling of reply data from cross-contract calls
- **Storage key collision**: Overlapping key prefixes in cw-storage-plus
- **Migration abuse**: Unprotected migrate entry point

## Medium
- **Gas DoS**: Operations that scale with state size
- **Admin escalation**: Admin can change critical parameters without timelock
- **Query amplification**: View functions that trigger expensive computation

## CosmWasm Checklist
- [ ] Execute handlers check `info.sender` authorization
- [ ] Iterate with pagination (limit + start_after)
- [ ] SubMessage replies validate submsg_id
- [ ] Storage keys use unique prefixes
- [ ] Admin/migrate protected by proper access control
- [ ] Uint128/Uint256 arithmetic checked
