# Solana Vulnerability Patterns

## Critical Patterns
1. **Missing owner check** - Account owner not validated, attacker passes fake account
2. **Missing signer check** - Privileged action without signature verification
3. **PDA seed confusion** - Wrong seeds used in PDA derivation, accessing wrong data
4. **Integer overflow** - Rust release mode wraps on overflow (no panic)
5. **Account revival** - Closed account reopened in same transaction

## High Patterns
1. **CPI privilege escalation** - Signed CPI grants unintended authority
2. **Duplicate account** - Same account passed twice in different parameters
3. **Type confusion** - Account deserialized as wrong type
4. **Rent exemption** - Account balance drops below rent-exempt minimum
5. **Clock manipulation** - Using Clock sysvar for randomness

## Medium Patterns
1. **Remaining accounts** - Unchecked remaining_accounts vector
2. **Lamport balance check** - Using lamports as proxy for data state
3. **Instruction introspection** - Missing check on adjacent instructions
4. **Bump seed canonicality** - Not using canonical (highest) bump

## Real-World Exploits
| Protocol | Loss | Pattern | Year |
|----------|------|---------|------|
| Wormhole | $320M | Missing signer validation | 2022 |
| Cashio | $48M | Missing account validation | 2022 |
| Mango Markets | $114M | Oracle manipulation | 2022 |
| Crema Finance | $8.8M | Fake tick account | 2022 |
