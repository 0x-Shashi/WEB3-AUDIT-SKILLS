# Cairo Vulnerability Patterns

## Critical
- **Felt overflow**: Field elements wrap around prime P, comparisons fail for "negative" values
- **Unprotected upgrade**: `replace_class_syscall` without access control
- **Missing reentrancy guard**: Cross-contract calls can re-enter

## High
- **Storage collision**: Custom storage address calculation overlaps
- **L1-L2 replay**: Message nonce not validated
- **Account validation bypass**: Custom `__validate__` logic flawed

## Medium
- **Unbounded storage**: No limits on dynamic data growth
- **Missing events**: State changes without event emission
- **Integer range**: Using felt where u256/u128 more appropriate

## Cairo-Specific Notes
- Felts are in [0, P-1] where P = 2^251 + 17*2^192 + 1
- Division is modular inverse, not integer division
- No native reentrancy guard (must implement manually)
- All accounts are smart contracts (native AA)
