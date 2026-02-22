# Starknet Security Considerations

## Sequencer Trust
- Centralized sequencer can censor/delay transactions
- Proofs ensure correctness but not liveness
- Force-inclusion via L1 may be available

## Account Abstraction
- All accounts are smart contracts
- Custom `__validate__` and `__execute__` methods
- Signature schemes are customizable per account
- Paymaster-like patterns possible

## Contract Upgrades
- `replace_class_syscall` changes contract logic
- Storage preserved during upgrade
- Must protect upgrade function with access control

## Storage Model
- Pedersen hash-based storage addresses
- No EVM-style storage slots
- Map storage = hash(base_address, key)
- Collision risk with custom address calculations
