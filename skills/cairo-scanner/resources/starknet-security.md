---
id: CAIRO-STARKNET-SEC
title: Starknet Architecture Security Considerations
parent: cairo-scanner
type: resource
last_updated: 2025-01-31
---

# Starknet Security Considerations

Architecture-level security concerns for smart contracts on Starknet. These are platform-specific risks that don't exist on EVM chains and require dedicated audit attention.

---

## Sequencer Trust Model

Starknet currently operates with a centralized sequencer (operated by StarkWare). This creates specific trust assumptions:

| Concern | Current State | Future (Decentralized) |
|---------|---------------|----------------------|
| Transaction ordering | Sequencer controls order | Consensus-based ordering |
| Censorship | Sequencer can censor/delay txs | Censorship resistance via multiple sequencers |
| Liveness | Single point of failure | Redundant sequencers |
| MEV | Sequencer can extract MEV | Proposer-builder separation (PBS) |
| Correctness | STARK proofs guarantee correctness | Same — proofs are chain-independent |

### Security Implications

- **STARK proofs ensure computational integrity but NOT liveness or ordering fairness**
- Force-inclusion via L1 may be available as a censorship escape hatch
- Time-sensitive operations (e.g., liquidations, auctions) may be delayed by sequencer
- Protocols should not assume strict ordering guarantees

### What Auditors Should Check

- [ ] Protocol doesn't rely on transaction ordering for security
- [ ] Time-sensitive operations have grace periods for sequencer delay
- [ ] Force-inclusion path exists for critical operations
- [ ] No MEV extraction possible by sequencer in protocol logic

---

## Account Abstraction (Native)

On Starknet, **all accounts are smart contracts**. There are no externally-owned accounts (EOAs). Every account implements:

| Function | Purpose | Security Context |
|----------|---------|------------------|
| `__validate__` | Verify transaction validity (signature, fee) | Called by sequencer BEFORE execution |
| `__execute__` | Execute the actual transaction calls | Called AFTER successful validation |
| `__validate_declare__` | Validate class declaration transactions | Specific to contract deployment |
| `__validate_deploy__` | Validate contract deployment transactions | Called during account deployment |

### Account Security Risks

1. **Weak `__validate__`**: If validation is too permissive, anyone can execute transactions as this account
2. **Custom signature schemes**: Non-standard signature verification may have subtle bugs
3. **Fee manipulation**: Account controls gas payment — it could manipulate fee token transfers
4. **Multicall support**: Be aware that `__execute__` may batch multiple calls in one tx

### Account Audit Checklist

- [ ] `__validate__` verifies cryptographic signature against stored public key
- [ ] Signature scheme uses secure curves (Stark curve or secp256k1/r1)
- [ ] Transaction hash is correctly computed and signed
- [ ] Nonce is properly managed (replay protection)
- [ ] Fee estimation doesn't allow fee manipulation
- [ ] Multicall in `__execute__` doesn't introduce reentrancy
- [ ] Account upgrade protected by owner only

---

## Contract Upgrades via `replace_class_syscall`

**Unlike EVM proxy patterns**, Starknet contracts can change their implementation class instantly via `replace_class_syscall`. This is simpler but has unique risks:

| Property | Starknet Upgrade | EVM Proxy Upgrade |
|----------|-----------------|-------------------|
| Mechanism | `replace_class_syscall(new_class_hash)` | `upgradeTo(new_implementation)` on proxy |
| Storage | Preserved (same storage layout) | Preserved (same storage layout) |
| Speed | Immediate (same transaction) | Immediate (same transaction) |
| Reversal | Call `replace_class_syscall` again | Call `upgradeTo` again |
| Risk | Same class hash = same code for ALL instances | Each proxy has independent implementation |

### Upgrade Security Checks

```cairo
// MINIMUM SECURITY: Owner-only upgrade
#[external(v0)]
fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
    self.assert_only_owner();
    assert(new_class_hash.is_non_zero(), 'Zero class hash');
    replace_class_syscall(new_class_hash).unwrap();
    self.emit(ContractUpgraded { new_class_hash });
}

// BETTER: Timelock pattern
#[external(v0)]
fn propose_upgrade(ref self: ContractState, new_class_hash: ClassHash) {
    self.assert_only_owner();
    let execute_after = get_block_timestamp() + UPGRADE_DELAY;
    self.pending_upgrade.write((new_class_hash, execute_after));
    self.emit(UpgradeProposed { new_class_hash, execute_after });
}

#[external(v0)]
fn execute_upgrade(ref self: ContractState) {
    self.assert_only_owner();
    let (class_hash, execute_after) = self.pending_upgrade.read();
    assert(get_block_timestamp() >= execute_after, 'Timelock active');
    replace_class_syscall(class_hash).unwrap();
    self.pending_upgrade.write((ClassHash { value: 0 }, 0));
    self.emit(ContractUpgraded { new_class_hash: class_hash });
}
```

### Upgrade Audit Checklist

- [ ] `replace_class_syscall` only callable by owner/admin
- [ ] New class hash validated (non-zero)
- [ ] Timelock for upgrade (recommended for high-value contracts)
- [ ] Upgrade event emitted
- [ ] Storage layout compatibility verified between old and new class
- [ ] No way to upgrade to a class that removes the upgrade function (bricking)

---

## Storage Model

Starknet uses Pedersen hash for storage addressing:

```
storage_address = pedersen(storage_variable_base, key1, key2, ...)

Where:
- storage_variable_base = sn_keccak(variable_name) mod 2^251
- For simple variables: storage_address = base
- For maps: storage_address = pedersen(base, key)
- For nested maps: storage_address = pedersen(pedersen(base, key1), key2)
```

### Storage Risks

| Risk | Description |
|------|-------------|
| **Hash collision** | Two different variables/keys producing the same storage address |
| **Cross-component collision** | Components sharing storage addresses |
| **Layout mismatch after upgrade** | New class expects different storage layout |

### Mitigations

- Use the standard `#[storage]` macro — it handles address calculation correctly
- Never compute storage addresses manually
- When upgrading, ensure new class uses identical storage variable names and types
- Use Cairo's component system for modular storage (each component has isolated namespace)

---

## Starknet-Specific Syscalls

| Syscall | Security Relevance |
|---------|--------------------|
| `get_caller_address()` | Returns calling contract address (or 0 for direct tx) — use for access control |
| `get_contract_address()` | Returns current contract address — use for self-reference |
| `get_block_timestamp()` | Block timestamp — sequencer-influenced, don't use for critical timing |
| `get_block_number()` | Current block number — increases monotonically |
| `get_tx_info()` | Transaction info including hash, signature, nonce — use in `__validate__` |
| `call_contract_syscall()` | External contract call — reentrancy risk |
| `library_call_syscall()` | Delegatecall equivalent — runs foreign code with local storage |
| `send_message_to_l1_syscall()` | Send L2→L1 message — see messaging-security.md |
| `replace_class_syscall()` | Upgrade contract — see upgrade section above |
| `deploy_syscall()` | Deploy new contract — check deployer access control |
