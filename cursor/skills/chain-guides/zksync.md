# zkSync Era Security Guide

## Chain Overview

- **Type:** zkRollup L2
- **VM:** zkEVM (Type 4 - high-level language equivalent)
- **Proving:** zk-SNARK (PLONK-based)
- **Finality:** ~1 hour (proof generation + verification)
- **Gas Token:** ETH
- **Chain ID:** 324

## Key Security Considerations

### 1. EVM Differences (Critical!)
zkSync Era is NOT EVM-equivalent. It compiles Solidity/Vyper to a custom VM:

```solidity
// CRITICAL DIFFERENCES:
// 1. msg.sender behavior in constructors differs
// 2. Contract deployment uses CREATE and CREATE2 differently
// 3. Different bytecode format (zkSync bytecode != EVM bytecode)
// 4. No support for some EVM opcodes
// 5. Gas costs significantly different for many operations
```

**Unsupported/Different opcodes:**
- `SELFDESTRUCT` - NOT supported
- `EXTCODECOPY` - returns empty for compiled contracts
- `CODECOPY` - different behavior
- `CODESIZE` - returns contract hash, not actual size
- `CALLCODE` - NOT supported (only `DELEGATECALL`)

### 2. Native Account Abstraction
zkSync has BUILT-IN account abstraction (no ERC-4337 needed):

```solidity
// All accounts can have custom validation logic
// This means:
// - tx.origin != msg.sender is NOT a reliable EOA check
// - Signature validation is customizable per account
// - Gas payment can be abstracted via Paymasters

// [VULNERABLE] EOA check doesn't work on zkSync
function onlyEOA() internal view {
    require(msg.sender == tx.origin); // Fails with AA!
}
```

**Audit implications:**
- Custom accounts can have arbitrary validation logic
- `ecrecover` may not be the only valid signature scheme
- Paymasters can pay gas on behalf of users
- Transaction flow: Validation → Execution (separate phases)

### 3. System Contracts
zkSync has special system contracts not found in standard EVM:
- `ContractDeployer` - All contract deployments go through this
- `NonceHolder` - Manages account nonces
- `MsgValueSimulator` - Handles ETH transfers with msg.value
- `SystemContext` - Block/transaction context
- `Bootloader` - Transaction processing (like block builder)

```solidity
// Deploying contracts on zkSync is different
// Must use ContractDeployer or factory patterns
// CREATE/CREATE2 are redirected through system contracts

// Address derivation is DIFFERENT from Ethereum!
// CREATE: hash(senderAddress, senderNonce, salt, bytecodeHash)
// CREATE2: hash(senderAddress, salt, bytecodeHash, constructorInputHash)
```

### 4. Gas Model
zkSync has a different gas model:
- `ergs` (zkSync internal gas unit) mapped to Ethereum gas
- Pubdata cost: storage writes that go to L1 are expensive
- Execution cost: generally lower than Ethereum
- **Critical:** Gas limits for operations differ significantly

```solidity
// [VULNERABLE] Hardcoded gas limits will break
function forwardCall(address target, bytes calldata data) external {
    (bool success,) = target.call{gas: 50000}(data); // May not be enough!
}
```

### 5. L1 <-> L2 Communication
```
L1 → L2: Priority queue (requestL2Transaction)
L2 → L1: L2→L1 logs (included in batch proof)
```

- Priority transactions from L1 are guaranteed inclusion
- L2→L1 messages finalized with batch proof (~1 hour)
- `msg.sender` in L1→L2 calls is the actual L1 sender (no aliasing like Arbitrum)

### 6. Paymaster System
```solidity
// Paymasters can sponsor gas fees
// Audit implications:
// - Griefing: spamming protocol with free transactions
// - Paymaster validation logic must be correct
// - ERC-20 gas payment introduces exchange rate risk
```

## zkSync-Specific Audit Checklist

- [ ] EVM opcode compatibility verified (SELFDESTRUCT, CALLCODE, EXTCODECOPY)
- [ ] Contract deployment through ContractDeployer
- [ ] CREATE2 address derivation uses zkSync formula (NOT Ethereum)
- [ ] No `msg.sender == tx.origin` checks (broken by native AA)
- [ ] Gas limits not hardcoded (ergs != gas)
- [ ] Signature validation considers custom account types
- [ ] Paymaster integration: spam/griefing protection
- [ ] System contract interactions correct
- [ ] L1<>L2 message handling and finality timing
- [ ] `CODESIZE` behavior different (returns hash)
- [ ] Storage layout may differ for upgradeable proxies
- [ ] Nonce management through NonceHolder

## Common Vulnerabilities on zkSync

| Vulnerability | Description |
|--------------|-------------|
| EOA detection bypass | `msg.sender == tx.origin` broken by AA |
| CREATE2 address mismatch | Different address derivation formula |
| Gas estimation failure | ergs != gas, hardcoded limits break |
| SELFDESTRUCT usage | Not supported, will fail |
| Paymaster griefing | Free transaction spam |
| Proxy pattern issues | Different bytecode format affects upgrades |
