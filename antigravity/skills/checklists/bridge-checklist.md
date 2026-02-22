# Bridge Audit Checklist

## 1. Message Verification
- [ ] **CRITICAL** Cross-chain messages authenticated (signature/proof verified)
- [ ] **CRITICAL** Message source chain validated (can't spoof source)
- [ ] **CRITICAL** Message sender validated (authorized contract on source chain)
- [ ] **CRITICAL** Message cannot be forged or tampered with
- [ ] **HIGH** Message hash includes all relevant fields (no field omission)
- [ ] **HIGH** Merkle proof verification correct (if proof-based)
- [ ] **HIGH** Validator signatures: threshold met (if multi-sig based)
- [ ] **MEDIUM** Message format versioning handled across upgrades

## 2. Replay Protection
- [ ] **CRITICAL** Messages cannot be replayed (nonce or unique identifier)
- [ ] **CRITICAL** Cross-chain replay: message valid on one chain only
- [ ] **HIGH** Replay protection survives contract upgrades
- [ ] **HIGH** Nonce tracking: no gaps exploitable
- [ ] **MEDIUM** Message ordering: out-of-order delivery handled correctly
- [ ] **MEDIUM** Same message to multiple destinations protected

## 3. Token Locking and Minting
- [ ] **CRITICAL** Lock on source = mint on destination (1:1 accounting)
- [ ] **CRITICAL** Burn on source = unlock on destination (1:1 accounting)
- [ ] **CRITICAL** Cannot mint without corresponding lock (phantom minting)
- [ ] **HIGH** Token decimals: conversion between different decimal tokens
- [ ] **HIGH** Wrapped token total supply <= locked amount on source
- [ ] **HIGH** Fee handling: bridge fees correctly deducted
- [ ] **MEDIUM** Token metadata: name/symbol consistent across chains
- [ ] **MEDIUM** Canonical vs wrapped token distinction maintained

## 4. Finality and Timing
- [ ] **CRITICAL** Source chain finality waited before processing on destination
- [ ] **HIGH** Reorg protection: sufficient block confirmations
- [ ] **HIGH** Challenge period (optimistic bridges): long enough for detection
- [ ] **HIGH** Proof finality (ZK bridges): proof verification on-chain
- [ ] **MEDIUM** Deposit/withdrawal timing: delays communicated to users
- [ ] **MEDIUM** Timeout mechanism: stuck messages can be recovered

## 5. Validator/Relayer Security
- [ ] **CRITICAL** Validator set: no single point of failure
- [ ] **CRITICAL** Validator key compromise: threshold high enough
- [ ] **HIGH** Validator rotation: key update mechanism secure
- [ ] **HIGH** Relayer incentives: honest behavior rewarded
- [ ] **HIGH** Relayer liveness: messages still processed if relayer goes down
- [ ] **MEDIUM** Watchtower/challenger: malicious proofs detected and challenged
- [ ] **MEDIUM** Validator collusion: economic penalty sufficient deterrent

## 6. Smart Contract Security
- [ ] **CRITICAL** Bridge contract upgradability: multisig + timelock
- [ ] **CRITICAL** Admin key management: no single admin can drain
- [ ] **HIGH** Emergency pause: can halt bridge in case of exploit
- [ ] **HIGH** Rate limiting: maximum bridge volume per time period
- [ ] **HIGH** Reentrancy: bridge callback functions protected
- [ ] **MEDIUM** Gas limits: cross-chain execution has sufficient gas
- [ ] **MEDIUM** Error handling: failed messages don't lock funds permanently

## 7. Liquidity and Accounting
- [ ] **CRITICAL** Total value locked (TVL) matches issued wrapped tokens
- [ ] **CRITICAL** Accounting invariant: can't create more tokens than locked
- [ ] **HIGH** Liquidity pool model: dynamic fees for pool-based bridges
- [ ] **HIGH** Rebalancing: cross-chain liquidity maintained
- [ ] **MEDIUM** Slippage: large bridge transfers don't cause excessive slippage
- [ ] **MEDIUM** Dust amounts: minimum bridge amount enforced

## 8. Chain-Specific Considerations
- [ ] **HIGH** L1→L2 bridges: rollup-specific messaging mechanism used
- [ ] **HIGH** L2→L1 bridges: withdrawal delay (7 days optimistic, proof time ZK)
- [ ] **HIGH** Non-EVM chains: address format conversion correct
- [ ] **MEDIUM** Different gas tokens handled (bridge ETH to non-ETH chain)
- [ ] **MEDIUM** EVM chain differences: opcode compatibility for verification
- [ ] **LOW** Network upgrades: bridge survives hard forks on either chain

## 9. Economic Security
- [ ] **HIGH** Validator bond > potential theft opportunity
- [ ] **HIGH** Slashing conditions clear and enforceable
- [ ] **MEDIUM** Insurance fund for bridge failures
- [ ] **MEDIUM** Fee model sustainable for relayers/validators
- [ ] **LOW** Bridge TVL relative to validator bond assessed
