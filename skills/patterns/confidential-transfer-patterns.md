---
id: PAT-CONFIDENTIAL-TRANSFER
title: Token-2022 Confidential Transfer Security Patterns
category: token-extension
severity: high
chains:
  - solana
tags:
  - token-2022
  - confidential-transfers
  - elgamal
  - zero-knowledge
  - privacy
  - spl-token
last_updated: 2026-02-25
---

# Token-2022 Confidential Transfer Security Patterns

## Overview

Confidential transfers encrypt token balances and transfer amounts using ElGamal encryption and zero-knowledge proofs. While the cryptographic primitives are sound, the **integration surface** — key derivation, multi-transaction flows, balance type management, and proof verification — introduces audit-relevant attack vectors unique to this extension.

### Balance Architecture

```
┌─────────────────────────────────────────────────┐
│             Token Account (Token-2022)           │
├──────────────┬──────────────┬───────────────────┤
│ Public       │ Pending      │ Available         │
│ (plaintext)  │ (encrypted)  │ (encrypted)       │
│ visible to   │ incoming txs │ spendable balance │
│ everyone     │ not yet      │ owner-decryptable │
│              │ applied      │                   │
├──────────────┴──────────────┴───────────────────┤
│ deposit ──→ pending ──apply──→ available ──→ withdraw │
└─────────────────────────────────────────────────┘
```

Three distinct balance types per account. Confusion between them is a vulnerability class.

---

## Detection Checklist

- [ ] **ElGamal key derivation**: Are keys derived from the same signer keypair? Compromise of signer = full balance exposure
- [ ] **Pending balance counter**: Is `max_pending_balance_credit_counter` set appropriately? Can it be exhausted to DoS the account?
- [ ] **Proof verification**: Are all three proofs (equality, ciphertext validity, range) verified on-chain? Any skipped?
- [ ] **Auditor key**: Is an auditor ElGamal pubkey configured on the mint? Does it decrypt amounts or balances?
- [ ] **Balance type confusion**: Does the protocol read `public` when it should read `available`? Or vice versa?
- [ ] **Multi-tx atomicity**: Are the 7 required transactions for a transfer vulnerable to front-running between steps?
- [ ] **`apply_pending_balance` timing**: Can an attacker force pending balance accumulation to block withdrawals?
- [ ] **Proof context account lifecycle**: Are proof context state accounts closed after use? (rent drain if not)
- [ ] **`decrypt_u32` overflow**: Balances are decrypted as `u32` — does the protocol handle amounts exceeding 2^32?
- [ ] **Privacy mode enforcement**: Does the mint enforce the correct mode (`Disabled`/`Whitelisted`/`OptIn`/`Required`)?

---

## Vulnerability Patterns

### 1. ElGamal Key Derivation — Single Point of Compromise

**Severity**: HIGH

**Risk**: ElGamal and AES keys are derived **deterministically** from the account owner's keypair. If the signer keypair is compromised, the attacker can reconstruct all encryption keys and decrypt every past and future confidential balance and transfer.

```rust
// Key derivation — DETERMINISTIC from signer + token account address
let elgamal_keypair = ElGamalKeypair::new_from_signer(
    authority,                          // signer keypair
    &token_account.to_bytes(),          // token account as salt
)?;
let aes_key = AeKey::new_from_signer(
    authority,                          // same signer keypair
    &token_account.to_bytes(),          // same salt
)?;
```

**Detection**: Flag any protocol that stores or transmits the signer keypair. Flag key derivation that uses a static or predictable salt instead of the token account address.

**Audit concerns**:
- No key rotation mechanism — compromised key exposes **all historical** encrypted data
- Same keypair → same ElGamal keys for every token account owned by that wallet (salt differs, but signer is the single secret)
- Wallet drainer malware that captures the signer can silently decrypt all confidential balances without on-chain evidence
- Hardware wallet users may have a false sense of security — the derivation requires the raw signer, which HSMs may not expose for ElGamal

### 2. Pending Balance Counter Manipulation (DoS)

**Severity**: MEDIUM

**Risk**: Each confidential account has a `pending_balance_credit_counter` with a maximum (default: 65536). An attacker can spam tiny confidential transfers to exhaust this counter, blocking the victim from receiving further transfers until they call `apply_pending_balance`.

```rust
// Configure sets the maximum counter
let max_pending_balance_credit_counter = 65536u64;

// Each incoming transfer increments the counter
// apply_pending_balance resets it

// ❌ Vulnerable: protocol relies on continuous receipt of confidential transfers
// without periodically applying pending balances
```

**Detection**:
- Check if `max_pending_balance_credit_counter` is set too low (easy to exhaust)
- Check if the protocol has automated `apply_pending_balance` calls
- Check if the protocol handles `PendingBalanceCreditCounterExceeded` errors gracefully

**Impact**: Temporary DoS — victim cannot receive new confidential transfers. Not a fund loss, but can break protocol flows that depend on timely receipt (e.g., payment channels, streaming payments).

### 3. Proof Verification Bypass

**Severity**: CRITICAL

**Risk**: Confidential transfers require three separate ZK proofs (equality, ciphertext validity, range). Each proof is created as a separate on-chain context state account. If a protocol builds custom transfer logic and skips any proof, an attacker can mint tokens from nothing or transfer more than their balance.

```rust
// A confidential transfer requires ALL THREE proof accounts:
// 1. Equality proof — proves sender's encrypted balance matches claimed value
// 2. Ciphertext validity proof — proves encrypted amounts are well-formed
// 3. Range proof — proves transfer amount is non-negative and ≤ balance

// ❌ Vulnerable: custom wrapper that only creates some proofs
token.confidential_transfer_transfer(
    &sender_account,
    &recipient_account,
    &sender_pubkey,
    Some(&equality_proof),          // ✓
    Some(&ciphertext_validity),     // ✓
    None,                           // ✗ MISSING range proof!
    amount,
    // ...
)
```

**Detection**: Trace every confidential transfer call. Verify all three `ProofLocation` arguments are `Some(...)` and point to valid, newly-created context state accounts. Flag any `None` proof argument.

**Note**: The Token-2022 program itself enforces proof verification. This vulnerability applies to **custom wrappers or CPI callers** that incorrectly construct the transfer instruction.

### 4. Auditor Key Privacy Implications

**Severity**: MEDIUM

**Risk**: Mints can configure an `auditor_elgamal_pubkey`. This key can decrypt **all transfer amounts** (not balances) for every confidential transfer of that mint. If the auditor key is compromised, all transfer amounts become public — retroactively.

```rust
// Mint configuration — auditor can see all transfer amounts
let auditor_elgamal_pubkey: Option<ElGamalPubkey> =
    Option::<PodElGamalPubkey>::from(mint_ct_extension.auditor_elgamal_pubkey)
        .map(|pk| pk.try_into())
        .transpose()?;

// Every transfer encrypts amount for: sender, recipient, AND auditor
let proof_data = transfer_info.generate_split_transfer_proof_data(
    amount,
    &sender_elgamal,
    &sender_aes,
    &recipient_elgamal_pubkey,
    auditor_elgamal_pubkey.as_ref(), // ← auditor sees every amount
)?;
```

**Detection**:
- Check if the mint has an auditor key configured — users may not know their "confidential" transfers are auditable
- Check who controls the auditor key and whether it can be rotated
- Check if the auditor key is the same as the mint authority (centralization risk)
- Flag mints with `Required` privacy mode + auditor key — users are forced into auditable confidential transfers

### 5. Balance Type Confusion

**Severity**: HIGH

**Risk**: Each account has three balances (public, pending, available). A protocol that reads the wrong balance type will have incorrect accounting — potentially allowing double-spends or blocking legitimate withdrawals.

```rust
// ❌ Vulnerable: reading public balance when confidential balance is relevant
let public_balance = account.base.amount;  // ← WRONG for confidential flows
// After deposit, public balance is 0 but available balance has the funds

// ❌ Vulnerable: reading pending instead of available
let pending_lo = ct_extension.pending_balance_lo;  // ← not yet spendable!

// ✅ Correct: decrypt available balance for spendable amount
let available_ct: ElGamalCiphertext = ct_extension.available_balance.try_into()?;
let available = available_ct.decrypt_u32(elgamal_keypair.secret())
    .ok_or("Decryption failed")?;

// ✅ Correct: check public balance for non-confidential operations
let public_balance = account.base.amount;  // ← correct for public transfers
```

**Detection**:
- Flag any `account.base.amount` read when the account has `ConfidentialTransferAccount` extension enabled
- Flag protocols that don't distinguish between the three balance types in their accounting
- Check for `pending` balance reads without prior `apply_pending_balance` — pending is not spendable

### 6. Multi-Transaction Flow Atomicity

**Severity**: HIGH

**Risk**: A single confidential transfer requires **up to 7 transactions** (3 proof account creations + 1 transfer + 3 proof account closures). These are NOT atomic. Between any two transactions, an attacker can:

- Front-run with a state-changing transaction
- Cause proof context accounts to be closed prematurely
- Race to use the same proof accounts in a different transfer

```
Transaction sequence for one confidential transfer:

  Tx 1: Create equality proof context account
  Tx 2: Create ciphertext validity proof context account
  Tx 3: Create range proof context account
  ──── ATOMICITY GAP ────
  Tx 4: Execute confidential transfer (reads all 3 proof accounts)
  ──── ATOMICITY GAP ────
  Tx 5: Close equality proof account
  Tx 6: Close ciphertext validity proof account
  Tx 7: Close range proof account
```

**Detection**:
- Check if the protocol assumes confidential transfers are atomic
- Check for time-sensitive logic that depends on confidential transfer completion
- Check if proof context accounts have proper ownership (only the creator should be able to close them)
- Flag any protocol that doesn't handle partial failure (e.g., proofs created but transfer fails)

**Impact**: Proof accounts cost rent (~0.003 SOL each). If transfers frequently fail between steps 3-4, rent accumulates. Protocols must handle cleanup.

### 7. Key Compromise — Full Balance Exposure

**Severity**: CRITICAL

**Risk**: Because key derivation is deterministic (Pattern 1), a compromised keypair doesn't just allow theft of funds — it **retroactively exposes all encrypted balances and transfer history**. An attacker who obtains the private key can:

1. Derive the ElGamal keypair from the signer
2. Decrypt `available_balance` (current spendable amount)
3. Decrypt `pending_balance_lo` + `pending_balance_hi` (incoming transfers)
4. Decrypt `decryptable_available_balance` via the AES key
5. Reconstruct full transaction history by decrypting all past transfer ciphertexts

```rust
// Attacker with stolen keypair can do:
let elgamal = ElGamalKeypair::new_from_signer(&stolen_keypair, &token_account.to_bytes())?;
let aes = AeKey::new_from_signer(&stolen_keypair, &token_account.to_bytes())?;

// Decrypt everything
let available = available_ct.decrypt_u32(elgamal.secret());   // current balance
let pending = pending_ct.decrypt_u32(elgamal.secret());       // incoming
let historical = aes.decrypt(&decryptable_balance)?;           // AES-encrypted copy
// Full exposure — no forward secrecy
```

**No mitigation exists on-chain** — this is a fundamental property of the deterministic key derivation design. Auditors should flag any protocol that claims "confidential" transfers provide protection against key compromise.

---

## `decrypt_u32` Range Limitation

Confidential balance decryption uses `decrypt_u32`, which returns a `u32` (max ~4.29 billion). For tokens with high decimal precision or large supplies, this creates a silent overflow risk:

```rust
// decrypt_u32 returns Option<u32> — max value 4,294,967,295
let balance = available_ct.decrypt_u32(elgamal.secret())
    .ok_or("Decryption failed")?;
// If actual encrypted value > u32::MAX, decryption returns None → treated as failure

// Pending balance uses split encoding: lo (u32) + hi (u32) << 16
let pending_total = pending_lo + (pending_hi << 16);
// Maximum representable: ~281 trillion (2^48) — but only if hi/lo are used correctly
```

**Detection**: Check if the protocol handles `None` from `decrypt_u32` (decryption failure vs overflow). Check if tokens with >9 decimals are used confidentially — balance in base units may exceed `u32`.

---

## Proof Context Account Lifecycle

Proof context state accounts are temporary on-chain accounts that store ZK proof data. They must be managed carefully:

| Concern | Risk | Detection |
|---------|------|-----------|
| Not closed after transfer | Rent drain (~0.003 SOL each × 3 per transfer) | Check for `close_context_state_account` calls after transfer |
| Closed before transfer reads them | Transfer instruction fails | Check transaction ordering |
| Reused across transfers | Proof replay — wrong proof for different transfer | Check that new keypairs are generated per transfer |
| Wrong close authority | Attacker closes proof accounts to grief transfer | Verify close authority matches sender |

```rust
// ✅ Correct: close proof accounts after successful transfer
token.confidential_transfer_close_context_state_account(
    &equality_proof_account.pubkey(),
    &sender_token_account,           // rent destination
    &sender.pubkey(),                // close authority = sender
    &[sender],
).await?;
```

---

## Privacy Mode Enforcement

| Mode | Behavior | Audit Concern |
|------|----------|---------------|
| `Disabled` | No confidential transfers | Check if protocol expects confidentiality but mint is disabled |
| `Whitelisted` | Only approved accounts | Who controls the whitelist? Centralization risk |
| `OptIn` | Accounts choose | Verify accounts are configured before confidential operations |
| `Required` | All transfers confidential | 7-tx overhead on every transfer — DoS amplification |

---

## Related Exploits

No public exploits of Token-2022 confidential transfers have been reported as of February 2026. The extension is currently deployed only on the ZK-Edge testnet (`https://zk-edge.surfnet.dev/`), with mainnet deployment pending.

**Adjacent vulnerabilities to monitor:**
- ElGamal implementation bugs in `solana-zk-sdk` (CVE tracking)
- ZK ElGamal Proof Program (`ZkE1Gama1Proof11111111111111111111111111111`) verification logic
- Token-2022 extension interaction bugs (confidential transfers + transfer hooks)
- Client-side proof generation timing attacks (side-channel on ElGamal decryption)

---

## Cross-References

| Resource | Relevance |
|----------|-----------|
| [pinocchio-security.md](../solana-scanner/resources/pinocchio-security.md) | Token-2022 discriminator validation (§2) |
| [solana-patterns.md](../solana-scanner/resources/solana-patterns.md) | General Solana vulnerability patterns |
| [account-validation.md](../solana-scanner/resources/account-validation.md) | Account owner/type validation |
