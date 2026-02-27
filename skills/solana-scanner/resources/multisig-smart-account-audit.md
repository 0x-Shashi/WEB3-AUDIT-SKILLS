---
id: SOL-MULTISIG-SMART-ACCOUNT-AUDIT
title: Multisig & Smart Account Audit Patterns
category: solana-scanner/resources
severity: critical
chains: [solana]
languages: [rust, typescript]
tags:
  - multisig
  - smart-account
  - squads
  - proposal
  - threshold
  - spending-limit
  - time-lock
  - session-key
  - passkey
  - pda
last_updated: 2026-02-27
description: >-
  Use when auditing Solana multisig programs, smart account implementations,
  or any program with multi-party authorization — covers Squads V4 multisig
  patterns (threshold validation, proposal lifecycle attacks, vault PDA
  security, permission system), spending limit circumvention, time lock
  bypass, and Smart Account Program patterns (session keys, passkeys,
  programmable policies). Derived from Squads SDK and Smart Account
  architecture analysis.
---

# Multisig & Smart Account Audit Patterns

## Overview

Multisig and smart account programs are TRUST INFRASTRUCTURE — they protect
other protocols' treasuries, upgrades, and governance. A vulnerability here
doesn't just affect one protocol — it affects every protocol that uses the
multisig as its admin. This makes them the highest-value audit targets in
the Solana ecosystem.

### Architecture: Squads V4

```
┌────────────────────────────────────────────────┐
│              SQUADS V4 MULTISIG                 │
│                                                 │
│  ┌──────────┐   ┌──────────────┐               │
│  │ Multisig │   │  Vault PDA   │               │
│  │ Config   │──▶│  (holds SOL/ │               │
│  │ (members,│   │   tokens)    │               │
│  │ threshold)│   └──────────────┘               │
│  └─────┬────┘                                   │
│        │                                        │
│  ┌─────▼──────┐   ┌──────────────┐             │
│  │ Proposal    │──▶│ Transaction  │             │
│  │ (vote track)│   │ (instruction │             │
│  └─────┬──────┘   │  payload)    │             │
│        │           └──────────────┘             │
│  ┌─────▼──────┐   ┌──────────────┐             │
│  │ Spending   │   │ Batch Tx     │             │
│  │ Limits     │   │ (atomic      │             │
│  │ (bypass    │   │  multi-ix)   │             │
│  │  proposals)│   └──────────────┘             │
│  └────────────┘                                 │
└────────────────────────────────────────────────┘
```

### Permission Model

Squads V4 uses a 3-permission bit field per member:

| Permission | Bit | What It Allows |
|-----------|-----|---------------|
| Initiate | 1 | Create proposals and transactions |
| Vote | 2 | Approve or reject proposals |
| Execute | 4 | Execute approved proposals |

**Critical insight**: Permissions are INDEPENDENT. A member can have
Execute without Vote, or Vote without Initiate. This creates subtle
attack surfaces.

## Threshold Validation Vulnerabilities

### Pattern 1: Threshold = 0

**Vulnerability**: If threshold is set to 0, any single member (even
with only Execute permission) can execute proposals without votes.

```rust
// ❌ DANGEROUS: No minimum threshold enforcement
pub fn create_multisig(threshold: u16, members: Vec<Member>) -> Result<()> {
    state.threshold = threshold; // Could be 0!
    Ok(())
}

// ✅ SAFE: Enforce minimum threshold
require!(threshold >= 1, ErrorCode::ThresholdTooLow);
require!(threshold <= voting_member_count, ErrorCode::ThresholdExceedsMembers);
```

**Audit checklist for threshold**:
- [ ] Is threshold >= 1 enforced on creation?
- [ ] Is threshold <= number of voting members?
- [ ] After member removal: is threshold still <= remaining voters?
- [ ] Can threshold be changed? Through what process?
- [ ] Is there a config transaction for threshold changes? (requires its own approval)

### Pattern 2: Threshold-to-Member Ratio After Removal

**Vulnerability**: Remove members until threshold exceeds remaining voter
count. Now proposals can never be approved — permanent lockout.

```
Initial state: 5 members, threshold = 3
Remove member A → 4 members, threshold = 3 (still ok)
Remove member B → 3 members, threshold = 3 (requires ALL members)
Remove member C → 2 members, threshold = 3 (IMPOSSIBLE to approve anything)
→ Multisig is permanently locked
```

**Audit check**: Does the protocol enforce `threshold <= voting_members`
after EVERY member removal?

## Proposal Lifecycle Attacks

### The Proposal State Machine

```
Created → Active → Approved → Executed
  │         │         │
  │         ▼         ▼
  │     Rejected   Cancelled
  ▼
Cancelled
```

### Pattern 3: Stale Proposal Execution

**Vulnerability**: Proposal approved months ago, context has changed,
but it can still be executed.

```
Attack:
1. January: Proposal to send $1M to address X is approved
2. February: Address X is compromised (unknown to multisig)
3. March: Attacker executes the stale approval → $1M stolen

Mitigations:
- Proposal expiration (approved proposals expire after N days)
- Re-approval required after threshold changes
- Stale transaction index checks
```

### Pattern 4: Config Transaction Ordering

**Vulnerability**: Config transactions (add/remove member, change threshold)
can be re-ordered to achieve unauthorized outcomes.

```
Attack:
1. Proposal A: Add malicious member M (approved by honest majority)
2. Proposal B: Change threshold from 3/5 to 2/5 (not yet approved)
3. Attacker executes B first (now only needs 2 votes)
4. M + one colluding member approve and execute anything

Audit check: Are config transactions ordered and executed sequentially?
Does executing one invalidate pending others?
```

### Pattern 5: Vote Replay

**Vulnerability**: Member votes for proposal N, but the vote is
counted for proposal N+1 due to index confusion.

```rust
// ❌ DANGEROUS: Vote references proposal by index only
pub fn approve(ctx: Context<Approve>, proposal_index: u64) -> Result<()> {
    // If proposal_index is reused after cancellation...
    let proposal = &mut ctx.accounts.proposal;
    proposal.approved.push(ctx.accounts.member.key());
}

// ✅ SAFE: Verify proposal is in Active state AND matches expected
require!(proposal.status == ProposalStatus::Active);
require!(proposal.transaction_index == expected_index);
```

## Vault PDA Security

### Pattern 6: Vault PDA Derivation

Vault PDAs hold the actual funds. Their security is paramount.

```rust
// Squads vault PDA derivation
let [vault_pda] = multisig.getVaultPda({
    multisigPda,
    index: 0, // vault index
});

// Critical audit checks:
// 1. Is the vault index validated? (can't use arbitrary index)
// 2. Is the multisig PDA verified as a real multisig? (not spoofed)
// 3. Can vault 0 vs vault 1 be confused?
// 4. Are vault funds accessible without going through proposal flow?
```

### Pattern 7: Ephemeral Signer PDA Bypass

Squads uses ephemeral signers for CPI calls from the vault:

```rust
// Ephemeral signer: temporary PDA that signs CPIs on vault's behalf
let [ephemeral_signer] = multisig.getEphemeralSignerPda({
    transactionPda,
    ephemeralSignerIndex: 0,
});
```

**Vulnerability**: If the ephemeral signer derivation doesn't include the
transaction PDA, a signer from one transaction could be reused for another.

**Audit checklist**:
- [ ] Ephemeral signer seeds include transaction PDA (binds to specific tx)
- [ ] Ephemeral signer index prevents collision within same tx
- [ ] Cannot derive an ephemeral signer for a transaction that wasn't approved

## Spending Limit Vulnerabilities

### How Spending Limits Work

Spending limits let trusted members transfer funds WITHOUT creating a
proposal and going through the full approval flow.

```rust
// Spending limit configuration
SpendingLimit {
    multisig: Pubkey,       // parent multisig
    create_key: Pubkey,     // unique identifier
    vault_index: u8,        // which vault
    mint: Pubkey,           // token type (SOL or SPL)
    amount: u64,            // maximum per period
    period: Period,         // Day, Week, Month, OneTime
    remaining_amount: u64,  // amount left in current period
    last_reset: i64,        // timestamp of last period reset
    bump: u8,
    members: Vec<Pubkey>,   // who can use this limit
    destinations: Vec<Pubkey>, // where funds can go
}
```

### Pattern 8: Spending Limit Period Reset Manipulation

**Vulnerability**: Reset the period to gain a fresh allowance.

```
Attack:
1. Spending limit: 10 SOL per Day
2. Use 10 SOL at 23:59 UTC → remaining = 0
3. Clock ticks to 00:00 UTC → period resets → remaining = 10 SOL
4. Use 10 SOL at 00:01 UTC → 20 SOL spent in 2 minutes

Audit check: Is the period boundary manipulation-resistant?
Use clock.unix_timestamp, not slot-based timing.
```

### Pattern 9: Spending Limit Destination Bypass

**Vulnerability**: Spending limit restricts destinations, but the destination
is a contract that forwards funds elsewhere.

```
Attack:
1. Spending limit allows transfers only to address A
2. Address A is a token account owned by the attacker's program
3. Attacker's program forwards funds to any address
4. Destination restriction is bypassed

Audit check: Are destination restrictions based on final recipient
or just the immediate transfer target?
```

### Pattern 10: Multiple Spending Limits Stacking

**Vulnerability**: Multiple spending limits on the same vault can be used
in the same transaction, draining more than intended.

```
Configuration:
- Limit 1: 10 SOL/day for member A, vault 0
- Limit 2: 10 SOL/day for member A, vault 0 (different create_key)

Attack: Member A uses BOTH limits → 20 SOL/day instead of intended 10

Audit check: Are spending limits deduplicated per (member, vault, mint)?
```

## Time Lock Vulnerabilities

### Pattern 11: Time Lock Bypass via Config Transaction

**Vulnerability**: Modify the time lock duration through a config
transaction, then execute the original transaction immediately.

```
Attack:
1. Protocol has 24-hour time lock
2. Attacker submits: Config Tx A → set timeLock = 0
3. Attacker submits: Vault Tx B → drain treasury
4. Approve and execute A → time lock is now 0
5. Approve and execute B → executes immediately (no wait)

Audit check: Do time lock changes take effect AFTER the time lock period?
(i.e., changing from 24h to 0 should itself take 24h)
```

### Pattern 12: Time Lock Clock Manipulation

**Vulnerability**: On Solana, `Clock::get()` returns validator-reported time.
In rare cases, timestamp can go backwards.

```rust
// ❌ BRITTLE: Exact time comparison
require!(
    clock.unix_timestamp >= proposal.approved_timestamp + time_lock,
    ErrorCode::TimeLockNotExpired
);

// ✅ SAFER: Use >= with monotonic assumption documented
// Note: Solana guarantees timestamps are non-decreasing within a slot,
// but not across slots. For security-critical time locks, prefer
// slot-based counting as a secondary check.
```

## Smart Account Program Patterns

### Architecture: Programmable Wallets

Smart Account Programs (like Squads' SAP) extend multisig with:
- **Session keys**: Temporary keys with limited permissions
- **Passkeys**: WebAuthn/FIDO2 biometric authentication
- **Policies**: Programmable rules governing execution

### Pattern 13: Session Key Scope Escalation

**Vulnerability**: Session key granted for "swap on Jupiter" is used to
"swap on malicious DEX" because the scope is too broad.

```
Intended: Session key can call Jupiter swap program
Actual: Session key can call ANY program with swap-like instruction

Audit focus:
- Is the allowed program ID hardcoded in the session key?
- Is the instruction discriminator (first 8 bytes) checked?
- Can the session key be used for CPI through an intermediary?
- Is there a spending cap on session key operations?
```

### Pattern 14: Passkey Verification Bypass

**Vulnerability**: Passkey verification happens off-chain, and only the
result (a signature) is verified on-chain.

```
Attack surface:
1. Is the WebAuthn challenge properly bound to the transaction?
2. Is the relying party (RP) ID verified? (prevents cross-site attacks)
3. Is the signature algorithm restricted? (P-256 only, no RSA)
4. Can an old passkey attestation be replayed?
5. Is user presence vs user verification distinguished?
```

### Pattern 15: Policy Composition Conflicts

**Vulnerability**: Two policies individually are safe, but their
COMBINATION creates an unsafe state.

```
Example:
- Policy A: Allow transfers up to 100 SOL per day
- Policy B: Allow any transfer to whitelisted addresses

Combined: Policy B allows unlimited transfers to whitelisted addresses,
bypassing Policy A's daily limit.

Audit check: Are policies AND-composed (all must pass) or OR-composed
(any one passing is sufficient)? AND is generally safer.
```

## PDA Derivation Reference & Audit Points

### Critical PDA Seeds

| PDA | Seeds | Audit Focus |
|-----|-------|-------------|
| Multisig | `["multisig", create_key]` | Is create_key truly unique? |
| Vault | `["vault", multisig, vault_index]` | Can vault_index be spoofed? |
| Transaction | `["transaction", multisig, tx_index]` | Is tx_index sequential? |
| Proposal | `["proposal", multisig, tx_index]` | Bound to specific transaction? |
| Batch | `["batch", multisig, batch_index]` | Are batch items ordered? |
| Spending Limit | `["spending_limit", multisig, create_key]` | Unique per limit? |
| Ephemeral Signer | `["ephemeral_signer", tx, index]` | Bound to specific transaction? |

### PDA Audit Checklist

For each PDA in the program:
- [ ] Seeds include sufficient entropy (no collisions possible)
- [ ] Bump is stored and verified (prevents grinding)
- [ ] Owner is checked after derivation
- [ ] PDA is not writable when it shouldn't be
- [ ] PDA cannot be closed and re-created with different data

## Comprehensive Audit Checklist

### Multisig Configuration
- [ ] Threshold >= 1 enforced at all times
- [ ] Threshold <= voting member count after every member change
- [ ] Member permissions are correctly enforced per operation
- [ ] Config authority (if set) is properly authorized
- [ ] Rent collector is authorized and bounded

### Proposal Flow
- [ ] Only members with Initiate permission can create proposals
- [ ] Only members with Vote permission can approve/reject
- [ ] Only members with Execute permission can execute
- [ ] Proposals expire (no stale execution)
- [ ] Cancelled proposals cannot be re-activated
- [ ] Vote count is accurate (no double-voting)

### Vault Security
- [ ] Vault PDA derivation is deterministic and verifiable
- [ ] Funds cannot leave vault without approved proposal or spending limit
- [ ] Ephemeral signers are bound to their specific transaction
- [ ] Multiple vault indices are properly isolated

### Spending Limits
- [ ] Period reset is based on real time (not manipulable)
- [ ] Destination restrictions cannot be bypassed via intermediary
- [ ] Multiple limits don't stack beyond intended total
- [ ] Only authorized members can use each limit
- [ ] Limit amount cannot overflow

### Time Locks
- [ ] Time lock changes are themselves time-locked
- [ ] Clock source is reliable (Clock::get())
- [ ] Time lock cannot be bypassed via config transaction ordering
- [ ] Emergency bypass (if any) is properly authorized

### Smart Account Extensions
- [ ] Session keys are scoped to specific programs and instructions
- [ ] Session keys have expiration and spending caps
- [ ] Passkey verification is complete (challenge, RP ID, algorithm)
- [ ] Policy composition is AND-based (all must pass)
- [ ] Direct debit/subscription limits are non-bypassable

## Integration with Other Skills

| Skill | Relationship |
|-------|-------------|
| [CPI Adversarial Security](../../patterns/cpi-adversarial-security.md) | Vault CPIs must verify program identity |
| [AA/ERC-7715 Permission Security](../../patterns/aa-erc7715-permission-security.md) | EVM counterpart for account abstraction |
| [EIP-7702 Delegation Security](../../patterns/eip-7702-delegation-security.md) | EVM delegation model comparison |
| [Formal Verification Assessment](../../methodology/formal-verification-assessment.md) | Multisig invariants are ideal for FV |
| [Solana Oracle Audit](solana-oracle-audit.md) | Oracle accounts often held in multisig vaults |
