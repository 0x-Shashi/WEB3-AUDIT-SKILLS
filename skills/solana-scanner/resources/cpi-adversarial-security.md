---
id: RES-SOLANA-CPI-ADVERSARIAL
title: Adversarial CPI Binding Security Patterns
category: resource
parent: SCANNER-SOLANA
chains: [solana]
languages: [rust]
frameworks: [native, pinocchio, anchor]
last_updated: 2026-02-25
description: >-
  Use when auditing Solana programs that invoke external programs via CPI —
  covers adversarial matcher models, identity binding, shape validation,
  ABI return verification, nonce discipline, trust boundary architecture,
  and exec_size vs requested_size discipline. Derived from production
  formal verification of the Percolator perpetuals program.
---

# Adversarial CPI Binding Security Patterns

## Overview

When a Solana program delegates execution to an external program via CPI
(Cross-Program Invocation), the external program must be treated as **fully
adversarial**. The calling program receives structured return data that could be
crafted to bypass security checks. This resource documents production-grade CPI
binding patterns proven correct via 110 Kani formal verification proofs.

> **Core principle**: Never trust a CPI return value. Validate identity, shape,
> ABI format, and semantic constraints before acting on any CPI result.

## Trust Boundary Architecture

Production CPI-heavy programs enforce three distinct trust layers:

```
┌─────────────────────────────────────────────────────┐
│  Layer 1: Core Engine (trusted)                     │
│  • Pure state machine — no CPI, no I/O              │
│  • Accounting, risk checks, state transitions       │
│  • Atomicity guarantee from Solana runtime           │
├─────────────────────────────────────────────────────┤
│  Layer 2: Program Wrapper (trusted glue)            │
│  • Validates accounts, owners, signers              │
│  • Performs token transfers via PDA signer           │
│  • Reads oracle prices                              │
│  • Runs optional CPI to external programs           │
│  • Enforces coupling invariants (identity, nonce)   │
├─────────────────────────────────────────────────────┤
│  Layer 3: External Program (adversarial)            │
│  • Provides execution results (price, size, flags)  │
│  • Trusted ONLY by the party that registered it     │
│  • Protocol treats ALL returns as adversarial input  │
└─────────────────────────────────────────────────────┘
```

**What to check in any CPI-using program**:
- [ ] Is the core state machine isolated from CPI? (Layer 1 purity)
- [ ] Does the wrapper validate ALL accounts before CPI? (Layer 2 completeness)
- [ ] Are CPI return values validated before use? (Layer 3 distrust)

## 1. Identity Binding (Mandatory)

Before invoking a CPI, the calling program must verify that the external program
and its context account match what was registered by the participant.

### The Check

```rust
// Identity binding: matcher program + context must equal LP registration
fn identity_ok(
    registered_program: &Pubkey,
    registered_context: &Pubkey,
    provided_program: &Pubkey,
    provided_context: &Pubkey,
) -> bool {
    registered_program == provided_program
        && registered_context == provided_context
}
```

### Formally Proven Property

```
∀ (reg_prog, reg_ctx, prov_prog, prov_ctx):
    identity_ok == (reg_prog == prov_prog ∧ reg_ctx == prov_ctx)
    
    Identity MISMATCH → REJECT (even if ABI is perfectly valid)
```

**Attack blocked**: Attacker substitutes a malicious program that mimics the expected
interface (same ABI, correct-looking returns) but executes different logic. Without
identity binding, the substitution succeeds silently.

**What to check**:
- [ ] Are both program ID AND context account verified against stored registration?
- [ ] Is identity binding checked BEFORE the CPI invocation?
- [ ] Can the registration be updated? By whom? With what authorization?
- [ ] Is there a cooldown period after registration changes?

## 2. Shape Validation (Before CPI)

Before invoking CPI, validate the structural properties of the external program
and its context account:

### The Checks

```rust
fn matcher_shape_ok(
    prog_executable: bool,  // program must be executable
    ctx_executable: bool,   // context must NOT be executable
    ctx_owned: bool,        // context owner must be the program
    ctx_len_ok: bool,       // context must be large enough for return prefix
) -> bool {
    prog_executable && !ctx_executable && ctx_owned && ctx_len_ok
}
```

### Formally Proven Property

```
∀ (prog_exec, ctx_exec, ctx_owned, ctx_len):
    shape_ok == (prog_exec ∧ ¬ctx_exec ∧ ctx_owned ∧ ctx_len)
    
    ANY shape failure → REJECT regardless of all other inputs
```

**Why each check matters**:

| Check | Attack if Missing |
|-------|-------------------|
| `prog_executable` | Non-program account treated as callable → CPI fails or unexpected behavior |
| `!ctx_executable` | Executable account as context → attacker controls execution |
| `ctx_owned` | Context owned by different program → data written by attacker |
| `ctx_len_ok` | Context too short → return prefix read crosses account boundary |

**What to check**:
- [ ] Are all four shape conditions validated before CPI?
- [ ] Is the length check using the ACTUAL return prefix size, not a hardcoded constant?
- [ ] Is `is_executable` checked on the program account?
- [ ] Is `owner` checked on the context account?

## 3. PDA Identity Signer

When the calling program needs to prove its identity during CPI (e.g., the
counterparty's PDA), the PDA must have "pure identity" properties:

```rust
fn lp_pda_shape_ok(
    system_owned: bool,  // owned by system program (not any program)
    data_zero: bool,     // empty data (no state to exploit)
    lamports_zero: bool, // unfunded (no economic surface)
) -> bool {
    system_owned && data_zero && lamports_zero
}
```

**Attack blocked**: If the PDA has data or lamports, an attacker could exploit
it as a state-bearing account or drain its funds through CPI side effects.

**What to check**:
- [ ] Are PDA signers verified as system-owned, empty, and unfunded?
- [ ] Is the PDA derivation deterministic (seeds include participant index)?
- [ ] Can the PDA be funded by a third party to violate shape constraints?

## 4. ABI Return Validation (After CPI)

The external program writes its return value into the context account's first bytes.
This return value is **adversarial input** that must be validated field by field.

### Validation Gate Sequence

```rust
fn validate_matcher_return(ret: &MatcherReturn, req: &Request) -> Result<(), Error> {
    // Gate 1: ABI version must match
    if ret.abi_version != EXPECTED_ABI_VERSION {
        return Err(Error::AbiMismatch);
    }
    
    // Gate 2: VALID flag required
    if ret.flags & FLAG_VALID == 0 {
        return Err(Error::MissingValidFlag);
    }
    
    // Gate 3: REJECTED flag must be clear
    if ret.flags & FLAG_REJECTED != 0 {
        return Err(Error::Rejected);
    }
    
    // Gate 4: Reserved/padding must be zero
    if ret.reserved != 0 {
        return Err(Error::NonZeroReserved);
    }
    
    // Gate 5: Exec price must be non-zero
    if ret.exec_price_e6 == 0 {
        return Err(Error::ZeroPrice);
    }
    
    // Gate 6: Zero exec_size requires PARTIAL_OK flag
    if ret.exec_size == 0 && ret.flags & FLAG_PARTIAL_OK == 0 {
        return Err(Error::ZeroSizeWithoutPartialOk);
    }
    
    // Gate 7: |exec_size| must not exceed |req_size|
    if ret.exec_size.unsigned_abs() > req.req_size.unsigned_abs() {
        return Err(Error::ExecExceedsReq);
    }
    
    // Gate 8: Sign must match (when req_size != 0)
    if req.req_size != 0 && sign(ret.exec_size) != sign(req.req_size) {
        return Err(Error::SignMismatch);
    }
    
    // Gate 9: Echoed fields must match request
    if ret.req_id != req.expected_req_id { return Err(Error::ReqIdMismatch); }
    if ret.lp_account_id != req.lp_id { return Err(Error::LpIdMismatch); }
    if ret.oracle_price != req.oracle_price { return Err(Error::OracleMismatch); }
    
    Ok(())
}
```

### Formally Proven Properties

Each gate has a "kill switch" proof: **a single gate failure causes rejection
regardless of ALL other inputs being valid**.

```
∀ inputs: ¬shape_ok → Reject     (8 proofs: shape, pda, user_auth, lp_auth,
∀ inputs: ¬identity → Reject      identity, abi, gate_risk_increase, panic_admin)
∀ inputs: ¬abi_ok  → Reject
```

### i128::MIN Edge Case

When working with signed sizes (i128 for position sizes), special care is needed:

```rust
// DANGEROUS: .abs() panics on i128::MIN
let size = i128::MIN;
let abs_size = size.abs();  // ← PANIC! Undefined behavior

// SAFE: .unsigned_abs() returns u128, handles MIN correctly
let abs_size = size.unsigned_abs();  // Returns 170141183460469231731687303715884105728
```

**What to check**:
- [ ] Are all size comparisons using `unsigned_abs()` instead of `.abs()`?
- [ ] Is `i128::MIN` explicitly tested?

## 5. Execution Size Discipline

A critical coupling invariant: the calling program must use the external program's
`exec_size`, **never** the user's originally requested size.

```rust
fn cpi_trade_size(exec_size: i128, _requested_size: i128) -> i128 {
    exec_size  // ALWAYS use the external program's size
}
```

### Formally Proven Property

```
∀ (exec_size, req_size):
    cpi_trade_size(exec_size, req_size) == exec_size
    
On Accept: chosen_size == exec_size (never req_size)
```

**Attack blocked**: Without this discipline, a user could request size X, the matcher
approves size Y < X, but the trade executes at size X — creating an unauthorized
position.

**What to check**:
- [ ] After CPI, does the program use `exec_size` from the return, not `req_size`?
- [ ] Is this discipline enforced in ALL code paths (not just the happy path)?
- [ ] Are there any intermediate variables that cache `req_size` and accidentally reuse it?

## 6. Nonce Discipline

Requests to external programs include a nonce (derived from on-chain state) that
must be echoed in the return. Nonce transitions follow strict rules:

```
On Reject: new_nonce == old_nonce       (state unchanged)
On Accept: new_nonce == old_nonce + 1   (wrapping at u64::MAX → 0)
```

### Formally Proven Properties

```
∀ old_nonce: nonce_on_failure(old_nonce) == old_nonce
∀ old_nonce: nonce_on_success(old_nonce) == old_nonce.wrapping_add(1)

∀ inputs: Reject → nonce_unchanged
∀ inputs: Accept → nonce_incremented ∧ chosen_size == exec_size
```

**Attack blocked**: Without nonce binding, an attacker can replay a previous
matcher response (which authorized a different trade) against a new request.

**What to check**:
- [ ] Is the nonce derived from on-chain state (not client-provided)?
- [ ] Does the return validation check `ret.req_id == expected_nonce`?
- [ ] Is the nonce strictly monotonic?
- [ ] On rejection, does the nonce remain unchanged?
- [ ] Does the nonce handle wrapping at `u64::MAX`?

## 7. Risk-Reduction Gating

When the system is under-insured, the wrapper enforces "risk-reduction-only" mode:

```rust
fn gate_active(threshold: u128, insurance_balance: u128) -> bool {
    threshold > 0 && insurance_balance <= threshold
}

// When gate is active:
//   Risk-INCREASING trades → REJECTED
//   Risk-REDUCING trades  → ALLOWED
```

### Formally Proven Properties

```
∀ balance: threshold == 0         → ¬gate_active
∀ (thresh, bal): bal > threshold  → ¬gate_active
∀ (thresh, bal): thresh > 0 ∧ bal ≤ thresh → gate_active

gate_active ∧ risk_increase → Reject (universal kill switch)
```

**What to check**:
- [ ] Is there a circuit-breaker for risk-increasing operations?
- [ ] What conditions activate the gate? Are they manipulation-resistant?
- [ ] Can an attacker force the gate to stay active (insurance griefing)?
- [ ] Are risk-reducing operations always allowed during gating?

## 8. Authorization Composition

The full CPI trade authorization composes multiple checks:

```
Accept iff:
    shape_ok
    ∧ identity_ok
    ∧ pda_ok
    ∧ abi_ok
    ∧ user_auth_ok
    ∧ lp_auth_ok
    ∧ ¬(gate_active ∧ risk_increase)
```

**Formally proven**: Each gate is independently necessary (kill switch proofs)
AND the conjunction is sufficient (forced acceptance proof).

**What to check**:
- [ ] Are ALL gates evaluated, or does early return skip some?
- [ ] Is the gate ordering consistent between the verified function and the production handler?
- [ ] Are there any code paths that bypass the composition?

## Security Review Checklist

### Pre-CPI Validation
- [ ] Identity binding: program + context match stored registration
- [ ] Shape validation: executable program, non-executable context, correct owner, sufficient length
- [ ] PDA shape: system-owned, empty data, zero lamports
- [ ] Authorization: both parties signed

### Post-CPI Validation
- [ ] ABI version match
- [ ] Flag validation (VALID required, REJECTED clear)
- [ ] Reserved fields zero
- [ ] Price non-zero
- [ ] Size constraints (|exec| ≤ |req|, sign match)
- [ ] Echoed fields match request (req_id, lp_id, oracle_price)
- [ ] `i128::MIN` handled with `unsigned_abs()`

### State Transition
- [ ] `exec_size` used (never `req_size`)
- [ ] Nonce monotonicity enforced
- [ ] Risk gating evaluated after CPI
- [ ] State unchanged on rejection

## Cross-References

- [formal-verification-for-auditors.md](formal-verification-for-auditors.md) — How these proofs were structured and evaluated
- [pinocchio-security.md](pinocchio-security.md) — Low-level Pinocchio CPI patterns (§CPI)
- [anchor-security.md](anchor-security.md) — Anchor CPI safety (Program\<T\> typed accounts)
- [proof-strength-evaluation.md](../../methodology/proof-strength-evaluation.md) — 6-point evaluation methodology

## Sources

- Percolator program Kani proofs: 110 harnesses, 91 STRONG, 0 VACUOUS
- Proof strength audit: 6-point analysis methodology applied by Claude Opus 4.6
- Production trade authorization: 10-input symbolic universal characterization proof
