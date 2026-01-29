# Anchor Program Audit Workflow

Systematic workflow for auditing Anchor-based Solana programs.

---

## Phase 1: Setup (30 minutes)

### 1.1 Environment

```bash
# Clone and build
git clone [repo]
cd [repo]
anchor build

# Verify compilation
anchor test --skip-local-validator

# Generate IDL for reference
anchor idl parse -f programs/*/src/lib.rs -o idl.json
```

### 1.2 Scope Mapping

```markdown
## Audit Scope

**Program:** [Name]
**Anchor Version:** [version]
**Commit:** [hash]

### Instructions
| Instruction | File | Priority |
|-------------|------|----------|
| initialize | lib.rs:45 | High |
| deposit | lib.rs:78 | Critical |
| withdraw | lib.rs:112 | Critical |

### Account Types
| Type | Size | Purpose |
|------|------|---------|
| Pool | 84 | Main pool state |
| User | 56 | User position |
```

---

## Phase 2: Account Analysis (2-4 hours)

### 2.1 For Each Account Type

```markdown
## Account: Pool

### Fields
| Field | Type | Size | Purpose |
|-------|------|------|---------|
| authority | Pubkey | 32 | Pool admin |
| token_mint | Pubkey | 32 | Token mint |
| total | u64 | 8 | Total deposits |
| bump | u8 | 1 | PDA bump |

### Security Properties
- [ ] Authority can only be changed by authority
- [ ] Total accurately tracks deposits
- [ ] Bump stored for efficient PDA

### Invariants
1. total = sum of all user deposits
2. authority != Pubkey::default()
```

### 2.2 Account Validation Sweep

For each instruction's account struct:

```markdown
## Instruction: withdraw

### Account Validation Matrix

| Account | Type | Signer | Mut | Seeds | has_one | Constraint |
|---------|------|--------|-----|-------|---------|------------|
| user | Signer | ✅ | ❌ | ❌ | ❌ | ❌ |
| pool | Account<Pool> | ❌ | ✅ | ✅ | ✅ auth | ❌ |
| user_token | Account<TA> | ❌ | ✅ | ❌ | ❌ | owner, mint |

### Missing Validations
- [ ] None / [Issue found]
```

---

## Phase 3: Instruction Analysis (4-8 hours)

### 3.1 Per-Instruction Template

```markdown
## Instruction: [name]

### Purpose
[What this instruction does]

### Access Control
- Who can call: [Anyone / Authority / Specific user]
- Authorization verified by: [Signer check / has_one / constraint]

### Account Checks
[Copy from Account Validation Matrix]

### Logic Flow
1. [Step 1]
2. [Step 2]
3. [Step 3]

### Arithmetic Operations
| Operation | Type | Safe? | Notes |
|-----------|------|-------|-------|
| a + b | Addition | ✅ checked_add | |
| a - b | Subtraction | ❌ | Potential underflow |

### CPI Calls
| Target | Purpose | Secure? |
|--------|---------|---------|
| Token::transfer | Move tokens | ✅ |

### State Changes
| Account | Field | Before | After |
|---------|-------|--------|-------|
| pool | total | x | x + amount |

### Issues Found
- [None or list]
```

---

## Phase 4: Cross-Instruction Analysis (2-4 hours)

### 4.1 State Transition Analysis

```markdown
## State Transitions

### Pool Lifecycle
1. initialize → Pool created, authority set
2. deposit → total increases
3. withdraw → total decreases
4. [other transitions]

### Invariant Verification
| Invariant | Maintained By | Violation Possible? |
|-----------|---------------|---------------------|
| total = Σ deposits | deposit, withdraw | Check arithmetic |
```

### 4.2 Ordering Attacks

```markdown
## Instruction Ordering

### Tested Sequences
| Sequence | Expected | Actual | Issue? |
|----------|----------|--------|--------|
| init → deposit → withdraw | Normal | Normal | ✅ |
| deposit → close → withdraw | Fail | ? | Check |
| init → init | Fail | ? | Check reinit |
```

---

## Phase 5: Specific Vulnerability Checks

### 5.1 Critical Checks

```markdown
## Vulnerability Scan

### Missing Owner Check (AV-01)
- [ ] All Account<T> used (not AccountInfo)
- [ ] Or explicit owner check present

### Missing Signer Check (AV-02)
- [ ] Authority uses Signer<'info>
- [ ] Or explicit is_signer check

### PDA Validation (PDA-01)
- [ ] All PDAs have seeds constraint
- [ ] Bumps are verified (stored or canonical)

### CPI Security (CPI-01, CPI-02)
- [ ] All CPIs to known programs
- [ ] Program<'info, T> used for CPI targets

### Arithmetic (AR-01, AR-02)
- [ ] All math uses checked operations
- [ ] Or verified safe by bounds

### Initialization (INIT-01)
- [ ] init constraint used for new accounts
- [ ] No manual initialization without guard
```

### 5.2 Protocol-Specific

Based on protocol type, apply relevant checklist from SKILL.md.

---

## Phase 6: Testing (2-4 hours)

### 6.1 Write Attack Tests

```typescript
// tests/attack.ts
describe("Attack Tests", () => {
  it("Cannot reinitialize pool", async () => {
    // First init
    await program.methods.initialize().accounts({...}).rpc();
    
    // Attempt reinit
    try {
      await program.methods.initialize().accounts({...}).rpc();
      assert.fail("Should have failed");
    } catch (e) {
      assert.include(e.message, "already in use");
    }
  });

  it("Cannot withdraw without authority", async () => {
    const fakeUser = Keypair.generate();
    try {
      await program.methods.withdraw(amount)
        .accounts({ user: fakeUser.publicKey, ... })
        .signers([fakeUser])
        .rpc();
      assert.fail("Should have failed");
    } catch (e) {
      assert.include(e.message, "has_one");
    }
  });
});
```

### 6.2 Edge Case Tests

```typescript
describe("Edge Cases", () => {
  it("Handles zero amount", async () => { /* ... */ });
  it("Handles max amount", async () => { /* ... */ });
  it("Handles duplicate accounts", async () => { /* ... */ });
});
```

---

## Phase 7: Documentation (1-2 hours)

### Finding Template

```markdown
## [SOL-##] [Title]

**Severity:** Critical/High/Medium/Low
**Category:** Account Validation / PDA / CPI / Arithmetic / Logic

### Location
- Program: [name]
- Instruction: [name]
- File: programs/name/src/lib.rs
- Line: [number]

### Description
[Detailed explanation]

### Vulnerable Code
```rust
#[derive(Accounts)]
pub struct Vulnerable<'info> {
    // Issue here
}
```

### Impact
[What an attacker can do]

### Proof of Concept
```typescript
// Attack script
```

### Recommendation
```rust
#[derive(Accounts)]
pub struct Fixed<'info> {
    // Fixed version
}
```
```

---

## Anchor Quick Checks

```bash
# Find AccountInfo usage (should be minimal)
grep -rn "AccountInfo<'info>" programs/

# Find missing mut
grep -rn "Account<'info" programs/ | grep -v "mut"

# Find CPIs
grep -rn "CpiContext\|invoke\|invoke_signed" programs/

# Find arithmetic
grep -rn "\+\|-\|\*\|/" programs/ | grep -v "//" | grep -v "checked"

# Find unchecked blocks
grep -rn "unchecked" programs/
```

---

## Audit Completion Checklist

- [ ] All instructions analyzed
- [ ] All account types documented
- [ ] All account validations verified
- [ ] All PDAs validated
- [ ] All CPIs reviewed
- [ ] All arithmetic checked
- [ ] All invariants identified
- [ ] Attack tests written
- [ ] Edge cases tested
- [ ] Findings documented
