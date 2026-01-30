# Native Solana Program Audit Workflow

Systematic workflow for auditing native (non-Anchor) Solana programs in raw Rust.

---

## Phase 1: Setup (30 minutes)

### 1.1 Build Environment

```bash
# Clone and build
git clone [repo]
cd [repo]
cargo build-sbf

# Run existing tests
cargo test-sbf
```

### 1.2 Entrypoint Mapping

```rust
// Identify instruction dispatch
entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    match instruction_data[0] {
        0 => initialize(program_id, accounts, instruction_data),
        1 => deposit(program_id, accounts, instruction_data),
        2 => withdraw(program_id, accounts, instruction_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
```

### 1.3 Scope Documentation

```markdown
## Audit Scope

**Program:** [Name]
**Program ID:** [address]
**Commit:** [hash]

### Instructions
| ID | Name | Handler | Priority |
|----|------|---------|----------|
| 0 | Initialize | initialize() | High |
| 1 | Deposit | deposit() | Critical |
| 2 | Withdraw | withdraw() | Critical |

### Account Data Structures
| Type | Size | Discriminator |
|------|------|---------------|
| Pool | 89 | 0x01 |
| User | 57 | 0x02 |
```

---

## Phase 2: Instruction Handler Analysis

### 2.1 Per-Handler Template

```markdown
## Handler: [name]

### Signature
```rust
fn handler(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult
```

### Account Parsing
| Index | Name | Expected Owner | Writable | Signer |
|-------|------|----------------|----------|--------|
| 0 | payer | System |  |  |
| 1 | pool | Self |  |  |
| 2 | token | Token |  |  |

### Validation Checklist
- [ ] Account count verified
- [ ] Each account owner checked
- [ ] Signer flags verified
- [ ] Writable flags verified
- [ ] Data length validated
- [ ] Account types discriminated
```

### 2.2 Critical Validation Pattern Check

```rust
// REQUIRED: Account validation template for native programs

// 1. Account count
if accounts.len() < EXPECTED_COUNT {
    return Err(ProgramError::NotEnoughAccountKeys);
}

// 2. Parse accounts
let account_iter = &mut accounts.iter();
let payer = next_account_info(account_iter)?;
let pool = next_account_info(account_iter)?;

// 3. Signer check (CRITICAL)
if !payer.is_signer {
    return Err(ProgramError::MissingRequiredSignature);
}

// 4. Owner check (CRITICAL)
if pool.owner != program_id {
    return Err(ProgramError::IncorrectProgramId);
}

// 5. Writable check
if !pool.is_writable {
    return Err(ProgramError::InvalidAccountData);
}

// 6. Discriminator check
let data = pool.try_borrow_data()?;
if data[0] != POOL_DISCRIMINATOR {
    return Err(ProgramError::InvalidAccountData);
}
```

---

## Phase 3: Account Validation Audit

### 3.1 Validation Matrix Per Instruction

```markdown
## Instruction: withdraw

### Account Validation Matrix

| Check | Account 0 | Account 1 | Account 2 | Account 3 |
|-------|-----------|-----------|-----------|-----------|
| Name | authority | pool | user_ata | pool_ata |
| Signer? |  |  |  |  |
| Writable? |  |  |  |  |
| Owner? | Any | Program | Token | Token |
| Size? | N/A | 89 | 165 | 165 |
| Discrim? | N/A | 0x01 | N/A | N/A |

### Missing Checks Found
- [ ] Account 1: No owner check - CRITICAL
- [ ] Account 2: No mint validation - HIGH
```

### 3.2 Common Native Mistakes

```markdown
## Native Program Red Flags

### AV-01: Missing Owner Check
```rust
//  VULNERABLE
let pool = next_account_info(account_iter)?;
let data = pool.try_borrow_data()?;  // Attacker can pass ANY account

//  SECURE
if pool.owner != program_id {
    return Err(ProgramError::IncorrectProgramId);
}
```

### AV-02: Missing Signer Check
```rust
//  VULNERABLE
let authority = next_account_info(account_iter)?;
// Proceeds without checking is_signer

//  SECURE
if !authority.is_signer {
    return Err(ProgramError::MissingRequiredSignature);
}
```

### AV-06: Missing Discriminator
```rust
//  VULNERABLE - Treats any data as Pool
let pool: Pool = Pool::try_from_slice(&pool_account.data.borrow())?;

//  SECURE - Verify type first
let data = pool_account.try_borrow_data()?;
if data[0] != POOL_DISCRIMINATOR {
    return Err(ProgramError::InvalidAccountData);
}
let pool: Pool = Pool::try_from_slice(&data[1..])?;
```

### AV-07: Missing Account Relationship
```rust
//  VULNERABLE - Doesn't verify user belongs to pool
let pool = next_account_info(account_iter)?;
let user = next_account_info(account_iter)?;

//  SECURE - Verify relationship
let user_data: User = User::unpack(&user.data.borrow())?;
if user_data.pool != *pool.key {
    return Err(ProgramError::InvalidAccountData);
}
```
```

---

## Phase 4: PDA Validation

### 4.1 PDA Analysis

```markdown
## PDA: Pool

### Derivation
```rust
let (pool_pda, bump) = Pubkey::find_program_address(
    &[b"pool", mint.key.as_ref()],
    program_id
);
```

### Validation Required
```rust
// MUST verify PDA on every use
if *pool.key != pool_pda {
    return Err(ProgramError::InvalidSeeds);
}
```

### Checks
- [ ] Seeds include all unique identifiers
- [ ] Bump handled correctly (stored vs canonical)
- [ ] PDA verified against derivation
- [ ] No arbitrary bumps accepted
```

### 4.2 Bump Seed Issues

```rust
//  VULNERABLE - Accepts user-provided bump
let (_, bump) = Pubkey::create_program_address(
    &[b"pool", &[user_bump]],  // User controls bump
    program_id
)?;

//  SECURE - Use find_program_address for canonical
let (pda, bump) = Pubkey::find_program_address(
    &[b"pool"],
    program_id
);

// OR store bump on init and verify
if stored_bump != provided_bump {
    return Err(...);
}
```

---

## Phase 5: CPI Security

### 5.1 CPI Analysis Template

```markdown
## CPI: Token Transfer

### Location
File: src/processor.rs
Line: 156

### Target Program
- Expected: TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
- Verified: [Yes/No]

### Code Review
```rust
// Check if program is verified
invoke(
    &spl_token::instruction::transfer(
        token_program.key,  // Is this validated?
        source.key,
        dest.key,
        authority.key,
        &[],
        amount,
    )?,
    &[source, dest, authority, token_program],
)?;
```

### Issues
- [ ] Token program ID not verified
- [ ] Could invoke malicious program
```

### 5.2 CPI Validation Pattern

```rust
//  SECURE CPI Pattern
const SPL_TOKEN: Pubkey = spl_token::ID;

// Verify target program
if *token_program.key != SPL_TOKEN {
    return Err(ProgramError::IncorrectProgramId);
}

// Then invoke
invoke(
    &instruction,
    &[...],
)?;
```

---

## Phase 6: Arithmetic Review

### 6.1 Arithmetic Audit

```markdown
## Arithmetic Operations

| Location | Operation | Type | Safe? |
|----------|-----------|------|-------|
| deposit:45 | a + b | u64 |  unchecked |
| withdraw:78 | a - b | u64 |  checked |
| calc_fee:23 | a * b / c | u128 |  overflow |
```

### 6.2 Common Issues

```rust
//  VULNERABLE - Overflow
pool.total += amount;

//  SECURE - Checked arithmetic
pool.total = pool.total.checked_add(amount)
    .ok_or(ProgramError::ArithmeticOverflow)?;

//  VULNERABLE - Division precision loss
let fee = amount * fee_bps / 10000;

//  SECURE - Use u128 for intermediate
let fee = (amount as u128)
    .checked_mul(fee_bps as u128)
    .and_then(|v| v.checked_div(10000))
    .and_then(|v| u64::try_from(v).ok())
    .ok_or(ProgramError::ArithmeticOverflow)?;
```

---

## Phase 7: Data Serialization

### 7.1 Serialization Audit

```markdown
## Serialization Analysis

### Format Used
- [ ] Borsh
- [ ] Custom
- [ ] None (raw bytes)

### Issues to Check
- [ ] Struct padding/alignment
- [ ] Variable length fields at end only
- [ ] Size validation before deserialize
- [ ] No deserialization from untrusted source without length check
```

### 7.2 Serialization Vulnerabilities

```rust
//  VULNERABLE - No size check
let data: MyStruct = MyStruct::try_from_slice(&account.data.borrow())?;

//  SECURE - Verify size first
if account.data_len() != MY_STRUCT_SIZE {
    return Err(ProgramError::InvalidAccountData);
}
let data: MyStruct = MyStruct::try_from_slice(&account.data.borrow())?;
```

---

## Phase 8: Quick Grep Audit

```bash
# Find account iteration (verify all validated)
grep -rn "next_account_info" src/

# Find owner checks (should match account count)
grep -rn "\.owner" src/

# Find signer checks
grep -rn "is_signer" src/

# Find invoke calls
grep -rn "invoke\|invoke_signed" src/

# Find unchecked arithmetic
grep -rn "[+\-*]=" src/ | grep -v checked

# Find PDA operations
grep -rn "find_program_address\|create_program_address" src/

# Find deserialization
grep -rn "try_from_slice\|deserialize" src/
```

---

## Audit Checklist

### Account Validation
- [ ] All accounts have owner checks
- [ ] All authority accounts have signer checks
- [ ] All writable operations verify is_writable
- [ ] Account data sizes validated
- [ ] Discriminators checked for typed accounts
- [ ] Account relationships verified

### PDA Security
- [ ] All PDAs derived with consistent seeds
- [ ] PDAs verified on every use
- [ ] No user-controlled bumps without validation
- [ ] Canonical bumps used or bumps stored

### CPI Security
- [ ] All CPI targets verified
- [ ] Correct program IDs hardcoded
- [ ] Signer seeds properly constructed
- [ ] Return values handled

### Arithmetic
- [ ] All additions use checked_add
- [ ] All subtractions use checked_sub
- [ ] Multiplication uses u128 intermediate
- [ ] Division handles remainders appropriately
- [ ] No unchecked arithmetic blocks

### Serialization
- [ ] Size validated before deserialization
- [ ] Structs properly aligned
- [ ] Variable fields at end only

### Logic
- [ ] Initialization cannot be replayed
- [ ] Close instructions drain lamports properly
- [ ] State transitions are valid
- [ ] Edge cases handled (zero, max values)

