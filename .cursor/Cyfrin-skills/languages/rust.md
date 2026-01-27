# Rust Smart Contract Security

## Overview

Rust is used for smart contracts on Solana, Near, Cosmos, and other non-EVM chains. Its memory safety features prevent many traditional bugs but introduce unique security considerations.

**Maturity:** High  
**Ecosystem:** Solana, Near, Cosmos (CosmWasm), Polkadot  
**Key Tools:** cargo-audit, clippy, cargo-fuzz, Anchor (Solana)

## Query Rust Findings

### All Rust HIGH Severity

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 50,
    "filters": {
      "languages": [{"value": "Rust"}],
      "impact": ["HIGH"],
      "qualityScore": 4,
      "sortField": "Quality"
    }
  }'
```

## Rust-Specific Vulnerabilities

### 1. Account Confusion (Solana)
The most common Solana vulnerability.

```rust
// VULNERABLE - No account validation
pub fn process_instruction(
    accounts: &[AccountInfo],
) -> ProgramResult {
    let account = &accounts[0];
    // Uses account without verifying it's the expected type
}

// SECURE - Validate accounts
pub fn process_instruction(
    accounts: &[AccountInfo],
) -> ProgramResult {
    let account = &accounts[0];
    // Verify account is expected program/owner
    if account.owner != &expected_program_id {
        return Err(ProgramError::IncorrectProgramId);
    }
}
```

### 2. Missing Signer Checks (Solana)
```rust
// VULNERABLE
pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
    // Doesn't verify authority signed
    transfer(...)
}

// SECURE (Anchor)
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(signer)]  // Enforces signature
    pub authority: Signer<'info>,
}
```

### 3. Integer Overflow
Rust doesn't check by default in release mode.

```rust
// VULNERABLE - Can overflow in release
let result = a + b;

// SECURE - Use checked arithmetic
let result = a.checked_add(b).ok_or(ErrorCode::Overflow)?;
```

### 4. Arbitrary CPI (Solana)
Cross-program invocation to wrong program.

```rust
// VULNERABLE
invoke(&instruction, &accounts)?;  // Arbitrary program

// SECURE - Verify program ID
if instruction.program_id != expected_program {
    return Err(ProgramError::IncorrectProgramId);
}
invoke(&instruction, &accounts)?;
```

### 5. PDA Seed Collisions (Solana)
```rust
// VULNERABLE - Predictable seeds
let (pda, _) = Pubkey::find_program_address(
    &[b"user", user.key().as_ref()],
    program_id
);

// Consider adding discriminators for different account types
```

## Solana-Specific Considerations

### Account Model
- Accounts are passed explicitly
- Data is serialized/deserialized
- Rent must be considered

### Common Solana Checks
```rust
// Anchor provides these automatically with constraints
#[account(
    mut,                            // Mutable
    seeds = [b"vault", user.key().as_ref()],  // PDA
    bump,                           // Bump seed
    constraint = vault.owner == *user.key    // Custom constraint
)]
pub vault: Account<'info, Vault>,
```

## Near-Specific Considerations

```rust
// Near uses promises for cross-contract calls
#[near_bindgen]
impl Contract {
    pub fn cross_call(&self) -> Promise {
        // Must handle callback results
        ext_contract::method(
            arg,
            env::current_account_id(),
            0,
            GAS,
        ).then(ext_self::callback(
            env::current_account_id(),
            0,
            GAS,
        ))
    }
}
```

## CosmWasm-Specific Considerations

```rust
// CosmWasm entry points
#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    // info.sender is authenticated caller
    // deps provides storage access
}
```

## Rust Security Checklist

### General Rust
- [ ] Using checked arithmetic
- [ ] Proper error handling (no unwrap in production)
- [ ] Cargo audit for dependencies
- [ ] No unsafe blocks (or thoroughly reviewed)

### Solana-Specific
- [ ] All accounts validated (owner, signer, etc.)
- [ ] PDA derivation verified
- [ ] Signer checks present
- [ ] CPI targets verified
- [ ] Rent exemption handled
- [ ] Account data properly deserialized

### Near-Specific
- [ ] Promise callbacks handled
- [ ] Gas attached properly
- [ ] Cross-contract return values validated

## Query Solana Findings

```bash
curl -X POST https://solodit.cyfrin.io/api/v1/solodit/findings \
  -H "Content-Type: application/json" \
  -H "X-Cyfrin-API-Key: $CYFRIN_API_KEY" \
  -d '{
    "page": 1,
    "pageSize": 25,
    "filters": {
      "keywords": "Solana account signer",
      "impact": ["HIGH"]
    }
  }'
```

## Cross-Reference

- For integer overflow → See [../vulnerability-tags/integer-overflow.md](../vulnerability-tags/integer-overflow.md)
- For access control → See [../vulnerability-tags/access-control.md](../vulnerability-tags/access-control.md)
