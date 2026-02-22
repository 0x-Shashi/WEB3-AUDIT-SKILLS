# Anchor Framework Security Guide

## Common Anchor Vulnerabilities

### 1. Missing Constraints
```rust
// [VULNERABLE] No constraints on account
#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub vault: Account<'info, Vault>,  // Missing: mut, has_one, seeds
    pub user: Signer<'info>,
}

// [SAFE] Full constraints
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = owner, seeds = [b"vault", owner.key().as_ref()], bump = vault.bump)]
    pub vault: Account<'info, Vault>,
    pub owner: Signer<'info>,
}
```

### 2. Arbitrary CPI
```rust
// [VULNERABLE] CPI to user-provided program
pub fn execute(ctx: Context<Execute>, data: Vec<u8>) -> Result<()> {
    let ix = Instruction { program_id: ctx.accounts.target_program.key(), .. };
    invoke(&ix, &[ctx.accounts.signer.to_account_info()])?;
    Ok(())
}

// [SAFE] Whitelist program IDs
require!(ctx.accounts.target_program.key() == KNOWN_PROGRAM_ID, ErrorCode::InvalidProgram);
```

### 3. Init-If-Needed Risks
```rust
// CAUTION: init_if_needed can be exploited
#[account(init_if_needed, payer = user, space = 8 + Vault::LEN)]
pub vault: Account<'info, Vault>,
// Risk: Attacker can front-run initialization with their own parameters
```

### 4. Close Account Pattern
```rust
// [SAFE] Use Anchor close constraint
#[account(mut, close = receiver)]
pub account_to_close: Account<'info, Data>,
pub receiver: SystemAccount<'info>,
// Anchor zeroes data AND transfers lamports
```

## Anchor Security Checklist
- [ ] All accounts have appropriate constraints (mut, has_one, seeds)
- [ ] Signer required for privileged operations
- [ ] PDA seeds include relevant data (user, mint, etc.)
- [ ] Bump stored and reused (not recalculated)
- [ ] CPI targets validated
- [ ] Account closing uses `close` constraint
- [ ] `init_if_needed` usage justified and safe
- [ ] Custom error codes for all failure paths
