---
id: SCANNER-SOLANA
title: Solana Program Security Scanner
category: chain-scanner
chains: [solana]
languages: [rust]
frameworks: [anchor, native]
last_updated: 2025-01-31
---

# Solana Scanner Skill

## Purpose

Analyze Solana programs (Rust/Anchor) for security vulnerabilities specific to the Solana runtime model. Solana's account-based execution model, where programs are stateless and all state is passed via accounts, creates a fundamentally different attack surface from EVM chains.

## Solana Security Model

| Property | Solana | EVM |
|----------|--------|-----|
| Execution model | Programs receive accounts as input | Contracts own their storage |
| State ownership | Account owner (program ID) controls data | Contract controls its own storage |
| Caller identity | Signer flag on accounts | `msg.sender` |
| Cross-program calls | CPI — accounts passed through | Internal calls share storage |
| Math safety | Overflow wraps in release mode | Solidity 0.8+ reverts on overflow |
| Account validation | Manual (native) or declarative (Anchor) | Automatic via `msg.sender` |
| Upgrades | Program authority can upgrade any time | Proxy patterns required |
| Rent | Accounts must maintain minimum SOL balance | No rent (storage is permanent) |

## Detection Capabilities

### Critical — Direct Fund Loss

| Vulnerability | Description | Detection Signal |
|---------------|-------------|-----------------|
| **Missing signer check** | Privileged instruction lacks signer validation | `AccountInfo` without `is_signer` check |
| **Missing owner check** | Program accepts accounts owned by other programs | No `owner == program_id` validation |
| **Arbitrary CPI** | Cross-program invocation to user-controlled program ID | `invoke()` with unchecked `program_id` |
| **PDA seed manipulation** | PDA derived with controllable seeds | Seeds include user-controlled data without validation |
| **Account data overwrite** | Writing data to wrong account | Missing discriminator / account type check |

### High — Significant Impact

| Vulnerability | Description | Detection Signal |
|---------------|-------------|-----------------|
| **Integer overflow (release)** | Wrapping arithmetic in release builds | Math ops without `checked_*` or Anchor `require!` |
| **Account closing revival** | Closed account can be revived in same tx | Close without zeroing data + relying on zero lamports |
| **Duplicate account injection** | Same account passed for two different parameters | No uniqueness check between accounts |
| **Type confusion** | Account deserialized as wrong type | Missing discriminator validation |
| **CPI privilege escalation** | CPI inherits signer privileges incorrectly | `invoke_signed()` with wrong seeds |

### Medium — Conditional Impact

| Vulnerability | Description | Detection Signal |
|---------------|-------------|-----------------|
| **PDA bump seed guessing** | Not storing/reusing canonical bump | `find_program_address` in instruction logic |
| **Missing rent exemption** | Account may be garbage collected | No rent-exempt check after creation |
| **Unchecked account size** | Account realloc without bounds | `realloc()` without size validation |
| **Clock dependency** | Using `Clock::get()` for security-sensitive logic | Validator can influence timestamp slightly |
| **Token account validation** | SPL Token account not validated for mint/owner | Missing `token::mint` or `token::authority` check |

## Key Audit Patterns

### Account Validation Matrix

Every instruction must validate EVERY account it accesses. Use this matrix:

| Check | Native Solana | Anchor |
|-------|--------------|--------|
| Is signer? | `account.is_signer` | `Signer<'info>` |
| Is writable? | `account.is_writable` | `#[account(mut)]` |
| Correct owner? | `account.owner == &program_id` | `Account<'info, T>` (automatic) |
| Correct PDA? | `Pubkey::find_program_address()` | `#[account(seeds = [...], bump)]` |
| Correct data type? | Check discriminator manually | `Account<'info, T>` (automatic) |
| Belongs to user? | Manual field comparison | `#[account(has_one = owner)]` |
| Not closed? | Check lamports > 0 and data | `Account<'info, T>` (checks discriminator) |
| Unique? | Compare pubkeys between params | Manual (Anchor doesn't auto-check) |

### Solana-Specific Attack Vectors

1. **Account Confusion Attack**: Passing a token account where a mint account is expected (or vice versa)
2. **Reinitialization Attack**: Calling `initialize` on already-initialized account
3. **Closing Account Revival**: Closing an account (zero lamports) but data remains readable in same tx
4. **CPI Re-signer Attack**: Exploiting that CPI can sign with PDA seeds the caller controls
5. **Remaining Accounts Abuse**: Exploiting unchecked accounts in `ctx.remaining_accounts`
6. **Flashback Attack**: Solana transactions can include multiple instructions — attacker can create and exploit account state in same tx

## Workflows

| Workflow | Description |
|----------|-------------|
| [Anchor Audit](workflows/anchor-audit.md) | Audit workflow for Anchor framework programs — constraint validation, CPI safety, PDA verification |
| [Native Audit](workflows/native-audit.md) | Audit workflow for native Solana programs — manual account deserialization, raw instruction processing |

## Resources

| Resource | Description |
|----------|-------------|
| [Account Validation](resources/account-validation.md) | Complete guide to account validation checks: signer, owner, PDA, type, uniqueness |
| [Anchor Security](resources/anchor-security.md) | Anchor-specific security patterns: constraints, CPI, init_if_needed, close |
| [Solana Patterns](resources/solana-patterns.md) | Common vulnerability patterns with code examples and fixes |

## Notable Solana Security Incidents

| Incident | Date | Root Cause | Loss |
|----------|------|-----------|------|
| Wormhole bridge | Feb 2022 | Missing signer verification on `complete_wrapped` | $326M |
| Cashio stablecoin | Mar 2022 | Missing `crate_collateral_tokens.mint` validation | $52M |
| Mango Markets | Oct 2022 | Oracle price manipulation + account borrowing | $116M |
| Crema Finance | Jul 2022 | Fake tick account injection in CPI | $8.8M |
| Slope wallet | Aug 2022 | Private key logging in centralized server | $4.1M |
| Solend | Various | Multiple oracle and liquidation issues | Various |

## Ecosystem Context

| Metric | Value |
|--------|-------|
| Smart contract language | Rust |
| Primary framework | Anchor (>90% of new projects) |
| Block time | ~400ms |
| Transaction model | Multiple instructions per transaction |
| Account size limit | 10MB |
| Compute budget | 200,000 compute units per instruction (adjustable to 1.4M) |
| Token standard | SPL Token / Token-2022 |
| NFT standard | Metaplex Token Metadata |

## Integration with Other Skills

| Skill | Connection |
|-------|-----------|
| `patterns/` | Cross-reference Solana-specific patterns with Solodit database (limited but growing) |
| `exploit-forensics/` | Wormhole, Cashio, Mango exploits provide forensic case studies |
| `chain-guides/solana.md` | Chain-level context for Solana validator behavior, consensus, fees |
| `attack-trees/` | Solana-specific attack trees (account confusion, CPI escalation) |
