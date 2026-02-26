---
id: SOLANA-NATIVE-SECURITY
title: Native Rust Security Patterns for Solana
category: solana-scanner
difficulty: advanced
triggers:
  - solana native security
  - manual account validation
  - PDA security
  - CPI security
  - serialization security
  - rent exemption
related_skills:
  - solana-scanner/resources/account-validation.md
  - solana-scanner/resources/solana-patterns.md
  - solana-scanner/resources/pinocchio-security.md
  - solana-scanner/resources/security-fundamentals.md
tags:
  - solana
  - rust
  - native
  - security
last_updated: 2026-02-26
description: >-
  Security vulnerabilities and best practices for Solana programs built with
  native Rust (no Anchor). Covers manual account validation, PDA derivation,
  CPI safety, serialization, rent, error handling, and Token-2022.
  Material sourced from tenequm's claude-plugins solana-security skill.
---

# Native Rust Security Patterns for Solana

> Native Rust Solana programs require explicit, manual validation of every security property. Anchor's safety rails do NOT apply.

---

## 1. Manual Account Validation

- **Signer check**: `if !account.is_signer { return Err(ProgramError::MissingRequiredSignature); }`
- **Owner check**: `if account.owner != program_id { return Err(ProgramError::IncorrectProgramId); }`
- **Writable check**: `if !account.is_writable { return Err(ProgramError::InvalidAccountData); }`
- **Initialization check**: Use a flag or discriminator to ensure account is initialized before use
- **Type check**: Use discriminators (first 8 bytes) to distinguish account types
- **Relationship check**: Compare fields (e.g., `vault.authority == authority.key()`)
- **Uniqueness**: Ensure semantically distinct accounts are not the same key

## 2. Account Discriminator Patterns

- Add an 8-byte discriminator to every account struct
- Validate discriminator before deserializing
- Use string-based or numeric discriminators for clarity

## 3. PDA Security in Native Rust

- Always use `Pubkey::find_program_address` to derive canonical bump
- Store bump in account data at initialization
- Validate PDA matches expected seeds and bump
- Never accept user-provided bump without validation

## 4. Manual CPI Security

- Validate target program ID before CPI
- Build `AccountMeta` arrays with correct signer/writable flags
- Use `invoke_signed` for PDA signing, with exact seeds
- Check CPI return values and validate post-CPI state
- Never allow arbitrary user-controlled CPI targets

## 5. Manual Serialization Security

- Use Borsh or similar for serialization
- Validate data length before deserialization
- Enforce maximum vector lengths to prevent OOM
- Use exact size checks to prevent truncation attacks

## 6. Rent and Space Management

- Use `Rent::get()` to calculate minimum balance
- Validate account is rent-exempt after creation
- Enforce reasonable min/max account sizes
- Align account sizes to 8 bytes for rent calculation

## 7. Error Handling in Native Rust

- Use custom error enums implementing `From<...> for ProgramError`
- Never use `unwrap()` or `expect()` — always propagate errors
- Provide meaningful error messages for all failure paths

## 8. Token Program Integration

- Validate token program ID (`spl_token::id()` or `spl_token_2022::id()`)
- Validate token account owner and mint
- For Token-2022, check for extensions and handle accordingly
- Use `StateWithExtensions` to parse extension data

## 9. Low-Level Security Patterns

- Reload account data after external calls if cached
- Validate all sysvars loaded from official accounts
- Use account iteration patterns that consume all expected accounts
- Version state structs for upgradability

## 10. Best Practices

- Create reusable validation functions for common checks
- Use Rust's type system to enforce invariants at compile time
- Document all invariants and security assumptions in code comments

---

## Summary

Native Rust Solana programs are powerful but dangerous. Every check is your responsibility. Use this guide as a checklist for every instruction and account.

---

*Material sourced from tenequm's claude-plugins solana-security skill and adapted for the WEB3 Audit Skills project.*
