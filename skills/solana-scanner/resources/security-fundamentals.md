---
id: SOLANA-SECURITY-FUNDAMENTALS
title: Solana Security Fundamentals & Validation
category: solana-scanner
difficulty: intermediate
triggers:
  - solana security fundamentals
  - security mindset
  - input validation
  - state management
  - arithmetic safety
  - reentrancy
related_skills:
  - solana-scanner/resources/account-validation.md
  - solana-scanner/resources/native-security.md
  - solana-scanner/resources/anchor-security.md
  - solana-scanner/resources/security-checklists.md
tags:
  - solana
  - security
  - fundamentals
  - validation
last_updated: 2026-02-26
description: >-
  Comprehensive security guidance for Solana program development. Covers
  security mindset, core validation patterns, common vulnerabilities, input
  validation, state management, arithmetic safety, and reentrancy protection.
  Material sourced from tenequm's claude-plugins solana-security skill.
---

# Solana Security Fundamentals & Validation

> The only thing you control is how your program handles inputs. Everything else is adversarial.

---

## 1. Security Mindset

- Always ask: "How do I break this?"
- Assume all accounts, parameters, and instruction data are malicious
- All programs can be exploited — your job is to make it as hard as possible
- Security is not optional: a single missing check can brick the program or lose all funds

---

## 2. Core Validation Patterns

- **Signer checks**: Require signatures for privileged operations
- **Owner checks**: Validate account ownership before reading/writing
- **PDA validation**: Ensure provided PDAs match expected derivation and canonical bump
- **Initialization checks**: Prevent re-initialization or use of uninitialized accounts
- **Type checks**: Use discriminators or enums to distinguish account types
- **Writable checks**: Ensure accounts to be modified are marked writable
- **Relationship checks**: Validate relationships between accounts (e.g., has_one)
- **Uniqueness**: Ensure semantically distinct accounts are not the same key

---

## 3. Common Vulnerabilities

- Missing signer/owner checks
- PDA substitution attacks
- Type cosplay (account type confusion)
- Account reloading issues (stale data after CPI)
- Improper account closing (data not zeroed)
- Arbitrary CPI (user-controlled program IDs)
- Duplicate mutable accounts
- Non-canonical bump usage
- Missing lamports/rent checks
- Precision loss/rounding errors
- Unchecked error returns
- Stale oracle data

---

## 4. Input Validation

- Validate all instruction data (length, range, type)
- Check string lengths and allowed characters
- Validate enum values are within expected range
- Never trust client-side or test-only constraints

---

## 5. State Management Security

- Avoid race conditions: use account-level locking and atomic operations
- Always validate state transitions (e.g., enum state machines)
- Prevent state corruption by checking invariants before/after changes
- Use version fields for upgradability

---

## 6. Arithmetic Safety

- Always use `checked_*` methods for all math
- Validate all inputs before arithmetic
- Handle precision loss by multiplying before dividing
- Use `.ok_or(ErrorCode::Overflow)?` for error propagation

---

## 7. Re-entrancy Protection

- Solana provides strong protection via account locking and atomic transactions
- Residual risks: state assumptions across CPIs, stale data, and multi-tx flows
- Always reload accounts after CPIs that may modify them

---

## 8. Security Checklist (Pre-Deployment)

- [ ] All signers verified
- [ ] All owners checked
- [ ] All PDAs validated with canonical bump
- [ ] All accounts checked for initialization
- [ ] Account types validated (discriminators)
- [ ] Writable accounts verified
- [ ] All numeric/string/enum inputs validated
- [ ] All math uses `checked_*`
- [ ] State transitions validated
- [ ] No assumptions across CPI boundaries
- [ ] All errors properly propagated
- [ ] Negative/fuzz/edge-case tests written

---

## 9. Summary

Security is not a feature — it's a requirement. Validate everything, fail fast, use checked math, and always think like an attacker.

---

*Material sourced from tenequm's claude-plugins solana-security skill and adapted for the WEB3 Audit Skills project.*
