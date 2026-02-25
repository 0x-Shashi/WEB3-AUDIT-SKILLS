---
id: admin-threat-model
title: "Admin / Privileged-Key Threat Model Template"
category: templates
tier: methodology
audience: [auditors, protocol-teams]
origin: methodology-extraction
version: 1.0.0
---

# Admin / Privileged-Key Threat Model Template

## Purpose

Every on-chain protocol with a privileged key (admin, owner, guardian, multisig,
timelock) needs a **dual-column threat model**: what the key *can* do by design
(governance powers), and what it *must never* be able to do (hard boundaries
enforced in code). Auditors use this to verify that the "CANNOT" column is
actually enforced, and users read it to understand residual trust assumptions.

This template captures the methodology used by world-class Solana programs where
every hard boundary has a named test proving it holds.

---

## How to Use This Template

1. **Identify every privileged role** in the protocol (admin, owner, guardian,
   keeper, oracle authority, fee manager, etc.).
2. **For each role**, fill in both tables below.
3. **Every "CANNOT" row MUST have a test name** — if you cannot name a test,
   the boundary is not enforced.
4. **Review lifecycle transitions** — some powers are only available in certain
   states (e.g., post-resolution).
5. **Document the burn path** — can the privileged key be permanently
   renounced? What happens after?

---

## Section 1: Role Identification

### Protocol: `[PROTOCOL_NAME]`
### Chain: `[CHAIN]`

| Role | Key Type | Rotation? | Burnable? | Timelock? |
|------|----------|-----------|-----------|-----------|
| Admin | Single EOA / Multisig | Yes / No | Yes / No | N/A / Duration |
| Oracle Authority | Single EOA / Multisig | Yes / No | Yes / No | N/A / Duration |
| Keeper | Permissionless / Restricted | N/A | N/A | N/A |
| `[ADD ROLES]` | | | | |

### Burn Semantics

> **Describe exactly what happens when the admin key is burned.**
>
> Example: "Setting admin to `[0;32]` is irreversible and disables all admin
> operations forever. Covered by `test_burned_admin_cannot_act`."

---

## Section 2: Powers Table (What a Malicious Key CAN Do)

> These are governance powers, not bugs. List every action the privileged key
> is trusted to perform, along with the worst-case impact if the key is
> compromised or adversarial.

| # | Action / Instruction | Description | Impact if Abused |
|---|---------------------|-------------|-----------------|
| 1 | `[InstructionName]` | Brief description of what it does | Worst-case scenario |
| 2 | `[InstructionName]` | | |
| 3 | `[InstructionName]` | | |
| 4 | `[InstructionName]` | | |
| 5 | `[InstructionName]` | | |
| 6 | `[InstructionName]` | | |
| 7 | `[InstructionName]` | | |
| 8 | `[InstructionName]` | | |
| 9 | `[InstructionName]` | | |
| 10 | `[InstructionName]` | | |

### Common Categories to Check

Use this checklist to ensure you haven't missed governance powers:

- [ ] **Key rotation** — can admin transfer control?
- [ ] **Parameter updates** — fees, thresholds, margins, caps
- [ ] **Oracle control** — price feeds, staleness, authority
- [ ] **Market lifecycle** — pause, resolve, wind-down, close
- [ ] **Fund movement** — insurance withdrawal, treasury access
- [ ] **Emergency actions** — panic mode, force-close, circuit breakers
- [ ] **Account management** — force-close user accounts, freeze
- [ ] **Upgrade authority** — program upgrades, proxy implementation changes
- [ ] **Fee extraction** — fee recipient changes, fee rate changes
- [ ] **Access control changes** — whitelist/blacklist modifications

---

## Section 3: Hard Boundaries Table (What a Malicious Key CANNOT Do)

> These are intended security boundaries enforced in code. **Every row MUST
> have at least one test name.** If no test exists, the boundary is not proven
> and should be flagged as a finding.

| # | Boundary Statement | Error Code | Test(s) Proving It |
|---|-------------------|------------|-------------------|
| 1 | Cannot execute admin ops without matching signer | `[ErrorName]` | `test_attack_admin_op_as_user`, `test_...` |
| 2 | Cannot use old key after rotation | `[ErrorName]` | `test_attack_old_admin_blocked_after_transfer` |
| 3 | Cannot act after key is burned | `[ErrorName]` | `test_attack_burned_admin_cannot_act` |
| 4 | Cannot push oracle prices without oracle authority | `[ErrorName]` | `test_attack_oracle_authority_wrong_signer` |
| 5 | Cannot perform action X without prerequisite Y | `[ErrorName]` | `test_attack_...` |
| 6 | Cannot mutate config after state transition Z | `[ErrorName]` | `test_attack_..._after_resolution_rejected` |
| 7 | Cannot force-close active user positions | `[ErrorName]` | `test_..._requires_zero_position` |
| 8 | Cannot redirect user funds to arbitrary accounts | `[ErrorName]` | `test_..._verifies_destination_owner` |
| 9 | Cannot drain protocol while obligations exist | `[ErrorName]` | `test_attack_..._with_open_positions` |
| 10 | Cannot bypass safety on account closure | `[ErrorName]` | `test_attack_close_with_remaining_...` |

### Common Boundary Categories to Check

- [ ] **Signer enforcement** — every admin path requires `admin == signer`
- [ ] **Post-rotation lockout** — old key is dead after rotation
- [ ] **Burn permanence** — burned key can never act again
- [ ] **State-gated operations** — some ops require specific market state
- [ ] **Fund safety** — cannot extract funds while obligations exist
- [ ] **User fund isolation** — admin cannot redirect user withdrawals
- [ ] **Lifecycle ordering** — resolution before withdrawal, etc.
- [ ] **Config immutability after transition** — no parameter changes after
      market enters terminal state
- [ ] **Account closure safety** — cannot close while state/funds remain
- [ ] **Feature flag dangers** — compile-time flags that weaken checks

---

## Section 4: State-Dependent Powers Matrix

> Some powers are only available in specific protocol states. Map each action
> to when it's allowed.

| Action | Active | Paused | Resolved | Closed |
|--------|--------|--------|----------|--------|
| `UpdateConfig` | Yes | Yes | **No** | No |
| `SetFees` | Yes | Yes | **No** | No |
| `ResolveMarket` | Yes | No | No | No |
| `WithdrawInsurance` | No | No | Yes (after all closed) | No |
| `ForceCloseAccount` | No | No | Yes (zero position) | No |
| `CloseMarket` | No | No | No | Yes (empty) |

---

## Section 5: Critical Caveats

> Document any compile-time flags, feature gates, or deployment configurations
> that weaken security boundaries.

| Caveat | Risk | Mitigation |
|--------|------|------------|
| `[feature_flag_name]` — skips safety check X | Describe the weakened boundary | "Do not enable in production builds" |
| Timelock bypass for emergency | Admin can act instantly via X | Monitoring + multisig required |
| | | |

---

## Section 6: Monitoring Checklist

> What should operators and users monitor to detect admin key abuse?

- [ ] Admin key rotation events — alert on any `UpdateAdmin` / `transferOwnership`
- [ ] Parameter change events — alert on fee/threshold/oracle changes
- [ ] Emergency action events — alert on pause, resolve, force-close
- [ ] Oracle authority changes — alert on `SetOracleAuthority`
- [ ] Unusual fund movements — insurance withdrawal, treasury changes
- [ ] State transitions — market resolution, account force-closes

---

## Section 7: Audit Verification Procedure

### For auditors reviewing a protocol against this model:

1. **Enumerate all privileged roles** from the codebase (search for
   `admin`, `owner`, `authority`, `guardian`, `operator`, `keeper`).
2. **Fill the Powers table** by reading every instruction that checks for a
   privileged signer.
3. **Fill the Boundaries table** by reading every test that contains
   `attack`, `unauthorized`, `rejected`, `blocked`, `cannot` in its name.
4. **Cross-reference**: for every power in the CAN table, verify there is
   a boundary preventing its worst-case abuse in the CANNOT table.
5. **Check state transitions**: verify that state-gated operations actually
   enforce the state requirement.
6. **Check the burn path**: if admin can be burned, verify permanence.
7. **Check feature flags**: search for `#[cfg(feature = ...)]` or
   conditional compilation that weakens checks.
8. **Run the test suite**: confirm all boundary tests pass.
9. **Flag gaps**: any boundary without a test is an **unverified claim**.

### Test Naming Convention

Good test names make the threat model self-documenting:

```
test_attack_{action}_{as_role}          — role-based auth bypass attempt
test_attack_{action}_after_{state}      — state-gated bypass attempt
test_attack_{action}_with_{condition}   — condition-gated bypass attempt
test_{role}_{action}_requires_{prereq}  — prerequisite enforcement
```

---

## Filled Example (DeFi Perpetuals)

> This shows the pattern applied to a perpetuals protocol with admin + oracle
> authority roles.

### Powers (CAN do)

| # | Action | Description | Impact |
|---|--------|-------------|--------|
| 1 | `UpdateAdmin` | Rotate admin key or burn to zero | Governance capture or permanent lockout |
| 2 | `SetRiskThreshold` | Force restrictive gating behavior | Users cannot open/increase positions |
| 3 | `UpdateConfig` | Change funding/threshold policy | Economics become unfavorable |
| 4 | `SetMaintenanceFee` | Increase maintenance fee | Faster capital decay |
| 5 | `SetOracleAuthority` | Choose who can push authority price | Price input censorship |
| 6 | `ResolveMarket` | Transition to wind-down mode | Trading halted, market enters resolution |
| 7 | `WithdrawInsurance` | Extract insurance buffer (post-resolution) | No insurance backstop remains |
| 8 | `ForceCloseAccount` | Force-close abandoned accounts (post-resolution) | Users forcibly settled |
| 9 | `KeeperCrank(panic)` | Admin-only panic crank | Emergency settlement triggered |
| 10 | `CloseSlab` | Decommission market when empty | Market permanently closed |

### Boundaries (CANNOT do)

| # | Boundary | Error | Tests |
|---|----------|-------|-------|
| 1 | Cannot run admin ops without signer | `Unauthorized` | `test_attack_admin_op_as_user` |
| 2 | Cannot use old key after rotation | `Unauthorized` | `test_attack_old_admin_blocked_after_transfer` |
| 3 | Cannot act after burn | `Unauthorized` | `test_attack_burned_admin_cannot_act` |
| 4 | Cannot push oracle without authority | `Unauthorized` | `test_attack_oracle_authority_wrong_signer` |
| 5 | Cannot resolve without oracle price | `MissingPrice` | `test_attack_resolve_without_oracle_price` |
| 6 | Cannot withdraw insurance before resolution | `InvalidState` | `test_attack_withdraw_insurance_before_resolution` |
| 7 | Cannot mutate config after resolution | `InvalidState` | `test_attack_set_*_after_resolution_rejected` (×4) |
| 8 | Cannot force-close active positions | `InvalidState` | `test_force_close_requires_zero_position` |
| 9 | Cannot redirect close payouts | `OwnerMismatch` | ATA owner verification in close paths |
| 10 | Cannot close slab with remaining funds | `NonEmpty` | `test_attack_close_slab_with_*` (×3) |

---

## Appendix: Why Both Columns Matter

**CAN without CANNOT** = users don't know what Admin is trusted to do, and
auditors don't know what to verify.

**CANNOT without CAN** = the threat model is incomplete; unlisted powers are
implicitly trusted but undocumented.

**CANNOT without test name** = the boundary is a claim, not a guarantee.
The test-name requirement forces teams to prove their boundaries hold.
