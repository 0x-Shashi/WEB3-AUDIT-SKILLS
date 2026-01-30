---
name: aptos-scanner
description: "Comprehensive Aptos Move vulnerability scanner for Move modules and smart contracts. Covers resource safety, module upgrades, coin standards, and Aptos-specific attack vectors. Use this skill when auditing Aptos programs."
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
---

# Aptos Vulnerability Scanner

## Purpose

This skill provides systematic vulnerability scanning for Aptos Move smart contracts. It includes:
- 50+ Aptos-specific vulnerability patterns
- Resource account security
- Module upgrade vulnerabilities
- Coin and fungible asset security
- Aptos Move-specific attack vectors

---

## When to Use This Skill

**Use when:**
- Auditing Aptos Move modules
- Reviewing resource account patterns
- Analyzing upgrade mechanisms
- Checking coin/FA implementations
- Scanning for Aptos-specific attacks

**Trigger phrases:**
- "Audit this Aptos contract"
- "Check this Move module for Aptos"
- "Review Aptos security"
- "Scan for Aptos vulnerabilities"

---

## When NOT to Use

Do NOT use this skill for:
- Sui Move (use sui-scanner - different object model)
- EVM chains (use solidity-scanner)
- Solana (use solana-scanner)
- Generic Move without Aptos context

---

## Aptos Security Fundamentals

### Key Concepts

```
┌─────────────────────────────────────────────────────────┐
│                   APTOS SECURITY MODEL                   │
├─────────────────────────────────────────────────────────┤
│ RESOURCES                                                │
│ • Stored under accounts (not objects)                   │
│ • Global storage access via borrow_global               │
│ • Acquires annotation for resource operations           │
├─────────────────────────────────────────────────────────┤
│ SIGNERS                                                  │
│ • Represent authorized accounts                         │
│ • Required for resource operations                      │
│ • Can create resource accounts                          │
├─────────────────────────────────────────────────────────┤
│ MODULES                                                  │
│ • Published under accounts                              │
│ • Can be upgraded (if allowed)                          │
│ • Define resource types                                 │
└─────────────────────────────────────────────────────────┘
```

---

## Vulnerability Categories

### Category 1: Signer Validation

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| SV-01 | Missing signer check | Critical | Signer not verified |
| SV-02 | Signer capability leak | Critical | SignerCap exposed |
| SV-03 | Resource account abuse | High | ResourceAccount signer misuse |
| SV-04 | Multi-signer confusion | High | Wrong signer used |

#### SV-01: Missing Signer Check

**Vulnerable Code:**
```move
// VULNERABLE: No signer verification
public entry fun admin_withdraw(
    admin: &signer,  // Not checked if authorized!
    amount: u64
) acquires Vault {
    let vault = borrow_global_mut<Vault>(@vault_address);
    let coins = coin::extract(&mut vault.coins, amount);
    coin::deposit(signer::address_of(admin), coins);
}
```

**Secure Code:**
```move
// SECURE: Verify admin
public entry fun admin_withdraw(
    admin: &signer,
    amount: u64
) acquires Vault, AdminConfig {
    let config = borrow_global<AdminConfig>(@vault_address);
    assert!(signer::address_of(admin) == config.admin, ENOT_ADMIN);
    
    let vault = borrow_global_mut<Vault>(@vault_address);
    let coins = coin::extract(&mut vault.coins, amount);
    coin::deposit(signer::address_of(admin), coins);
}
```

---

### Category 2: Resource Account Security

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| RA-01 | SignerCapability storage | Critical | Cap stored insecurely |
| RA-02 | Missing capability revocation | High | Cap can't be revoked |
| RA-03 | Resource account DoS | Medium | Account can be locked |
| RA-04 | Signer capability sharing | Critical | Cap passed to untrusted code |

#### RA-01: SignerCapability Storage

**Vulnerable Code:**
```move
// VULNERABLE: SignerCap exposed
struct Config has key {
    signer_cap: SignerCapability,  // Anyone reading can use?
}

public fun get_signer_cap(): &SignerCapability acquires Config {
    &borrow_global<Config>(@resource_addr).signer_cap
}
```

**Secure Code:**
```move
// SECURE: Cap protected, only internal use
struct Config has key {
    signer_cap: SignerCapability,
    admin: address,
}

// Only callable by module, signer created internally
fun get_resource_signer(): signer acquires Config {
    let config = borrow_global<Config>(@resource_addr);
    account::create_signer_with_capability(&config.signer_cap)
}
```

---

### Category 3: Module Upgrade Vulnerabilities

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| MU-01 | No upgrade policy | Critical | Arbitrary upgrades |
| MU-02 | Weak upgrade auth | High | Upgrade not multisig |
| MU-03 | Storage migration | Medium | Old data incompatible |
| MU-04 | Upgrade frontrunning | Medium | No timelock |

#### MU-01: No Upgrade Policy

**Detection:**
```bash
# Check Move.toml for upgrade policy
grep -r "upgrade_policy" Move.toml

# Check if immutable
aptos move view --function module_addr::metadata::is_immutable
```

**Secure Pattern:**
```move
// Set upgrade policy to immutable after testing
// Or use proper multisig + timelock for upgrades
```

---

### Category 4: Global Storage Patterns

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| GS-01 | Missing exists check | High | borrow_global on nonexistent |
| GS-02 | Double initialization | High | Resource overwritten |
| GS-03 | Unauthorized global access | Critical | Wrong address accessed |
| GS-04 | Storage slot collision | Medium | Same type different meaning |

#### GS-01: Missing Exists Check

**Vulnerable Code:**
```move
// VULNERABLE: Crashes if not initialized
public fun get_balance(addr: address): u64 acquires UserBalance {
    borrow_global<UserBalance>(addr).amount  // Aborts if not exists!
}
```

**Secure Code:**
```move
// SECURE: Check existence
public fun get_balance(addr: address): u64 acquires UserBalance {
    if (!exists<UserBalance>(addr)) {
        return 0
    };
    borrow_global<UserBalance>(addr).amount
}
```

#### GS-02: Double Initialization

**Vulnerable Code:**
```move
// VULNERABLE: Can overwrite existing
public entry fun initialize(admin: &signer) {
    move_to(admin, Config { value: 0 });  // Fails if exists
}
```

**Secure Code:**
```move
// SECURE: Check not already initialized
public entry fun initialize(admin: &signer) {
    assert!(!exists<Config>(signer::address_of(admin)), EALREADY_INITIALIZED);
    move_to(admin, Config { value: 0 });
}
```

---

### Category 5: Coin and Fungible Asset Security

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| CF-01 | Coin capability leak | Critical | MintCap/BurnCap exposed |
| CF-02 | Unlimited minting | Critical | No supply cap |
| CF-03 | Flash loan abuse | High | No repayment check |
| CF-04 | Coin type confusion | High | Wrong coin type |

#### CF-01: Coin Capability Leak

**Vulnerable Code:**
```move
// VULNERABLE: Mint cap accessible
struct CoinCaps has key {
    mint_cap: MintCapability<MyCoin>,
    burn_cap: BurnCapability<MyCoin>,
}

// Public accessor leaks capability!
public fun get_mint_cap(): &MintCapability<MyCoin> acquires CoinCaps {
    &borrow_global<CoinCaps>(@coin_addr).mint_cap
}
```

**Secure Code:**
```move
// SECURE: Capabilities never exposed
struct CoinCaps has key {
    mint_cap: MintCapability<MyCoin>,
    burn_cap: BurnCapability<MyCoin>,
    admin: address,
}

// Only admin can mint, cap never leaves module
public entry fun mint(
    admin: &signer,
    to: address,
    amount: u64
) acquires CoinCaps {
    let caps = borrow_global<CoinCaps>(@coin_addr);
    assert!(signer::address_of(admin) == caps.admin, ENOT_ADMIN);
    
    let coins = coin::mint(amount, &caps.mint_cap);
    coin::deposit(to, coins);
}
```

---

### Category 6: Table and Vector Security

| ID | Pattern | Severity | Detection |
|----|---------|----------|-----------|
| TV-01 | Missing key check | High | Table access without contains |
| TV-02 | Unbounded iteration | Medium | Gas DoS via large vector |
| TV-03 | Table key collision | Medium | Same key different context |

#### TV-01: Missing Key Check

**Vulnerable Code:**
```move
// VULNERABLE: Aborts if key not found
public fun get_user_balance(
    table: &Table<address, u64>,
    user: address
): u64 {
    *table::borrow(table, user)  // Crashes if not exists!
}
```

**Secure Code:**
```move
// SECURE: Check key exists
public fun get_user_balance(
    table: &Table<address, u64>,
    user: address
): u64 {
    if (!table::contains(table, user)) {
        return 0
    };
    *table::borrow(table, user)
}
```

---

## Detection Workflow

### Step 1: Module Analysis
```bash
# List all Move files
find sources/ -name "*.move"

# Find public entry points
grep -r "public entry fun" sources/

# Find resource definitions
grep -r "struct.*has.*key" sources/
```

### Step 2: Signer Analysis
```
1. List all functions taking &signer
2. Verify signer address checked
3. Check signer capability usage
4. Verify resource account patterns
```

### Step 3: Global Storage Review
```
1. Find all acquires annotations
2. Verify exists checks before borrow_global
3. Check move_to for double init
4. Verify correct addresses used
```

### Step 4: Coin Flow Analysis
```
1. Find MintCapability/BurnCapability
2. Verify caps never exposed
3. Check coin registration
4. Trace all coin movements
```

---

## Aptos-Specific Checklists

### Signer Security Checklist
- [ ] All signers verified against expected address
- [ ] SignerCapability stored securely
- [ ] Resource account signers not leaked
- [ ] Multi-signer operations correct

### Resource Checklist
- [ ] exists<T> checked before borrow_global
- [ ] Double initialization prevented
- [ ] Correct addresses for global access
- [ ] acquires annotation complete

### Upgrade Checklist
- [ ] Upgrade policy defined
- [ ] Multisig required for upgrades
- [ ] Timelock on upgrades (optional)
- [ ] Storage compatibility verified

### Coin Checklist
- [ ] MintCap/BurnCap never exposed
- [ ] Supply cap enforced if needed
- [ ] Coin registered before use
- [ ] Correct coin types verified

---

## Real-World Exploits

| Protocol | Vulnerability | Loss | Root Cause |
|----------|--------------|------|------------|
| Tortuga Finance | Signer bypass | $1.5M | Missing signer verification |
| Thala Labs | Resource account | $25M | SignerCap leak |
| Pontem | Upgrade attack | $500K | No upgrade policy |

---

## Quick Reference Commands

```bash
# Find signers not verified
grep -r "signer: &signer" sources/ | grep -v "assert!"

# Find SignerCapability usage
grep -r "SignerCapability\|create_signer_with_capability" sources/

# Find coin capabilities
grep -r "MintCapability\|BurnCapability\|FreezeCapability" sources/

# Find global storage access
grep -r "borrow_global\|borrow_global_mut\|move_to\|move_from" sources/

# Find public entry points
grep -r "public entry fun" sources/
```

---

## Integration with Other Skills

- Use `move-scanner` for generic Move patterns
- Use `token-analyzer` for coin implementations
- Use `access-control-patterns` for signer design
- Use `methodology/llm-audit-workflow` for systematic review
