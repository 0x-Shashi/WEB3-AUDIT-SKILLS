---
id: PAT-GAMEFI-SECURITY
title: GameFi Security Audit Patterns
category: patterns
severity: critical
chains: [solana, ethereum, all]
languages: [rust, solidity, typescript, csharp]
tags:
  - gamefi
  - gaming
  - token-economics
  - anti-inflation
  - payment-ux
  - client-trust
  - on-chain-off-chain
  - reward-systems
  - in-game-economy
  - nft-assets
  - hardware-wallet
last_updated: 2026-02-27
description: >-
  Use when auditing GameFi protocols, blockchain games, in-game economies,
  play-to-earn systems, or any protocol mixing game logic with on-chain
  value transfer — covers payment UX security, token economics attack
  surface, anti-inflation mechanism validation, client-server trust
  boundaries, on-chain vs off-chain state security, reward system abuse,
  hardware wallet integration, and biometric authentication patterns.
  Derived from Solana gaming ecosystem patterns including Solana.Unity-SDK,
  Commerce Kit, Kora gasless infrastructure, and PlaySolana/SvalGuard
  hardware security models.
---

# GameFi Security Audit Patterns

## Overview

GameFi protocols combine the real-time demands of gaming with the
irreversibility of blockchain transactions. Unlike pure DeFi, GameFi
introduces **client-side trust problems** (game clients are inherently
adversarial), **economic balancing risks** (reward inflation can destroy
token value), and **UX-driven security shortcuts** (speed vs safety
trade-offs that open exploit windows).

**Core Risk**: Games need to feel fast and responsive while handling
irreversible value transfers. This tension creates unique attack surfaces
not found in standard DeFi.

### GameFi Protocol Architecture

```
┌─────────────────────────────────────────────────────┐
│                   GAMEFI STACK                        │
│                                                       │
│  ┌──────────┐   ┌─────────────┐   ┌──────────────┐  │
│  │ Game     │   │ Economy     │   │ Asset        │  │
│  │ Client   │──▶│ Engine      │──▶│ Management   │  │
│  │ (Unity/  │   │ (Rewards,   │   │ (NFTs,       │  │
│  │  Web/RN) │   │  Spending)  │   │  Tokens)     │  │
│  └─────┬────┘   └──────┬──────┘   └──────┬───────┘  │
│        │               │                  │          │
│  ┌─────▼────┐   ┌──────▼──────┐   ┌──────▼───────┐  │
│  │ Wallet   │   │ On-Chain    │   │ Marketplace  │  │
│  │ Adapter  │   │ Program     │   │ / Trading    │  │
│  └──────────┘   └─────────────┘   └──────────────┘  │
└─────────────────────────────────────────────────────┘
```

---

## Pattern 1: Payment UX Security Checklist

### The Seven Commandments

GameFi payment flows must satisfy ALL seven security properties
simultaneously. Missing ANY ONE creates an exploitable gap.

| # | Property | Attack if Missing |
|---|----------|-------------------|
| 1 | Show clear transaction details before signing | User signs blind → wallet drain |
| 2 | Protect against replay attacks | Same purchase charged twice |
| 3 | Confirm settlement on-chain | Client shows success, funds never arrive |
| 4 | Handle partial failures gracefully | User charged but item not delivered |
| 5 | Provide clear error messages | User retries → double-spend |
| 6 | Show loading states during processing | User re-clicks → duplicate transactions |
| 7 | Implement retry logic with blockhash expiry | Stale transactions replayed later |

### What to Audit

```
FOR EACH payment flow in the game:
  1. Trace the UI → signing → broadcast → confirmation path
  2. Verify transaction preview shows: amount, recipient, fee, item
  3. Check for unique reference/memo per transaction (replay protection)
  4. Verify confirmation waits for on-chain finality, NOT callback
  5. Test: What happens if transaction lands but callback fails?
  6. Test: What happens if user closes app mid-transaction?
  7. Verify blockhash freshness check before retry
```

### Anti-Pattern: Trusting Payment Callbacks

```typescript
// ❌ VULNERABLE — trusts client-side callback
async function purchaseItem(item: Item) {
  const sig = await wallet.sendTransaction(tx);
  // Client immediately grants item without on-chain verification
  grantItem(item);  // EXPLOITABLE: tx may fail, user keeps item
}

// ✅ SECURE — confirms on-chain before granting
async function purchaseItem(item: Item) {
  const sig = await wallet.sendTransaction(tx);
  const confirmed = await connection.confirmTransaction(sig, 'confirmed');
  if (confirmed.value.err === null) {
    // Verify on-chain state matches expected transfer
    const receipt = await connection.getTransaction(sig);
    if (verifyTransferDetails(receipt, item.price, TREASURY)) {
      grantItem(item);
    }
  }
}
```

### Simulation-Before-Send Pattern

```typescript
// ✅ Simulate transaction before sending (catches errors pre-flight)
async function securePurchase(tx: Transaction) {
  // Step 1: Simulate
  const simulation = await connection.simulateTransaction(tx);
  if (simulation.value.err) {
    showError(`Transaction would fail: ${simulation.value.err}`);
    return null;
  }

  // Step 2: Send with confirmation
  const sig = await connection.sendRawTransaction(tx.serialize(), {
    skipPreflight: false,  // Double-check on RPC side
    maxRetries: 3,
  });

  // Step 3: Wait for on-chain confirmation
  const result = await connection.confirmTransaction(sig, 'confirmed');
  return result.value.err === null ? sig : null;
}
```

---

## Pattern 2: On-Chain vs Off-Chain State Security

### The State Classification Rule

**Everything that has monetary value MUST live on-chain.** Everything
transient CAN live off-chain. Misclassifying state is a Critical finding.

| State Category | Storage | Security Implication |
|---------------|---------|---------------------|
| NFT ownership | On-chain | Immutable proof of ownership |
| Token balances | On-chain | Prevents duplication/inflation |
| Achievement unlocks | On-chain | Permanent, verifiable credentials |
| Tournament results | On-chain | Tamper-proof competitive integrity |
| Rare item attributes | On-chain | Prevents attribute manipulation |
| Frame positions | Off-chain | No monetary value, transient |
| Temporary buffs | Off-chain | Session-scoped, no lasting impact |
| Player preferences | Off-chain | No economic consequence |
| Cached display data | Off-chain | Can be reconstructed |
| Session state | Off-chain | Ephemeral by design |

### What to Audit

```
FOR EACH piece of game state:
  1. Classify: Does this state have monetary value? (Yes → on-chain)
  2. Classify: Can manipulation of this state yield profit? (Yes → on-chain)
  3. Classify: Does this state affect other players' outcomes? (Yes → on-chain)
  4. Verify: Is on-chain state ONLY writable by authorized programs?
  5. Verify: Can off-chain state be used to bypass on-chain checks?
  6. Red flag: Client-side state used to determine reward amounts
  7. Red flag: Off-chain "score" submitted without server validation
```

### Anti-Pattern: Client-Authoritative Valuable State

```rust
// ❌ VULNERABLE — trusts client-reported score for rewards
pub fn claim_reward(ctx: Context<ClaimReward>, score: u64) -> Result<()> {
    // Client sends whatever score they want
    let reward = calculate_reward(score);  // Attacker sends max score
    transfer_tokens(ctx.accounts.vault, ctx.accounts.player, reward)?;
    Ok(())
}

// ✅ SECURE — server/program computes score from on-chain game state
pub fn claim_reward(ctx: Context<ClaimReward>) -> Result<()> {
    let game_state = &ctx.accounts.game_state;
    require!(game_state.authority == ctx.accounts.player.key(), Unauthorized);
    require!(!game_state.reward_claimed, AlreadyClaimed);

    // Score derived from on-chain state, not client input
    let score = compute_score_from_state(game_state)?;
    let reward = calculate_reward(score);
    transfer_tokens(ctx.accounts.vault, ctx.accounts.player, reward)?;

    game_state.reward_claimed = true;
    Ok(())
}
```

---

## Pattern 3: Anti-Inflation Mechanism Validation

### The Five Anti-Inflation Controls

GameFi token economies MUST implement inflation controls. Without them,
reward emissions destroy token value within weeks (the "death spiral").

| # | Mechanism | Purpose | Failure Mode |
|---|-----------|---------|-------------|
| 1 | Time-Gated Rewards | Daily/weekly earning caps | Bots farm 24/7, instant inflation |
| 2 | Diminishing Returns | Reduced rewards over time/play | Whales extract disproportionate value |
| 3 | Sink Mechanisms | Consumables, repair fees, entry fees | No token demand → price collapse |
| 4 | Staking Incentives | Lock tokens for boosted rewards | Insufficient lock → sell pressure |
| 5 | Burn Mechanics | Permanent supply reduction | Without burns, supply only grows |

### Token Economics Balance Equation

```
HEALTHY ECONOMY:
  Token Inflows (earning) ≈ Token Outflows (spending + burning)

EARNING SOURCES:          SPENDING SINKS:
  ├── Quest rewards         ├── Equipment repair
  ├── Battle victories      ├── Crafting fees
  ├── Achievement bonuses   ├── Marketplace listing fees
  ├── Tournament prizes     ├── Cosmetic purchases
  └── Staking yields        ├── Entry fees (tournaments)
                            ├── Consumable items
                            └── Token burns
```

### What to Audit

```
FOR EACH token emission source:
  1. Is there a per-address daily/weekly cap? (Time-Gated)
  2. Do rewards decrease with repeated actions? (Diminishing Returns)
  3. Is there a corresponding sink for this emission? (Balance)
  4. Can the emission rate be adjusted by governance? (Adaptability)
  5. What happens if 10,000 bots farm simultaneously? (Stress Test)

FOR EACH token sink:
  1. Is the sink compelling enough that players actually use it?
  2. Can the sink be bypassed (e.g., using alternative paths)?
  3. Is the sink proportional to emissions?

OVERALL ECONOMY:
  1. Model: total_daily_emission vs total_daily_sink
  2. If emission >> sink → flag as ECONOMIC DEATH SPIRAL RISK
  3. Check: Are there circuit breakers for extreme inflation?
```

### Anti-Pattern: Uncapped Reward Emission

```rust
// ❌ VULNERABLE — no cap, no diminishing returns, no cooldown
pub fn claim_battle_reward(ctx: Context<ClaimReward>) -> Result<()> {
    let reward = FIXED_REWARD_PER_BATTLE;  // Same reward every time
    // No check: how many times claimed today
    // No check: diminishing returns
    // No check: total daily emission
    mint_tokens(ctx.accounts.mint, ctx.accounts.player_ata, reward)?;
    Ok(())
}

// ✅ SECURE — time-gated + diminishing + capped
pub fn claim_battle_reward(ctx: Context<ClaimReward>) -> Result<()> {
    let player = &mut ctx.accounts.player_state;
    let clock = Clock::get()?;
    let today = clock.unix_timestamp / 86400;

    // Time gate: reset daily counter
    if player.last_claim_day != today {
        player.last_claim_day = today;
        player.daily_claims = 0;
    }

    // Daily cap
    require!(player.daily_claims < MAX_DAILY_CLAIMS, DailyCapReached);

    // Diminishing returns: each subsequent claim yields less
    let multiplier = DIMINISHING_CURVE[player.daily_claims as usize];
    let reward = BASE_REWARD
        .checked_mul(multiplier).ok_or(MathError)?
        .checked_div(PRECISION).ok_or(MathError)?;

    // Global emission cap check
    let global = &mut ctx.accounts.global_state;
    require!(
        global.daily_emission + reward <= MAX_DAILY_EMISSION,
        GlobalCapReached
    );

    mint_tokens(ctx.accounts.mint, ctx.accounts.player_ata, reward)?;
    player.daily_claims += 1;
    global.daily_emission += reward;
    Ok(())
}
```

---

## Pattern 4: Client-Server Trust Boundaries

### The Golden Rule

> **Never trust the client for anything with economic consequences.**

Games are uniquely vulnerable because the client (Unity, browser, mobile
app) is fully controlled by the attacker. Unlike web apps where server-side
validation is standard, games often push logic to the client for
performance — creating trust boundary violations.

### Trust Boundary Map

```
┌─────────────────────────────────────────┐
│           UNTRUSTED ZONE                 │
│         (Game Client)                    │
│                                          │
│  • Player inputs (movement, actions)     │
│  • Displayed scores / UI state           │
│  • Client-computed results               │
│  • Local save files                      │
│  • Memory-resident game state            │
│                                          │
│  ──────────── TRUST BOUNDARY ─────────── │
│                                          │
│           TRUSTED ZONE                   │
│     (Server / On-Chain Program)          │
│                                          │
│  • Reward calculations                   │
│  • Score validation                      │
│  • Asset ownership verification          │
│  • Economy rules enforcement             │
│  • Rate limiting                         │
│  • Anti-cheat validation                 │
└─────────────────────────────────────────┘
```

### What to Audit

```
FOR EACH client → server/program interaction:
  1. What data does the client send?
  2. Can ANY of that data be spoofed to gain advantage?
  3. Does the server/program independently validate ALL claims?
  4. Is there rate limiting to prevent spam/abuse?
  5. Are critical computations (rewards, damage, loot) on-chain?

SPECIFIC CHECKS:
  □ Server authority: Critical game logic runs server-side
  □ Rate limiting: API endpoints protected against bot abuse
  □ Economic modeling: Reward rates validated against economic model
  □ Audit critical paths: Especially reward/mint/burn logic
  □ Input validation: All client inputs bounds-checked
  □ Replay protection: Actions cannot be replayed for double rewards
```

### Anti-Pattern: Client-Authoritative Damage Calculation

```typescript
// ❌ VULNERABLE — client calculates and reports damage
// Attacker modifies client to report massive damage
websocket.send(JSON.stringify({
  action: 'attack',
  targetId: 'boss_1',
  damage: 999999,  // Client computed, easily modified
}));

// ✅ SECURE — client sends intent, server calculates outcome
websocket.send(JSON.stringify({
  action: 'attack',
  targetId: 'boss_1',
  weaponId: 'sword_42',
  // NO damage value — server computes from on-chain weapon stats
}));
```

---

## Pattern 5: Reward System Abuse Prevention

### Common Attack Vectors

| Attack | Description | Mitigation |
|--------|-------------|------------|
| Sybil Farming | One attacker, 1000 accounts | Per-wallet rate limits + proof-of-personhood |
| Bot Grinding | Automated 24/7 gameplay | Behavioral analysis + CAPTCHA gates on rewards |
| Time Manipulation | Exploit clock-based rewards | Use `Clock::get()` (Solana) or `block.timestamp`, never client time |
| Score Injection | Submit fabricated high scores | Server-computed scores from on-chain game state |
| Reward Front-Running | Claim rewards before legitimate winner | Commit-reveal schemes for competitive rewards |
| Flash Loan + Staking | Borrow → stake → claim → unstake → repay | Minimum staking duration enforced on-chain |

### What to Audit

```
FOR EACH reward distribution mechanism:
  1. Can a single entity create multiple accounts to multiply rewards?
  2. Can the reward trigger be automated (botted)?
  3. Is the time source server-side or client-side?
  4. Can reward amounts be influenced by client input?
  5. Are there minimum hold/lock periods for staking rewards?
  6. Can flash loans be used to temporarily meet staking requirements?
  7. Is there a commit-reveal pattern for competitive rewards?
```

---

## Pattern 6: In-Game Marketplace Security

### Marketplace Vulnerabilities

| Vulnerability | Impact | Check |
|--------------|--------|-------|
| Listing price manipulation | Buy underpriced NFTs | Verify listing price immutable after creation |
| Front-running purchases | MEV bots snipe deals | Use commit-reveal or private mempool |
| Cancelled listing still executable | Drain seller's NFT | Verify cancellation invalidates on-chain |
| Royalty bypass | Creator gets 0% | Enforce royalties at program level (Token-2022) |
| Fake NFT listing | Buyer receives worthless token | Verify mint authority + collection |
| Fee calculation rounding | Marketplace loses fees | Check rounding direction favors protocol |

### What to Audit

```
FOR EACH marketplace interaction:
  1. Listing creation: Is price stored on-chain or client-side?
  2. Purchase: Is the exact listed price enforced in the program?
  3. Cancellation: Does cancel fully invalidate the listing PDA?
  4. Royalties: Are they enforced at the program level?
  5. Collection verification: Can fake NFTs impersonate real ones?
  6. Fee math: Check rounding direction in all fee calculations
```

---

## Pattern 7: NFT Game Asset Integrity

### Asset Verification Checklist

```
FOR EACH NFT used as a game asset:
  1. OWNERSHIP: Is owner verified via token account authority?
  2. COLLECTION: Is collection verified (Metaplex Certified Collection)?
  3. ATTRIBUTES: Are game-relevant attributes stored on-chain?
  4. MUTABILITY: Can attributes be changed? By whom?
  5. TRANSFER HOOKS: Are transfer hooks used to enforce game rules?
  6. BURN AUTHORITY: Can the game burn assets? Under what conditions?
  7. FREEZE AUTHORITY: Can assets be frozen during gameplay?
```

### Anti-Pattern: Trusting Off-Chain Metadata for Game Logic

```rust
// ❌ VULNERABLE — game stats from off-chain metadata URI
// Attacker changes metadata JSON on their server
pub fn use_weapon(ctx: Context<UseWeapon>) -> Result<()> {
    let metadata_uri = get_metadata_uri(&ctx.accounts.nft_mint)?;
    let stats = fetch_from_uri(metadata_uri)?;  // Attacker controls this
    let damage = stats["attack_power"];  // Can be anything
    apply_damage(damage)?;
    Ok(())
}

// ✅ SECURE — game stats from on-chain account
pub fn use_weapon(ctx: Context<UseWeapon>) -> Result<()> {
    let weapon = &ctx.accounts.weapon_state;  // PDA derived from NFT mint
    require!(weapon.owner == ctx.accounts.player.key(), Unauthorized);
    let damage = weapon.attack_power;  // On-chain, program-controlled
    apply_damage(damage)?;
    Ok(())
}
```

---

## Pattern 8: Hardware Wallet & Biometric Authentication

### Hardware Security Attack Surface

Games integrating hardware-backed wallets (e.g., TEE + Secure Element)
introduce additional security considerations:

| Component | Attack Surface | What to Verify |
|-----------|---------------|----------------|
| TEE (Trusted Execution Environment) | Side-channel attacks, firmware exploits | Key material never leaves TEE |
| Secure Element | Physical extraction, power analysis | Transaction signing happens in SE |
| StrongBox (Android) | OS-level compromise | Keys marked `setIsStrongBoxBacked(true)` |
| Biometric Auth | Presentation attacks, bypass | Biometric required for EVERY signing |

### What to Audit

```
FOR hardware wallet integrations:
  1. Does biometric authentication gate EVERY transaction signature?
  2. Can the biometric check be bypassed via API calls?
  3. Are keys generated inside the secure element (not imported)?
  4. Is there a fallback path that bypasses hardware security?
  5. Does the game cache any signing authority client-side?
  6. Are transaction details shown BEFORE biometric prompt?

FOR mobile/handheld game consoles:
  1. Does the wallet implementation use the device's TEE?
  2. Is the key derivation path standard (BIP-44/BIP-32)?
  3. Can another app on the device access signing capabilities?
  4. Is there inter-process communication (IPC) validation?
```

---

## Pattern 9: Gasless Transaction Security

### Gasless (Sponsored) Transaction Risks

Many games use gasless/sponsored transactions (e.g., Kora) to improve UX.
This introduces fee payer trust and relay abuse vectors.

| Risk | Description | Mitigation |
|------|-------------|------------|
| Relay abuse | Attacker spams free transactions | Rate limiting per wallet address |
| Fee payer drain | Sponsored wallet depleted by bot farm | Per-session / per-wallet caps |
| Transaction substitution | Relay replaces user's intended transaction | User signs complete transaction, relay only broadcasts |
| Relay censorship | Relay refuses to submit certain transactions | Fallback to direct submission |

### What to Audit

```
FOR gasless/sponsored transaction systems:
  1. Who pays the fee? Is the fee payer wallet sufficiently funded?
  2. Are there per-address rate limits on sponsored transactions?
  3. Does the user sign the COMPLETE transaction (not just a message)?
  4. Can the relay modify the transaction after user signature?
  5. Is there Sybil protection (one user, many wallets)?
  6. What's the fallback if the relay is down?
  7. Are sponsored transaction types whitelisted?
```

---

## Pattern 10: Cross-Game Identity & Progression

### On-Chain Identity Risks

Games with persistent on-chain identity (cross-game profiles, XP systems,
achievement platforms) create new attack surfaces:

| Risk | Description | Check |
|------|-------------|-------|
| XP inflation | Fake game submits inflated XP | Is the game program whitelisted to write XP? |
| Achievement spoofing | Forge achievement completion | Is completion verified by authorized program? |
| Identity squatting | Register others' usernames | Is there identity verification or auction? |
| Profile manipulation | Alter level/stats after creation | Is profile PDA authority properly constrained? |
| Cross-game exploit | Use item in wrong game context | Is game ID verified in cross-game transfers? |

### What to Audit

```
FOR cross-game identity systems:
  1. Who can write to the identity/profile PDA?
  2. Is game program authorization verified before XP/achievement writes?
  3. Can achievements be replayed across game boundaries?
  4. Is there input validation on scores/XP submitted by game programs?
  5. Are game programs upgradeable? (upgrade → inflate XP)
  6. Is the username system resistant to squatting/impersonation?
```

---

## Master Audit Checklist

### Payment & Transaction Security

- [ ] All 7 Payment UX properties verified (Pattern 1)
- [ ] Transactions simulated before sending
- [ ] On-chain confirmation required before granting items
- [ ] Unique reference/memo per transaction (replay protection)
- [ ] Blockhash freshness verified before retry
- [ ] Partial failure handling tested

### State Management Security

- [ ] All valuable state lives on-chain (Pattern 2)
- [ ] No client-authoritative economic state
- [ ] Off-chain state cannot influence on-chain rewards
- [ ] Score/results computed server-side or on-chain

### Economic Security

- [ ] All 5 anti-inflation mechanisms present (Pattern 3)
- [ ] Daily/weekly emission caps enforced on-chain
- [ ] Diminishing returns implemented
- [ ] Token sinks exist and are compelling
- [ ] Economic death spiral scenario modeled
- [ ] Flash loan + staking exploit tested

### Trust Boundary Security

- [ ] Client sends intent, server/program computes outcome (Pattern 4)
- [ ] Rate limiting on all reward-granting endpoints
- [ ] All client inputs bounds-checked and validated
- [ ] No client-computed values used in economic calculations

### Reward System Security

- [ ] Sybil resistance implemented (Pattern 5)
- [ ] Bot detection / behavioral gates present
- [ ] Time source is on-chain, not client-provided
- [ ] Minimum staking durations enforced
- [ ] Competitive rewards use commit-reveal

### Asset & Marketplace Security

- [ ] NFT collection verification on-chain (Pattern 7)
- [ ] Game attributes stored on-chain, not in off-chain metadata
- [ ] Marketplace listings are immutable once created
- [ ] Royalties enforced at program level
- [ ] Cancellation invalidates listing fully

### Infrastructure Security

- [ ] Hardware wallet integration uses TEE/SE properly (Pattern 8)
- [ ] Biometric auth gates every signature
- [ ] Gasless relay has rate limits and Sybil protection (Pattern 9)
- [ ] Cross-game identity writes are authorized (Pattern 10)

---

## Cross-References

| Topic | Related Skill File |
|-------|-------------------|
| Oracle manipulation in games | [solana-scanner/resources/solana-oracle-audit.md](../solana-scanner/resources/solana-oracle-audit.md) |
| Solana program security | [solana-scanner/SKILL.md](../solana-scanner/SKILL.md) |
| Token economics auditing | [patterns/defi-perpetuals-audit.md](defi-perpetuals-audit.md) |
| NFT standards | [token-analyzer/SKILL.md](../token-analyzer/SKILL.md) |
| Confidential gaming (Arcium) | [patterns/confidential-gaming-audit.md](confidential-gaming-audit.md) |
| Smart account / multisig | [solana-scanner/resources/multisig-smart-account-audit.md](../solana-scanner/resources/multisig-smart-account-audit.md) |
