---
id: PAT-CONFIDENTIAL-GAMING-AUDIT
title: Confidential Gaming Audit Patterns
category: patterns
severity: high
chains: [solana]
languages: [rust, typescript]
tags:
  - arcium
  - confidential
  - mxe
  - hidden-state
  - fog-of-war
  - sealed-bid
  - mev-protection
  - privacy
  - multi-party-computation
  - game-security
last_updated: 2026-02-27
description: >-
  Use when auditing Solana games or protocols that use confidential compute
  environments (Arcium MXE, similar MPC/TEE systems) for private game state,
  sealed-bid auctions, fog-of-war mechanics, or MEV-protected actions.
  Covers the architecture of client → confidential compute → L1 settlement,
  state revelation timing attacks, proof verification, and the intersection
  of privacy guarantees with on-chain auditability. Emerging attack surface
  analogous to Token-2022 confidential transfers.
---

# Confidential Gaming Audit Patterns

## Overview

Confidential gaming uses off-chain secure computation (Multi-Party
Computation, Trusted Execution Environments, or hybrid systems) to keep
game state hidden until the rules dictate revelation. This solves a real
problem: on a transparent blockchain, all state is public — meaning
card games, fog-of-war, sealed bids, and hidden inventories are impossible
without a privacy layer.

**Core risk**: The privacy layer becomes a new trust boundary. If the
confidential compute environment is compromised, all "hidden" state is
exposed AND the attacker can predict or manipulate game outcomes.

### Architecture: Confidential Gaming Stack

```
  ┌──────────────┐
  │  Game Client  │  Player actions (move, bid, play card)
  └──────┬───────┘
         │ Encrypted inputs
         ▼
  ┌──────────────────────┐
  │  Confidential Compute │  Arcium MXE / TEE / MPC cluster
  │  Environment          │  - Processes hidden state
  │  (Off-Chain)          │  - Generates proofs
  │                       │  - Reveals results when rules allow
  └──────────┬───────────┘
             │ Proof + revealed state
             ▼
  ┌──────────────────────┐
  │  Solana L1            │  On-chain settlement
  │  (Settlement Layer)   │  - Verifies proofs
  │                       │  - Updates balances
  │                       │  - Enforces commitments
  └──────────────────────┘
```

### Why This Matters for Auditors

| Traditional Game Audit | Confidential Game Audit |
|-----------------------|------------------------|
| All state is on-chain and verifiable | Critical state is hidden off-chain |
| Logic is in verified Solana programs | Logic runs in MXE/TEE — different trust model |
| Exploits are visible on-chain | Exploits may be invisible (hidden compute) |
| Oracle manipulation is the main risk | State revelation timing is the main risk |

## Arcium MXE (Multi-Party eXecution Environment)

### How Arcium Works

Arcium provides confidential compute for Solana via a network of MXE nodes
running Multi-Party Computation (MPC):

```
1. Client encrypts game action with session key
2. Encrypted data sent to MXE node cluster (N nodes)
3. MPC protocol: each node holds a share, none sees plaintext
4. Computation runs on encrypted data (e.g., "is my hidden card > opponent's?")
5. Result is revealed to authorized parties only
6. Proof of correct computation posted to Solana
7. On-chain program verifies proof and updates state
```

### MXE Trust Assumptions

| Assumption | What It Means | Risk If Violated |
|-----------|--------------|------------------|
| Honest majority in MPC | At least t-of-n nodes are honest | Colluding nodes reconstruct plaintext |
| TEE integrity (if used) | Enclave hasn't been compromised | All hidden state exposed |
| Network liveness | MXE nodes respond within timeout | Game halts; locked funds |
| Correct implementation | MPC protocol matches specification | Silent computation errors |

## Confidential Gaming Attack Patterns

### Pattern 1: State Revelation Timing Attack

**Vulnerability**: Hidden state is revealed too early, giving one player
an unfair advantage.

```
Scenario: Poker game with hidden hands
Attack:
1. Game reaches showdown — hidden hands should be revealed simultaneously
2. MXE reveals Player A's hand first (network latency or bug)
3. Player B sees Player A's hand before their own is revealed
4. Player B disconnects (avoids revealing losing hand / paying pot)

Audit checklist:
- [ ] Are state revelations atomic (all-or-nothing)?
- [ ] Is there a commitment phase before revelation?
- [ ] What happens if one party refuses to participate in revelation?
- [ ] Is there a timeout + default resolution for non-responsive players?
```

### Pattern 2: Commitment-Reveal Scheme Manipulation

Most confidential games use commit-reveal:

```
COMMIT:  hash(secret + nonce) posted on-chain
REVEAL:  secret + nonce posted on-chain, hash verified

Vulnerabilities:
1. Missing nonce: hash(secret) is grindable for small domains
   - Card game with 52 cards: only 52 possible hashes to check
   - ❌ hash("ace_of_spades") → instantly reveals the card
   - ✅ hash("ace_of_spades" + random_256_bit_nonce) → preimage-resistant

2. Selective reveal: Player commits but never reveals when losing
   - Mitigation: Slash bond if reveal doesn't happen within timeout

3. Front-running reveal: MEV bot sees reveal tx in mempool, acts first
   - Mitigation: Use MXE for revelation (not on-chain reveal tx)
```

### Pattern 3: MPC Node Collusion

**Vulnerability**: If enough MXE nodes collude, they can reconstruct
any player's hidden state.

```
Typical MPC threshold: 2-of-3 or 3-of-5
Attack: Two colluding nodes combine their shares → see all hidden cards

Audit questions:
- What is the MPC threshold (t-of-n)?
- Who operates the MXE nodes? (Same entity = single point of failure)
- Is node selection deterministic or random per session?
- Can a game creator choose which nodes run their game?
- Is there slashing for provable misbehavior?
```

**Risk classification**:

| Node Configuration | Trust Level | Suitable For |
|-------------------|-------------|-------------|
| 1-of-1 (single operator) | Centralized | Low-stakes games only |
| 2-of-3 (known operators) | Semi-trusted | Medium-stakes with reputation |
| 3-of-5 (independent operators) | Decentralized | High-stakes gaming |
| t-of-n with TEE attestation | High assurance | Financial gaming / gambling |

### Pattern 4: Encrypted Input Manipulation

**Vulnerability**: Client sends maliciously crafted encrypted input that
causes unexpected behavior in the MXE computation.

```
Scenario: Card game — client supposed to play a card from their hand
Attack:
1. Client encrypts "play card #99" (doesn't exist in hand)
2. MXE processes the encrypted input without input validation
3. Result: array out-of-bounds, or playing a card they don't have

Audit checklist:
- [ ] Does the MXE validate inputs BEFORE computation?
- [ ] Are input ranges enforced (card_id in [0, 51])?
- [ ] Is the input encrypted with an authenticated scheme (AEAD)?
- [ ] Can replay of old encrypted inputs succeed?
```

### Pattern 5: Proof Verification Bypass

**Vulnerability**: On-chain program accepts state updates from MXE
without properly verifying the computation proof.

```rust
// ❌ DANGEROUS: No proof verification
pub fn settle_game(ctx: Context<Settle>, result: GameResult) -> Result<()> {
    // Trusts result directly — MXE could submit anything
    ctx.accounts.game.winner = result.winner;
    transfer_pot(ctx, result.winner)?;
    Ok(())
}

// ✅ SAFE: Verify proof before accepting result
pub fn settle_game(
    ctx: Context<Settle>,
    result: GameResult,
    proof: ComputationProof,
) -> Result<()> {
    // 1. Verify proof was generated by authorized MXE cluster
    require!(
        verify_mxe_signature(&proof, &AUTHORIZED_MXE_CLUSTER),
        ErrorCode::InvalidMXEProof
    );

    // 2. Verify proof covers THIS game session (not a different one)
    require!(
        proof.session_id == ctx.accounts.game.session_id,
        ErrorCode::SessionMismatch
    );

    // 3. Verify proof is fresh (not replayed)
    require!(
        proof.sequence > ctx.accounts.game.last_proof_sequence,
        ErrorCode::StaleProof
    );

    // 4. Accept result
    ctx.accounts.game.winner = result.winner;
    ctx.accounts.game.last_proof_sequence = proof.sequence;
    transfer_pot(ctx, result.winner)?;
    Ok(())
}
```

### Pattern 6: MEV in Game Actions

**Vulnerability**: Even with hidden game state, the EXISTENCE and TIMING
of transactions leak information.

```
Scenario: Sealed-bid auction using MXE for bid privacy
Information leak:
1. Attacker monitors Solana for "submit_bid" transactions
2. Transaction metadata reveals: WHO bid, WHEN, gas fee (priority)
3. Even without knowing the bid AMOUNT, timing and frequency are signals
4. Attacker submits last-second bid based on observed participation

Advanced MEV:
- MXE node operator can see encrypted bid before forwarding
- If node operator is also a bidder → insider trading

Audit checklist:
- [ ] Does the protocol hide transaction metadata (not just state)?
- [ ] Are bid submissions indistinguishable from other transactions?
- [ ] Is there a submission deadline enforced on-chain?
- [ ] Are MXE node operators prohibited from participating?
```

### Pattern 7: State Transition Proof Gaps

**Vulnerability**: MXE proves result is correct but doesn't prove ALL
intermediate state transitions were valid.

```
Scenario: Turn-based strategy game
1. Turn 1 → MXE computes → posts proof of Turn 1 result ✓
2. Turn 2 → MXE computes → posts proof of Turn 2 result ✓
3. Problem: Does Turn 2 proof verify it started from Turn 1's end state?

If proofs don't chain: MXE can skip states, replay old states, or
fabricate intermediate positions.

Required property: proof(turn_N).input_state_hash == proof(turn_N-1).output_state_hash
```

### Pattern 8: Fog-of-War State Leakage

**Vulnerability**: In fog-of-war games, the client must NOT receive
information about hidden map areas. But if the client receives encrypted
data for the entire map, traffic analysis reveals map changes.

```
Scenario: RTS game with fog-of-war
Attack:
1. Client receives encrypted map updates for visible region
2. When an enemy enters the fog (near visible region):
   - Data packet SIZE changes (more entities to encrypt)
   - Update FREQUENCY changes (more state changes)
3. Even without decryption, attacker infers enemy movement patterns

Mitigation:
- Fixed-size encrypted packets (pad to constant length)
- Constant-rate updates (send dummy data when nothing changes)
- MXE only sends data for visible regions (never hidden regions)
```

## Settlement Layer Security

### On-Chain Settlement Checklist

The Solana program that receives MXE results must verify:

```
1. PROOF VERIFICATION
   - [ ] MXE computation proof is cryptographically valid
   - [ ] Proof was generated by an authorized MXE cluster
   - [ ] Proof covers the correct game session ID
   - [ ] Proof sequence number is monotonically increasing

2. STATE CONSISTENCY
   - [ ] Result is consistent with game rules (valid winner, valid scores)
   - [ ] State transition from previous state is valid
   - [ ] No state was skipped (proof chaining)
   - [ ] Timeout defaults are applied if MXE is non-responsive

3. VALUE SETTLEMENT
   - [ ] Winner receives correct amount (pot minus fees)
   - [ ] Loser's funds are correctly debited
   - [ ] Protocol fees are correctly extracted
   - [ ] No double-settlement (same game can't settle twice)

4. DISPUTE RESOLUTION
   - [ ] Is there a challenge period after result posting?
   - [ ] Can players dispute with evidence?
   - [ ] What happens if the MXE cluster goes offline mid-game?
   - [ ] Are player bonds returned on legitimate disputes?
```

### Timeout and Liveness Patterns

```rust
// Critical: What happens when MXE stops responding?
pub fn claim_timeout(ctx: Context<ClaimTimeout>) -> Result<()> {
    let game = &ctx.accounts.game;
    let clock = Clock::get()?;

    // Game has been waiting for MXE result too long
    require!(
        clock.unix_timestamp - game.last_action_timestamp > GAME_TIMEOUT_SECONDS,
        ErrorCode::GameNotTimedOut
    );

    // Default resolution: return funds to all players
    // (or award to the last player who acted, depending on game rules)
    for player in &game.players {
        refund_player(ctx, player, game.deposit_per_player)?;
    }

    game.status = GameStatus::TimedOut;
    Ok(())
}
```

## Privacy vs Auditability Trade-off

### The Fundamental Tension

| Property | Traditional On-Chain | Confidential Gaming |
|----------|---------------------|-------------------|
| Anyone can verify game fairness | ✅ All state public | ❌ State is hidden |
| Players can prove they were cheated | ✅ Replay transactions | ⚠️ Only if proofs are public |
| Auditors can review game logic | ✅ Read program code | ⚠️ MXE logic may not be public |
| Regulators can inspect | ✅ Blockchain explorer | ❌ Need MXE cooperation |

### Audit Assessment Framework

When auditing a confidential game, assess:

1. **What is hidden?** — Only game actions? Or game rules too?
2. **Who can reveal?** — MXE operator? Players? Court order?
3. **Is the MXE code open-source?** — If not, trust is fully in operator
4. **Are proofs independently verifiable?** — Can a third party verify?
5. **What's the failure mode?** — MXE down → funds locked? Lost?

### Severity Classification

| Finding | Severity | Rationale |
|---------|----------|-----------|
| MXE proof not verified on-chain | Critical | Any result can be fabricated |
| Single MXE operator (no MPC) | High | Centralized trust in one entity |
| No timeout/liveness mechanism | High | Funds locked if MXE goes offline |
| State revelation not atomic | Medium | Timing advantage for one player |
| Fixed-size padding not used | Medium | Traffic analysis reveals hidden state |
| MXE code not open-source | Medium | Cannot verify computation correctness |
| No dispute mechanism | Medium | Players have no recourse |
| Proof sequence not checked | High | Old results can be replayed |

## Comparison: Confidential Approaches

| Approach | Privacy Level | Trust Model | Latency | Cost | Maturity |
|----------|-------------|-------------|---------|------|----------|
| Arcium MXE (MPC) | High | t-of-n honest nodes | ~100ms | Medium | Emerging |
| TEE (SGX/TDX) | High | Intel/AMD hardware trust | ~10ms | Low | Established but has side-channel risks |
| ZK Proofs (client-side) | Full | Trustless (math only) | ~1-10s | High (prover cost) | Maturing |
| Commit-Reveal (on-chain) | Low | Trustless | 2+ blocks | Low | Battle-tested |
| Hybrid (MXE + ZK) | High | Reduced trust via ZK | ~200ms | High | Experimental |

## Cross-References

| Topic | Related Skill File |
|-------|-------------------|
| GameFi economic security | [patterns/gamefi-security-patterns.md](gamefi-security-patterns.md) |
| Solana oracle manipulation | [solana-scanner/resources/solana-oracle-audit.md](../solana-scanner/resources/solana-oracle-audit.md) |
| Token-2022 confidential transfers | [solana-scanner/SKILL.md](../solana-scanner/SKILL.md) |
| CPI adversarial patterns | [patterns/cpi-adversarial-security.md](cpi-adversarial-security.md) |
| Formal verification for proofs | [methodology/formal-verification-assessment.md](../methodology/formal-verification-assessment.md) |
| Payment security patterns | [patterns/gamefi-security-patterns.md §Payment UX](gamefi-security-patterns.md) |
