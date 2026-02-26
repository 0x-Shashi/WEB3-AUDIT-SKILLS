---
id: PAT-ERC8004-AGENT-SECURITY
title: ERC-8004 AI Agent Registry Security Patterns
category: pattern
severity: high
chains: [ethereum, base, polygon, arbitrum, optimism]
languages: [solidity, typescript]
tags:
  - erc-8004
  - ai-agents
  - agent-registry
  - reputation
  - identity
  - uups
  - nft
last_updated: 2026-02-25
description: >-
  Use when auditing protocols that register, discover, or interact with AI
  agents on-chain — covers ERC-8004 identity registry attacks, reputation
  gaming, UUPS upgrade risks, agent wallet binding, MCP/A2A endpoint
  validation, and trust model verification.
---

# ERC-8004 AI Agent Registry Security Patterns

## Overview

ERC-8004 (Draft EIP) defines three on-chain singleton registries for discovering and
interacting with AI agents across organizational boundaries without pre-existing trust.
As AI agents gain on-chain agency, the attack surface expands beyond traditional DeFi
patterns into identity spoofing, reputation manipulation, and endpoint impersonation.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    ERC-8004 Registry Layer                   │
├───────────────────┬──────────────────┬──────────────────────┤
│ Identity Registry │ Reputation       │ Validation Registry  │
│ (ERC-721 NFTs)    │ Registry         │ (Attestations)       │
│                   │ (Feedback)       │                      │
├───────────────────┼──────────────────┼──────────────────────┤
│ agentURI →        │ fixed-point      │ Stake / zkML / TEE   │
│ Registration File │ signed feedback  │ validator binding     │
│ (IPFS / HTTPS)    │ + off-chain file │                      │
└───────────────────┴──────────────────┴──────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
   Agent Identity      Trust Signals         Hardware/Crypto
   (NFT + URI)         (Anti-Sybil)          Attestations
```

**Key insight**: All three registries are deployed as UUPS-upgradeable singletons via
CREATE2 deterministic addresses. A single upgrade vulnerability compromises the entire
agent identity layer across all chains.

## 1. Identity Registry Attacks

### 1.1 Agent URI Manipulation

The identity registry stores an `agentURI` pointing to a JSON registration file (IPFS or
HTTPS). The registration file advertises endpoints, capabilities, and trust models.

**Attack vector**: URI points to mutable storage (HTTPS) that can be changed after
registration to advertise malicious endpoints while retaining reputation built on
legitimate behavior.

```solidity
// VULNERABLE: Agent registered with HTTPS URI
// Attacker builds reputation → changes URI to point to malicious MCP server
function registerAgent(string calldata name, string calldata agentURI) external {
    // agentURI = "https://evil.com/agent.json"  ← can change content at any time
    uint256 tokenId = _nextTokenId++;
    _safeMint(msg.sender, tokenId);
    _agentURIs[tokenId] = agentURI;
}
```

**What to check**:
- [ ] Does the protocol pin to immutable storage (IPFS CID, Arweave)?
- [ ] Is there an on-chain content hash that must match the URI content?
- [ ] Can the `agentURI` be updated after registration? By whom?
- [ ] Is there a cooldown or re-verification after URI changes?

### 1.2 Bidirectional Link Verification Bypass

ERC-8004 establishes a bidirectional cryptographic link: the NFT points to the
registration file, and the registration file points back to the NFT via the
`registrations` field. Additionally, endpoint domain verification uses
`/.well-known/agent-registration.json`.

**Attack vector**: Attacker creates registration file claiming endpoints they don't
control, without proper domain verification.

```json
{
  "registrations": [
    {
      "agentId": 42,
      "agentRegistry": "eip155:84532:0x8004A818..."
    }
  ],
  "services": [
    { "name": "MCP", "endpoint": "https://victim.com/mcp" }
  ]
}
```

**What to check**:
- [ ] Does the consuming protocol verify `/.well-known/agent-registration.json` on the endpoint domain?
- [ ] Is the `registrations[].agentRegistry` validated against the actual registry contract?
- [ ] Are HTTPS endpoints validated for TLS and domain ownership?

### 1.3 Agent Transfer and Operator Abuse

Agent NFTs can be transferred and operators can be delegated. This creates a secondary
market for agent identities with established reputation.

**Attack vector**: Buy an agent NFT with high reputation, then use it to lure victims
via the trusted identity.

**What to check**:
- [ ] Does reputation reset on NFT transfer?
- [ ] Can operators perform critical actions (URI updates, endpoint changes)?
- [ ] Is there a grace period after transfer before the agent is considered trusted?

## 2. Reputation System Gaming

### 2.1 Sybil Feedback Attacks

The reputation registry uses a `getSummary()` function that requires a non-empty
`clientAddresses` array (caller supplies trusted reviewer list). Self-feedback is
rejected (agent owner/operators cannot submit feedback on their own agent).

**Attack vector**: Create multiple wallets, give each other feedback to inflate
reputation scores.

**What to check**:
- [ ] Is the `clientAddresses` filter actually applied in aggregation?
- [ ] Can the same wallet submit multiple feedbacks (overwrite vs accumulate)?
- [ ] Is there stake-weighting or token-gating on feedback submission?
- [ ] Can feedback be removed or modified after submission?

### 2.2 Fixed-Point Value Manipulation

Feedback uses signed fixed-point numbers: `value` (int128) + `valueDecimals` (uint8, 0-18).

```
Example: value=87, valueDecimals=0 → 87/100 quality
Example: value=9977, valueDecimals=2 → 99.77% uptime
```

**Attack vector**: Submit extreme values to skew averages. A single `value=type(int128).max`
feedback could dominate naive averaging.

```solidity
// VULNERABLE: No bounds checking on feedback value
function giveFeedback(
    string calldata agentId,
    int128 value,        // Can be int128.max or int128.min
    uint8 valueDecimals, // 0-18
    string calldata tag1,
    string calldata tag2,
    string calldata feedbackFileURI
) external { ... }
```

**What to check**:
- [ ] Are feedback values bounded per tag type?
- [ ] Does aggregation use median instead of mean (Sybil-resistant)?
- [ ] Is there minimum stake or history required to submit feedback?
- [ ] Can a single extreme value dominate the summary?

### 2.3 Cross-Chain Reputation Isolation

ERC-8004 deploys identical registries on multiple chains. An agent may register on
chain A with high reputation and on chain B with different (or malicious) behavior.

**What to check**:
- [ ] Does the application aggregate reputation cross-chain?
- [ ] Can different registration files exist per chain for the same logical agent?
- [ ] Is there a canonical chain designation for reputation?

## 3. Validation Registry Attacks

The validation registry stores third-party attestations: stake-based,
zkML (zero-knowledge machine learning), or TEE (Trusted Execution Environment).

### 3.1 Stale Attestation Exploitation

**Attack vector**: Validator attests agent quality at time T. Agent behavior degrades.
Attestation remains valid indefinitely.

**What to check**:
- [ ] Do attestations have expiry timestamps?
- [ ] Can validators revoke attestations?
- [ ] Is there a heartbeat or refresh mechanism?

### 3.2 Validator Capture

**Attack vector**: Validator colludes with agent operator. Validator provides fraudulent
attestations in exchange for payment.

**What to check**:
- [ ] Is validator registration open or permissioned?
- [ ] Is there slashing for provably false attestations?
- [ ] Do consuming protocols check multiple independent validators?

## 4. UUPS Upgrade Vulnerabilities

All three registries use UUPS-upgradeable proxies deployed via CREATE2.

```
   Same proxy addresses across ALL chains:
   Identity:   0x8004A169FB4a3325136EB29fA0ceB6D2e539a432
   Reputation: 0x8004BAa17C55a88189AE136b182e5fdA19dE9b63
   Validation: 0x8004Cb1BF31DAf7788923b405b754f57acEB4272
```

### 4.1 Upgrade Authority Compromise

**Attack vector**: Compromise the upgrade authority key → upgrade all three registries
on all chains simultaneously → insert backdoor that reassigns agent identities.

**What to check**:
- [ ] Who holds the upgrade authority (EOA, multisig, timelock)?
- [ ] Is the upgrade authority the same across all chains?
- [ ] Is there a timelock on upgrades with community veto?
- [ ] Can storage layout be corrupted by a malicious upgrade?

### 4.2 Uninitialized Implementation

Standard UUPS vulnerability: if the implementation contract's `initialize()` is not
called, an attacker can call it and become the owner.

**What to check**:
- [ ] Is `_disableInitializers()` called in the constructor?
- [ ] Is the implementation contract self-destructible?
- [ ] Are proxy admin slots properly protected?

## 5. MCP/A2A Endpoint Security

Agents advertise MCP (Model Context Protocol) and A2A (Agent-to-Agent) endpoints in
their registration files. These are the actual interaction surfaces.

### 5.1 MCP Tool Injection

**Attack vector**: Agent advertises MCP tools that, when invoked by an AI orchestrator,
execute malicious operations (data exfiltration, unauthorized transactions).

```json
{
  "services": [
    {
      "name": "MCP",
      "endpoint": "https://agent.example/mcp",
      "mcpTools": ["financial_analyzer", "execute_trade"]
    }
  ]
}
```

**What to check**:
- [ ] Does the consuming AI validate MCP tool schemas before invocation?
- [ ] Are tool outputs sandboxed from sensitive operations?
- [ ] Is there a capability boundary between read-only and state-changing tools?
- [ ] Does the orchestrator enforce rate limits per tool?

### 5.2 A2A Task Escalation

**Attack vector**: Agent accepts A2A tasks and escalates privileges through delegated
tool chains, performing operations beyond the original requester's intent.

**What to check**:
- [ ] Are A2A task scopes bounded?
- [ ] Does the task lifecycle enforce status transitions (submitted → working → done)?
- [ ] Can an agent spawn sub-tasks with elevated privileges?

## 6. Agent Wallet Security

Agents can declare an `agentWallet` in their registration — a CAIP-10 address used for
receiving payments (including x402 micropayments).

### 6.1 Wallet Verification Bypass

The `agentWallet` is set via `setAgentWallet()` which requires an EIP-712 or
ERC-1271 signature to prove wallet ownership.

**Attack vector**: If signature verification is weak or replayable, an attacker can
claim ownership of another agent's wallet to intercept payments.

**What to check**:
- [ ] Is the wallet signature scheme EIP-712 with proper domain separator (chainId, contract)?
- [ ] Does ERC-1271 verification include gas limit protection (reentrancy)?
- [ ] Can wallet assignments be replayed across chains?
- [ ] Is there a nonce to prevent replay of wallet setting transactions?

## 7. OASF Taxonomy Abuse

The Open Agentic Schema Framework provides 136 skills and 204 domains for agent
classification. Agents self-declare capabilities.

**Attack vector**: Agent claims capabilities it doesn't have to appear in searches,
then delivers malicious or empty responses.

**What to check**:
- [ ] Is there any on-chain or off-chain verification of claimed capabilities?
- [ ] Can an agent claim unlimited skills/domains?
- [ ] Does the search/discovery layer weight attestations over self-declarations?

## Security Review Checklist

### Identity Layer
- [ ] Verify `agentURI` storage mutability (IPFS preferred over HTTPS)
- [ ] Check bidirectional link validation (`registrations` field ↔ NFT)
- [ ] Verify domain ownership via `/.well-known/agent-registration.json`
- [ ] Check agent transfer effects on reputation
- [ ] Verify operator permission boundaries

### Reputation Layer
- [ ] Verify self-feedback prevention (owner/operator cannot rate own agent)
- [ ] Check `clientAddresses` filter enforcement in `getSummary()`
- [ ] Verify feedback value bounds per tag type
- [ ] Check for Sybil resistance (stake-weighting, identity requirements)
- [ ] Verify cross-chain reputation aggregation strategy

### Validation Layer
- [ ] Check attestation expiry and revocation mechanisms
- [ ] Verify validator independence (no collusion surface)
- [ ] Check minimum validator count requirements

### Upgrade Security
- [ ] Verify UUPS upgrade authority (multisig + timelock required)
- [ ] Check `_disableInitializers()` in implementation constructors
- [ ] Verify storage layout compatibility across upgrades
- [ ] Check consistency of upgrade authority across chains

### Endpoint Security
- [ ] Verify MCP tool schema validation before invocation
- [ ] Check A2A task scope boundaries
- [ ] Verify agent wallet signature scheme (EIP-712 domain separator)
- [ ] Check for endpoint impersonation via registration file manipulation

## Contract Addresses (Reference)

All registries use deterministic CREATE2 addresses via SAFE Singleton Factory:

| Registry | Mainnet Address | Chains |
|----------|-----------------|--------|
| Identity | `0x8004A169FB4a...a432` | Ethereum, Base, Polygon, Arbitrum, Optimism + 10 more |
| Reputation | `0x8004BAa17C55...9b63` | Same |
| Validation | `0x8004Cb1BF31D...4272` | Same |

## Cross-References

- [aa-delegation-session-patterns.md](aa-delegation-session-patterns.md) — Session keys for AI agent wallets
- [x402-payment-security.md](x402-payment-security.md) — Payment protocol agents use for micropayments
- [ai-agent-payment-patterns.md](ai-agent-payment-patterns.md) — Cross-cutting agent identity + payment risks

## Sources

- ERC-8004 Draft EIP: https://ethereum-magicians.org/t/erc-8004-trustless-agents/25098
- Agent0 SDK: https://sdk.ag0.xyz
- Contracts: https://github.com/erc-8004/erc-8004-contracts
- OASF Taxonomy: https://github.com/agntcy/oasf
