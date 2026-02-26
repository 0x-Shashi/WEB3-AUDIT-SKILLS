---
id: PAT-X402-PAYMENT-SECURITY
title: x402 Payment Protocol Security Patterns
category: pattern
severity: high
chains: [ethereum, base, solana]
languages: [solidity, typescript, rust, python, go]
tags:
  - x402
  - http-402
  - micropayments
  - eip-3009
  - permit2
  - facilitator
  - payment-protocol
last_updated: 2026-02-25
description: >-
  Use when auditing protocols that integrate x402 (HTTP 402 Payment Required)
  for on-chain micropayments — covers facilitator trust model, EIP-3009
  authorization attacks, Permit2 risks, cross-chain settlement, MCP payment
  flows, and payment replay/front-running vectors.
---

# x402 Payment Protocol Security Patterns

## Overview

x402 is an open standard (Apache-2.0, Coinbase) that activates HTTP 402 Payment
Required for programmatic on-chain payments. No accounts, sessions, or API keys —
clients pay with signed crypto transactions directly over HTTP. The protocol involves
three roles: Resource Server, Client (payer), and Facilitator (verifier + settler).

### Payment Flow

```
Client ──── GET /resource ─────────────► Resource Server
       ◄─── 402 + PAYMENT-REQUIRED ────

Client ──── Signs payment authorization ──┐
       │                                   │
       ──── GET /resource ─────────────► Resource Server
            + PAYMENT-SIGNATURE header     │
                                           │
       Resource Server ── POST /verify ──► Facilitator
                       ◄── verified ──────
       Resource Server ── POST /settle ──► Facilitator ──► On-chain
                       ◄── settled ───────
       ◄─── 200 + PAYMENT-RESPONSE ────
            + resource data
```

**Critical insight**: The facilitator is a trusted intermediary that both verifies
payment signatures and settles them on-chain. A compromised facilitator can steal
payments, censor transactions, or serve resources without settlement.

## 1. Facilitator Trust Model Attacks

### 1.1 Facilitator Compromise

The facilitator verifies payment signatures and settles on-chain. The default public
facilitator (`https://x402.org/facilitator`) is a single point of trust.

**Attack vector**: Compromised facilitator accepts payment authorization from client,
returns "verified" to resource server (which delivers the resource), but never settles
on-chain — effectively stealing the payment.

**What to check**:
- [ ] Does the protocol use the public facilitator or a self-hosted one?
- [ ] Is there on-chain settlement verification independent of the facilitator?
- [ ] Can the resource server verify settlement directly on-chain?
- [ ] Is there a settlement timeout with automatic refund?
- [ ] Does the facilitator have access to private keys? (It shouldn't — only signatures)

### 1.2 Self-Hosted Facilitator Configuration

```typescript
// Self-hosted facilitator — full control but increased responsibility
const facilitator = new HTTPFacilitatorClient({
  url: "https://your-facilitator.example.com"
});

// VULNERABLE: No TLS pinning, no certificate validation
// A MITM can intercept/redirect facilitator traffic
```

**What to check**:
- [ ] Is the facilitator endpoint HTTPS with valid certificates?
- [ ] Is there mutual TLS between resource server and facilitator?
- [ ] Can the facilitator endpoint be changed at runtime (configuration injection)?
- [ ] Is the facilitator's on-chain settler account properly funded?

### 1.3 Facilitator Censorship

**Attack vector**: Facilitator selectively refuses to verify/settle payments from
specific clients or for specific resources, creating a censorship layer.

**What to check**:
- [ ] Can clients bypass the facilitator and settle directly?
- [ ] Is there a fallback facilitator mechanism?
- [ ] Does the protocol support multi-facilitator redundancy?

## 2. Payment Authorization Attacks

### 2.1 EIP-3009 TransferWithAuthorization Replay

On EVM chains, x402 uses EIP-3009 (`transferWithAuthorization`) for USDC or
Permit2 for other tokens. EIP-3009 authorizations include a nonce to prevent replay.

**Attack vector**: If the nonce is predictable or reused, the same authorization
can be submitted multiple times.

```typescript
// EIP-3009 authorization structure
{
  from: senderAddress,
  to: recipientAddress,
  value: amount,
  validAfter: timestamp,
  validBefore: timestamp + TTL,
  nonce: randomBytes32  // ← MUST be cryptographically random
}
```

**What to check**:
- [ ] Is the nonce generated from a CSPRNG (cryptographically secure)?
- [ ] Does `validBefore` have a tight window (minutes, not days)?
- [ ] Is there on-chain nonce tracking to prevent replay?
- [ ] Can the authorization be used on a different chain (missing chainId in domain)?

### 2.2 Permit2 Token Approval Risks

For non-EIP-3009 tokens, x402 uses Uniswap's Permit2 protocol with a dedicated
proxy contract (`x402Permit2Proxy`).

```solidity
// x402 Permit2 proxy — intermediary between payer and recipient
// Risk: Payer must approve Permit2 for the token amount
// If the proxy is compromised, all approved tokens are at risk
```

**Attack vector**: Client grants Permit2 approval thinking it's for a micropayment,
but the approval amount is much larger than needed, enabling future drains.

**What to check**:
- [ ] Are Permit2 approvals scoped to exact amounts (not unlimited)?
- [ ] Is the `x402Permit2Proxy` contract verified and audited?
- [ ] Does the approval include a tight `expiration` timestamp?
- [ ] Can the proxy be upgraded (proxy pattern)?
- [ ] Is there a separate proxy per network?

### 2.3 Payment Signature Front-Running

**Attack vector**: Attacker observes a client's `PAYMENT-SIGNATURE` header in transit
(if not TLS) and submits it to the facilitator before the resource server does, settling
the payment to a different recipient.

**What to check**:
- [ ] Is the `payTo` address bound in the payment signature (not modifiable)?
- [ ] Is the resource server endpoint bound in the payment data?
- [ ] Is all communication over TLS?
- [ ] Is there an idempotency mechanism (payment-identifier extension)?

## 3. Cross-Chain Settlement Risks

x402 supports multi-network payments (EVM + Solana) simultaneously:

```typescript
// Server accepts payment on multiple networks
"GET /weather": {
  accepts: [
    { scheme: "exact", price: "$0.001", network: "eip155:84532", payTo: evmAddress },
    { scheme: "exact", price: "$0.001", network: "solana:EtWTR...", payTo: svmAddress },
  ],
}
```

### 3.1 Network Confusion

**Attack vector**: Client signs payment for testnet (Base Sepolia: `eip155:84532`) but
resource server expects mainnet payment (`eip155:8453`). If chain validation is weak,
the resource is delivered without real payment.

**What to check**:
- [ ] Does the server validate the `network` field from the payment against accepted networks?
- [ ] Is CAIP-2 chain ID parsing done correctly for both EVM (`eip155:*`) and Solana (`solana:*`)?
- [ ] Are testnet facilitators segregated from mainnet?
- [ ] Does the facilitator verify on the correct chain?

### 3.2 Token Mismatch

**Attack vector**: Server accepts USDC on Base, client pays with a worthless token
that has the same address on a different chain.

**What to check**:
- [ ] Is `asset` (token contract address) validated per chain?
- [ ] Does the facilitator verify token contract authenticity?
- [ ] Is there a default asset resolution that can be spoofed?

## 4. Solana-Specific Payment Vectors

On Solana, x402 uses SPL `TransferChecked` instructions:

```typescript
// Solana payment payload
{
  payerKey: "sender_pubkey",
  recipientKey: "recipient_pubkey",
  asset: "USDC_MINT_ADDRESS",
  amount: 1000,  // micro-units
  transaction: "base64_serialized_tx"
}
```

### 4.1 Transaction Substitution

**Attack vector**: Client signs a transaction for the correct amount but to a different
recipient. If the facilitator only checks the signature without deserializing the
transaction, the payment goes to the attacker.

**What to check**:
- [ ] Does the facilitator deserialize and validate the full transaction?
- [ ] Is the recipient address checked against the expected `payTo`?
- [ ] Is the mint address verified?
- [ ] Is `TransferChecked` used (which validates decimals) vs `Transfer` (which doesn't)?

### 4.2 Partial Transaction Submission

**Attack vector**: Client constructs a valid-looking transaction that will fail on-chain
(insufficient funds, wrong PDA), but the facilitator marks it as verified based only on
signature validity.

**What to check**:
- [ ] Does the facilitator simulate the transaction before marking as verified?
- [ ] Is there a distinction between "verified" (signature valid) and "settled" (on-chain)?
- [ ] Does the resource server wait for settlement confirmation before delivering?

## 5. MCP Payment Integration

x402 integrates with Model Context Protocol for AI agent payments:

```typescript
// MCP transport — payment data in JSON-RPC _meta field
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "_meta": {
    "x402": {
      "paymentSignature": "...",
      "paymentRequired": { ... }
    }
  }
}
```

### 5.1 AI Agent Payment Autonomy

**Attack vector**: AI agent with payment capability is tricked into paying for resources
via prompt injection or MCP tool manipulation. The agent autonomously signs payments
without human approval.

**What to check**:
- [ ] Does the agent have spending limits per tool call?
- [ ] Is there a human-in-the-loop for payments above a threshold?
- [ ] Are payment amounts logged and auditable?
- [ ] Can the agent be tricked into paying for resources it shouldn't?

### 5.2 MCP Server Payment Inflation

**Attack vector**: Malicious MCP server progressively increases prices or charges for
tool calls that should be free.

**What to check**:
- [ ] Does the client validate prices against expected ranges?
- [ ] Is there a maximum price per tool call?
- [ ] Are price changes logged and alertable?

## 6. Extension Security

### 6.1 Payment Identifier (Idempotency)

The `paymentIdentifier` extension prevents double-payment for the same resource.

**Attack vector**: If the identifier is predictable, an attacker can pre-occupy
identifiers to denial-of-service legitimate payments.

**What to check**:
- [ ] Are payment identifiers cryptographically random?
- [ ] Is there a TTL on identifier reservation?
- [ ] Can identifiers be reused after expiry?

### 6.2 Sign-In With X (Authentication)

The `sign-in-with-x` extension uses SIWE (Sign-In With Ethereum) or SIWS (Solana)
for wallet-based authentication alongside payment.

**Attack vector**: SIWE nonce reuse or domain mismatch allows replay of authentication.

**What to check**:
- [ ] Is the SIWE/SIWS nonce single-use and verified server-side?
- [ ] Does the domain in the SIWE message match the resource server domain?
- [ ] Is the `issued-at` timestamp within an acceptable window?

### 6.3 Gas Sponsoring Extensions

Two gas sponsoring schemes: `eip2612GasSponsoring` and `erc20ApprovalGasSponsoring`.

**Attack vector**: Gas sponsor drains by rapidly generating micropayments that each
consume sponsored gas, with no actual resource consumption.

**What to check**:
- [ ] Is gas sponsoring rate-limited per client address?
- [ ] Are sponsored transactions validated before submission?
- [ ] Is there a maximum gas budget per sponsorship?

## Security Review Checklist

### Facilitator Trust
- [ ] Identify facilitator type (public vs self-hosted)
- [ ] Verify settlement independence from facilitator (on-chain proof)
- [ ] Check for settlement timeout and refund mechanism
- [ ] Verify facilitator communication is TLS-protected

### Payment Authorization
- [ ] Verify EIP-3009 nonce generation (CSPRNG required)
- [ ] Check `validBefore` window tightness
- [ ] Verify Permit2 approval scope (exact amount, tight expiration)
- [ ] Check payment signature binding to recipient and resource

### Cross-Chain
- [ ] Verify CAIP-2 chain ID validation
- [ ] Check testnet/mainnet segregation
- [ ] Verify token contract address per chain

### Solana-Specific
- [ ] Verify full transaction deserialization by facilitator
- [ ] Check `TransferChecked` usage (not raw `Transfer`)
- [ ] Verify transaction simulation before settlement

### AI Agent / MCP
- [ ] Verify per-tool-call spending limits
- [ ] Check for human-in-the-loop above threshold
- [ ] Verify price validation against expected ranges

## Cross-References

- [erc-8004-agent-security.md](erc-8004-agent-security.md) — Agent identity for payment recipients
- [ai-agent-payment-patterns.md](ai-agent-payment-patterns.md) — Cross-cutting agent + payment risks
- [aa-delegation-session-patterns.md](aa-delegation-session-patterns.md) — Session key payment authorization

## Sources

- x402 Protocol: https://github.com/coinbase/x402
- x402 Specification: https://github.com/coinbase/x402/tree/main/specs
- EIP-3009: https://eips.ethereum.org/EIPS/eip-3009
- Permit2: https://github.com/Uniswap/permit2
