---
id: TON-AUDIT
title: TON Smart Contract Audit Workflow
category: ton-scanner
difficulty: advanced
triggers:
  - ton audit workflow
  - func audit steps
  - tact audit steps
  - ton security review
related_skills:
  - ton-scanner/SKILL.md
  - ton-scanner/resources/ton-patterns.md
tags:
  - ton
  - audit
  - workflow
  - func
  - tact
last_updated: 2026-02-24
---

# TON Smart Contract Audit Workflow

> TON auditing requires thinking in messages, not transactions. Every cross-contract interaction is asynchronous. This workflow covers FunC and Tact contracts on TVM.

---

## Step 1: Contract Structure Mapping

**Goal**: Understand the contract's message interface, storage layout, and dependencies.

### FunC Contracts
```func
;; Identify all entry points:
() recv_internal(int balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    ;; Internal messages (from other contracts or wallets)
    int op = in_msg_body~load_uint(32);  ;; Operation code
    int query_id = in_msg_body~load_uint(64);  ;; Query ID for matching replies
}

() recv_external(slice in_msg) impure {
    ;; External messages (from off-chain)
    ;; Must call accept_message() to pay gas
}

;; Identify all get-methods (read-only, off-chain only):
int get_balance() method_id {
    return load_data().balance;
}
```

### Tact Contracts
```tact
contract MyContract {
    // Identify receive handlers (equivalent to recv_internal)
    receive(msg: Deploy) { ... }
    receive(msg: TokenTransfer) { ... }
    receive("emergency-stop") { ... }   // Text message receiver

    // External receivers (equivalent to recv_external)
    external(msg: ExternalCommand) { ... }

    // Bounced message handlers (critical!)
    bounced(msg: bounced<TokenTransfer>) { ... }

    // Get-methods
    get fun balance(): Int { return self.balance; }
}
```

### Checklist
- [ ] All operation codes (`op`) mapped and documented
- [ ] Storage layout documented (cell tree structure)
- [ ] Contract dependencies identified (what contracts does it message?)
- [ ] All get-methods identified (cannot be used for on-chain logic)

---

## Step 2: Message Flow Analysis

**Goal**: Trace every message chain from entry to final state change.

```
Draw the message graph:

  [External User]
        │
        ▼ (op::transfer, value: 1 TON)
  ┌─────────────┐
  │   Wallet     │
  └──────┬──────┘
         │ (op::transfer_notification, value: 0.9 TON)
         ▼
  ┌─────────────┐
  │   Jetton     │──► Bounce back if wallet doesn't exist
  │   Wallet     │
  └──────┬──────┘
         │ (op::internal_transfer, value: 0.8 TON)
         ▼
  ┌─────────────┐
  │   Jetton     │──► Bounce back if insufficient balance
  │   Master     │
  └─────────────┘
```

### What to Trace
- **Value flow**: How much TON enters each hop? How much is forwarded?
- **Gas budget**: Is there enough gas for the entire chain?
- **Failure paths**: What happens if any hop bounces? Does the originator get refunded?
- **Return path**: Are query_ids used consistently for matching replies to requests?

---

## Step 3: Gas & Value Accounting

**Goal**: Verify every message has sufficient gas and values are correctly accounted.

### FunC Gas Calculation
```func
;; Key gas costs to verify:
;; - accept_message() for external messages
;; - Storage fees: ~0.001 TON per KB per year
;; - Forwarding fees: depends on message size
;; - Computation: typically 0.01-0.05 TON for simple operations

;; Check: Does the contract reserve enough for storage?
int MIN_BALANCE = 50000000;  ;; 0.05 TON minimum reserve

() recv_internal(int balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    ;; FIX: Reserve minimum balance for storage fees
    int available = balance + msg_value - MIN_BALANCE;
    throw_unless(ERROR_LOW_BALANCE, available > 0);
}
```

### Send Mode Analysis
| Scenario | Correct Mode | Why |
|---|---|---|
| Reply to sender | `64` | Forward remaining incoming gas |
| Transfer specific amount | `0` or `1` | Pay fees from value (0) or balance (1) |
| Return all funds | `64` | Carry remaining value back |
| Emergency drain | `128 + 32` | **Only** with proper access control |

### Checklist
- [ ] Each outgoing message has explicitly calculated gas value
- [ ] `send_raw_message` mode flags documented and justified
- [ ] Contract maintains minimum balance for storage fees
- [ ] Mode 128 and mode 32 protected by strict access control
- [ ] Gas forwarding chain verified end-to-end (entry → final hop)

---

## Step 4: Bounce Handling Review

**Goal**: Verify every bounceable message has a corresponding bounce handler.

### Audit Process
1. Find all `send_raw_message` with bounceable flag (0x18)
2. For each, verify `recv_internal` checks `flags & 1`
3. Verify the bounce handler reverses any state changes from the original send
4. In Tact: verify `bounced()` handlers exist for every message type sent

```func
;; Pattern: For every send, check the bounce path
;;
;; SEND:    Transfer 100 tokens to user
;;          → Debit sender by 100
;;          → send_raw_message(transfer, 64)
;;
;; BOUNCE:  Message failed
;;          → on_bounce: Credit sender back by 100
;;          → If on_bounce is missing: 100 tokens LOST FOREVER
```

### Checklist
- [ ] Every bounceable `send_raw_message` has a bounce handler
- [ ] Bounce handlers reverse state changes correctly
- [ ] Non-bounceable messages (0x10) justified — understand the risk
- [ ] Bounce handlers don't themselves send bounceable messages (bounce loop)

---

## Step 5: Storage Layout & Fee Analysis

**Goal**: Verify storage is bounded and fees won't drain the contract.

### Cell Tree Analysis
```
;; TON storage is a tree of cells
;; Each cell: max 1023 bits, max 4 references (child cells)
;; Storage fee: proportional to total bits + cells stored

Contract Storage (Root Cell)
├── [256 bits] owner address
├── [64 bits] balance
├── [Cell Ref 1] user_data (Dictionary)
│   ├── Entry 1: [256-bit key → Cell value]
│   ├── Entry 2: [256-bit key → Cell value]
│   └── ... (unbounded?)      ◄── Check size limit!
├── [Cell Ref 2] config
└── [Cell Ref 3] ...

Total storage cost = (total_bits / 1024 + total_cells) × fee_per_year
```

### Checklist
- [ ] All dictionaries have maximum size limits
- [ ] Users pay proportional storage deposits for data they store
- [ ] Contract can clean up expired/old entries to reduce fees
- [ ] Cell tree depth reasonable (deep trees cost more to traverse)
- [ ] Contract has escape mechanism if balance drops too low

---

## Step 6: Replay & Authentication

**Goal**: Verify external messages cannot be replayed and message authentication is correct.

### FunC External Message Security
```func
() recv_external(slice in_msg) impure {
    ;; Required security checks:
    ;; 1. Signature verification
    var signature = in_msg~load_bits(512);
    throw_unless(35, check_signature(slice_hash(in_msg), signature, stored_pubkey));

    ;; 2. Sequence number (replay protection)
    var msg_seqno = in_msg~load_uint(32);
    throw_unless(33, msg_seqno == stored_seqno);

    ;; 3. Accept message (pay gas from contract)
    accept_message();

    ;; 4. Increment seqno BEFORE processing
    save_data(stored_seqno + 1, ...);

    ;; 5. Expiration (optional but recommended)
    var valid_until = in_msg~load_uint(32);
    throw_if(36, valid_until < now());
}
```

### Checklist
- [ ] `recv_external` validates signature before `accept_message()`
- [ ] Sequence number incremented before any state changes
- [ ] Message expiration implemented (prevents old message replay)
- [ ] Public key can be rotated if compromised

---

## Step 7: Serialization Safety

**Goal**: Verify all cell read/write operations stay within TVM limits.

### Common Pitfalls
```func
;; Pitfall 1: Reading more bits than available
int value = cs~load_uint(256);  ;; Throws if less than 256 bits remain

;; FIX: Check before reading
if (cs.slice_bits() >= 256) {
    int value = cs~load_uint(256);
}

;; Pitfall 2: Writing too much to a cell
;; 1023 bits max — 4 uint(256) = 1024 bits → OVERFLOW

;; Pitfall 3: More than 4 references
builder b = begin_cell();
b = b.store_ref(cell1);  ;; ref 1
b = b.store_ref(cell2);  ;; ref 2
b = b.store_ref(cell3);  ;; ref 3
b = b.store_ref(cell4);  ;; ref 4
b = b.store_ref(cell5);  ;; CRASH: max 4 refs per cell!
```

### Checklist
- [ ] Total bits per cell ≤ 1023 verified for all `begin_cell()` builders
- [ ] References per cell ≤ 4 verified
- [ ] Slice reads validated (sufficient bits/refs before loading)
- [ ] Dictionary operations handle missing keys gracefully

---

## Step 8: Sharding & Message Ordering

**Goal**: Identify cross-shard dependencies and ordering assumptions.

### Questions to Answer
- Are there operations that depend on messages being processed in a specific order?
- Can two concurrent messages to the same contract cause a race condition?
- Do multi-step operations have rollback mechanisms if a middle step fails?

### Checklist
- [ ] No cross-shard message ordering assumptions
- [ ] Multi-step operations use state machines (not sequence assumptions)
- [ ] Concurrent message handling verified (no race conditions)

---

## Step 9: Workchain & Address Validation

**Goal**: Verify address handling is correct.

```func
;; TON address = (workchain_id, hash_part)
;; Workchain 0 = basechain (most contracts)
;; Workchain -1 = masterchain (system contracts, validators)

;; Validate incoming addresses
(int, int) parse_address(slice addr) {
    (int wc, int hash) = parse_std_addr(addr);
    throw_unless(333, (wc == 0) | (wc == -1));  ;; Only valid workchains
    return (wc, hash);
}
```

### Checklist
- [ ] All parsed addresses validate workchain ID
- [ ] No assumptions about address format (MsgAddressInt variants)
- [ ] Contract handles both basechain and masterchain addresses if needed

---

## Step 10: Report & Findings

### TON-Specific Finding Fields
```markdown
## Finding: [Title]

**Severity**: Critical | High | Medium | Low
**Category**: Bounce Handling | Gas Management | Storage | Replay | Serialization | Sharding
**Contract**: [contract name, FunC/Tact]
**Location**: recv_internal(), op::XXXX

### Description
[Describe the vulnerability in terms of TON's actor model]

### Message Flow Impact
[Show how the vulnerability affects the message chain]

### Proof of Concept
[Show the attack message sequence]

### Recommendation
[Fix with FunC/Tact code example]
```

---

## Related Files

- [TON Scanner Overview](../SKILL.md) — Architecture, language comparison
- [TON Patterns](../resources/ton-patterns.md) — Vulnerability patterns with code
