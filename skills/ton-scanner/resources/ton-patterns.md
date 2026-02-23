---
id: TON-PATTERNS
title: TON Vulnerability Patterns
category: ton-scanner
difficulty: advanced
triggers:
  - ton vulnerability patterns
  - func security bugs
  - tact security bugs
  - bounce handling
  - message chain gas
related_skills:
  - ton-scanner/SKILL.md
  - ton-scanner/workflows/ton-audit.md
tags:
  - ton
  - func
  - tact
  - patterns
  - security
last_updated: 2026-01-31
---

# TON Vulnerability Patterns

> TON uses an actor model: contracts communicate via asynchronous messages, not synchronous calls. There are no atomic cross-contract transactions. This creates a fundamentally different vulnerability surface from EVM chains.

---

## 1. Missing Bounce Handling (CRITICAL)

**Impact**: When a message to another contract fails (e.g., contract doesn't exist, runs out of gas), TON sends a **bounced message** back to the sender. If the sender doesn't handle the bounce, funds attached to the original message are permanently lost.

### Vulnerable FunC Code
```func
() send_tokens(slice to_address, int amount) impure {
    ;; Sends tokens to another contract
    var msg = begin_cell()
        .store_uint(0x18, 6)          ;; bounceable message
        .store_slice(to_address)
        .store_coins(amount)
        .store_uint(0, 1 + 4 + 4 + 64 + 32 + 1 + 1)
        .store_uint(op::transfer, 32)
        .end_cell();
    send_raw_message(msg, 64);  ;; forward remaining gas
    ;; BUG: No bounce handler!
    ;; If `to_address` doesn't exist or rejects, funds are lost
}

() recv_internal(int balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    slice cs = in_msg_full.begin_parse();
    int flags = cs~load_uint(4);
    ;; BUG: No check for bounced flag (bit 0x1)
    ;; Bounced messages silently ignored → lost funds
    int op = in_msg_body~load_uint(32);
    ;; ... handle operations
}
```

### Secure FunC Code
```func
() recv_internal(int balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    slice cs = in_msg_full.begin_parse();
    int flags = cs~load_uint(4);

    ;; FIX: Check for bounced messages first
    if (flags & 1) {  ;; bounced flag
        on_bounce(in_msg_body);
        return ();
    }

    int op = in_msg_body~load_uint(32);
    ;; ... handle normal operations
}

() on_bounce(slice in_msg_body) impure {
    ;; Skip 32-bit bounced prefix
    in_msg_body~skip_bits(32);
    int op = in_msg_body~load_uint(32);

    if (op == op::transfer) {
        ;; FIX: Reverse the transfer — credit funds back to sender
        int amount = in_msg_body~load_coins();
        ;; Restore internal accounting
        int sender_addr = in_msg_body~load_uint(256);
        ;; Credit back to the original sender
        save_data_with_refund(sender_addr, amount);
    }
}
```

### Secure Tact Code
```tact
contract SecureWallet {
    // Tact has built-in bounce handling
    bounced(msg: bounced<TokenTransfer>) {
        // FIX: Automatically called when TokenTransfer bounces
        // Reverse the accounting
        self.balance = self.balance + msg.amount;
    }
}
```

**Detection**: Search for `send_raw_message` with bounceable flag (0x18) and verify `recv_internal` checks `flags & 1`. In Tact, verify `bounced()` receivers exist for all sent message types.

---

## 2. Message Chain Gas Exhaustion (CRITICAL)

**Impact**: A multi-step operation (A → B → C → D) can fail mid-chain if insufficient gas is forwarded. The first steps succeed but later steps silently fail, leaving the system in an inconsistent state.

### Vulnerable FunC Code
```func
;; Contract A sends to B, B sends to C, C sends to D
;; Each hop consumes gas — if total gas is insufficient, D never executes

() process_order(slice buyer, int item_id, int price) impure {
    ;; Step 1: Debit buyer (succeeds)
    ;; Step 2: Send to marketplace contract (may run out of gas)
    var msg = begin_cell()
        .store_uint(0x18, 6)
        .store_slice(marketplace_addr)
        .store_coins(0)         ;; BUG: No gas attached for further hops!
        .store_uint(0, 1 + 4 + 4 + 64 + 32 + 1 + 1)
        .store_uint(op::finalize_sale, 32)
        .store_uint(item_id, 64)
        .end_cell();
    send_raw_message(msg, 64);  ;; mode 64: forward remaining gas
    ;; BUG: mode 64 forwards remaining gas, but if this contract consumed
    ;; most of it, the marketplace won't have enough for its own message to the seller
}
```

### Secure FunC Code
```func
() process_order(slice buyer, int item_id, int price) impure {
    ;; FIX: Calculate minimum gas needed for the full message chain
    ;; Each hop needs approximately: base_gas + storage_gas + compute_gas
    int gas_per_hop = 50000000;  ;; 0.05 TON per hop
    int total_hops = 3;         ;; marketplace → seller → NFT transfer
    int min_gas = gas_per_hop * total_hops;

    ;; FIX: Ensure sufficient gas before starting the chain
    throw_unless(ERROR_INSUFFICIENT_GAS, msg_value >= min_gas + price);

    var msg = begin_cell()
        .store_uint(0x18, 6)
        .store_slice(marketplace_addr)
        .store_coins(min_gas)   ;; FIX: Attach gas for remaining chain
        .store_uint(0, 1 + 4 + 4 + 64 + 32 + 1 + 1)
        .store_uint(op::finalize_sale, 32)
        .store_uint(item_id, 64)
        .end_cell();
    send_raw_message(msg, 1);   ;; FIX: mode 1 = pay from contract balance
}
```

**Detection**: Trace every multi-message chain. For each hop, verify either explicit TON value is attached or mode 64 is used with a gas reservation check at the entry point.

---

## 3. Unbounded Storage Growth (CRITICAL)

**Impact**: TON contracts pay ongoing **storage fees** based on how much data they store. If users can force unlimited data storage, the contract's balance is slowly drained until it's destroyed.

### Vulnerable FunC Code
```func
;; BUG: Users can store unlimited data in contract's dict
(cell) add_message(cell messages, int sender, cell message_content) {
    ;; No limit on number of entries — each entry costs storage rent
    messages~udict_set(256, sender, message_content);
    return messages;
}

() recv_internal(int balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    int op = in_msg_body~load_uint(32);
    if (op == op::post_message) {
        cell content = in_msg_body~load_ref();
        ;; BUG: Attacker can call this repeatedly with different sender IDs
        ;; Each call adds data → storage fees increase indefinitely
        var (data) = load_data();
        data~add_message(sender, content);
        save_data(data);
    }
}
```

### Secure FunC Code
```func
const int MAX_MESSAGES = 1000;
const int MIN_STORAGE_FEE = 100000000;  ;; 0.1 TON minimum required per entry

() recv_internal(int balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    int op = in_msg_body~load_uint(32);

    if (op == op::post_message) {
        ;; FIX: Require storage deposit from caller
        throw_unless(ERROR_LOW_VALUE, msg_value >= MIN_STORAGE_FEE);

        var (data, count) = load_data();

        ;; FIX: Enforce maximum entry count
        throw_unless(ERROR_STORAGE_FULL, count < MAX_MESSAGES);

        cell content = in_msg_body~load_ref();
        data~udict_set(256, sender, content);
        save_data(data, count + 1);
    }
}
```

---

## 4. Missing Replay Protection (HIGH)

**Impact**: External messages (from off-chain) don't have built-in nonce protection. Without a sequence number (`seqno`), the same signed message can be replayed to execute operations multiple times.

### Vulnerable FunC Code
```func
() recv_external(slice in_msg) impure {
    var signature = in_msg~load_bits(512);
    var hash = slice_hash(in_msg);
    ;; BUG: No seqno — same signed message replayed indefinitely
    throw_unless(35, check_signature(hash, signature, public_key));
    accept_message();  ;; Accept gas payment

    ;; Process the operation (can be replayed!)
    int op = in_msg~load_uint(32);
    process_operation(op, in_msg);
}
```

### Secure FunC Code
```func
() recv_external(slice in_msg) impure {
    var signature = in_msg~load_bits(512);
    var hash = slice_hash(in_msg);
    throw_unless(35, check_signature(hash, signature, public_key));

    ;; FIX: Verify and increment sequence number
    var (stored_seqno, public_key, ...) = load_data();
    var msg_seqno = in_msg~load_uint(32);
    throw_unless(33, msg_seqno == stored_seqno);
    accept_message();

    ;; FIX: Increment seqno BEFORE processing (prevents replay even on failure)
    save_data(stored_seqno + 1, public_key, ...);

    int op = in_msg~load_uint(32);
    process_operation(op, in_msg);
}
```

---

## 5. Carry-Value Attack (HIGH)

**Impact**: In TON, incoming messages carry TON value. If a contract uses the incoming message value to fund outgoing messages without proper accounting, an attacker can manipulate fund flows.

### Vulnerable FunC Code
```func
() recv_internal(int balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    int op = in_msg_body~load_uint(32);

    if (op == op::distribute) {
        ;; BUG: Uses msg_value directly to fund outgoing messages
        ;; Attacker sends a tiny amount but contract forwards its own balance
        send_raw_message(
            build_message(recipient_a, msg_value / 2),
            0  ;; mode 0: pay from contract balance
        );
        send_raw_message(
            build_message(recipient_b, msg_value / 2),
            0
        );
        ;; With mode 0, the msg_value is added to contract balance first,
        ;; then subtracted for outgoing messages. But if msg_value is small
        ;; and contract has accumulated balance, this drains real funds
    }
}
```

### Secure FunC Code
```func
() recv_internal(int balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    int op = in_msg_body~load_uint(32);

    if (op == op::distribute) {
        ;; FIX: Validate incoming value covers outgoing amounts
        int total_out = amount_a + amount_b;
        throw_unless(ERROR_INSUFFICIENT, msg_value >= total_out + GAS_RESERVE);

        ;; FIX: Use mode 1 (pay from incoming value, not contract balance)
        send_raw_message(build_message(recipient_a, amount_a), 1);
        send_raw_message(build_message(recipient_b, amount_b), 1);
    }
}
```

---

## 6. Cell Overflow/Underflow (HIGH)

**Impact**: TVM cells have strict limits: max 1023 bits and 4 references per cell. If serialization exceeds these limits, the transaction fails with an unrecoverable error.

### Vulnerable FunC Code
```func
;; BUG: Packing too much data into a single cell
cell pack_order(int buyer, int seller, int price, int item_id,
                int timestamp, slice metadata, int status, int fee) {
    return begin_cell()
        .store_uint(buyer, 256)       ;; 256 bits
        .store_uint(seller, 256)      ;; 256 bits (total: 512)
        .store_coins(price)           ;; up to 124 bits (total: ~636)
        .store_uint(item_id, 256)     ;; 256 bits (total: ~892)
        .store_uint(timestamp, 64)    ;; 64 bits (total: ~956)
        .store_slice(metadata)        ;; variable — OVERFLOW if metadata > 67 bits!
        .store_uint(status, 8)
        .store_coins(fee)
        .end_cell();
    ;; CRASH: Exceeds 1023-bit cell limit
}
```

### Secure FunC Code
```func
;; FIX: Split data across multiple cells using references
cell pack_order(int buyer, int seller, int price, int item_id,
                int timestamp, slice metadata, int status, int fee) {
    ;; Cell 1: Core fields (fits within 1023 bits)
    cell metadata_cell = begin_cell()
        .store_slice(metadata)
        .store_uint(status, 8)
        .store_coins(fee)
        .end_cell();

    return begin_cell()
        .store_uint(buyer, 256)
        .store_uint(seller, 256)
        .store_coins(price)
        .store_uint(item_id, 256)
        .store_uint(timestamp, 64)
        .store_ref(metadata_cell)     ;; FIX: Store overflow data in child cell
        .end_cell();
}
```

---

## 7. Incorrect Send Mode Flags (HIGH)

**Impact**: `send_raw_message` accepts a mode parameter that controls gas and value behavior. Wrong mode flags can drain the contract balance, destroy the contract, or cause messages to fail.

### Mode Reference
| Mode | Behavior | Danger |
|---|---|---|
| 0 | Pay transfer fee from message value | Safe default |
| 1 | Pay transfer fee from contract balance | May drain contract |
| 2 | Ignore action phase errors | Hides failures |
| 64 | Forward remaining incoming gas | Safe for replies |
| 128 | Forward ALL contract balance | **Drains entire contract** |
| 32 | Destroy contract if balance becomes zero | **Irreversible** |

### Vulnerable FunC Code
```func
;; BUG: mode 128 sends ENTIRE contract balance
send_raw_message(msg, 128);  ;; Contract is now empty!

;; BUG: mode 128 + 32 sends everything AND destroys the contract
send_raw_message(msg, 128 + 32);  ;; Contract permanently deleted!

;; BUG: mode 2 ignores errors — message silently fails
send_raw_message(msg, 2);  ;; No error if message can't be sent
```

### Secure Patterns
```func
;; Reply to sender: forward remaining gas
send_raw_message(reply_msg, 64);  ;; mode 64: carry remaining gas

;; Transfer specific amount from contract
send_raw_message(transfer_msg, 1);  ;; mode 1: pay fees separately

;; NEVER use mode 128 unless deliberately emptying contract
;; NEVER use mode 32 unless deliberately destroying contract
;; NEVER use mode 2 unless you explicitly want silent failure
```

---

## 8. Missing accept_message() (MEDIUM)

**Impact**: External messages (from outside the blockchain) must call `accept_message()` to pay gas from the contract's balance. Without it, the external message is silently discarded — no error, no event, nothing.

### Vulnerable FunC Code
```func
() recv_external(slice in_msg) impure {
    var signature = in_msg~load_bits(512);
    ;; BUG: If signature check fails, no accept_message() was called
    ;; The entire operation silently vanishes
    throw_unless(35, check_signature(hash, signature, public_key));

    ;; BUG: accept_message after throw means failed messages are invisible
    accept_message();
}
```

### Secure FunC Code
```func
() recv_external(slice in_msg) impure {
    var signature = in_msg~load_bits(512);
    var hash = slice_hash(in_msg);

    ;; Validate signature
    throw_unless(35, check_signature(hash, signature, public_key));

    ;; FIX: accept_message() immediately after validation
    ;; This ensures the contract pays gas and the message is recorded
    accept_message();

    ;; Now process the operation (gas is secured)
    process_operation(in_msg);
}
```

---

## 9. Sharded Message Ordering (MEDIUM)

**Impact**: TON is sharded — contracts on different shards process messages in parallel. If a protocol assumes messages arrive in the order they were sent, it can enter inconsistent states.

### Example
```
Contract A (Shard 1) sends two messages:
  1. Message X → Contract B (Shard 2)
  2. Message Y → Contract C (Shard 3)

Contract B sends: Message Z → Contract C (Shard 3)

Expected order at Contract C: Y, Z
Actual order at Contract C: Z might arrive before Y!

If Contract C assumes Y will be processed before Z, it breaks.
```

### Mitigation
- Never assume cross-shard message ordering
- Use explicit state flags or sequence numbers for multi-step operations
- Design idempotent message handlers

---

## 10. Workchain ID Validation (MEDIUM)

**Impact**: TON addresses include a workchain ID. If a contract doesn't validate the workchain, it can send messages to invalid addresses on non-existent workchains, losing funds.

### FunC Detection
```func
;; BUG: Not validating workchain ID
(slice) parse_address(slice addr) {
    (int wc, int hash) = addr~load_msg_addr().parse_std_addr();
    ;; Missing: throw_unless(ERROR_WRONG_WC, wc == 0);
    ;; wc should be 0 (basechain) or -1 (masterchain)
    return addr;
}

;; FIX:
(int, int) parse_and_validate_address(slice addr) {
    (int wc, int hash) = parse_std_addr(addr);
    throw_unless(333, (wc == 0) | (wc == -1));
    return (wc, hash);
}
```

---

## TON Audit Checklist

### Critical Checks
- [ ] All `recv_internal` handlers check bounced flag (`flags & 1`) and process bounces appropriately
- [ ] Sufficient gas attached/forwarded in every message chain hop
- [ ] Storage growth bounded — max entries enforced, storage deposits required
- [ ] External messages implement seqno/nonce for replay protection

### High Checks
- [ ] Incoming message values properly accounted — no carry-value drain
- [ ] Cell serialization verified within 1023-bit / 4-reference limits
- [ ] Send mode flags reviewed (no accidental mode 128/32/2)
- [ ] Workchain ID validated in all address operations

### Medium Checks
- [ ] `accept_message()` called in external handlers after validation
- [ ] No cross-shard ordering assumptions in multi-contract protocols
- [ ] Storage fee impact estimated for contract lifetime
- [ ] Get-methods (off-chain) cannot be used for on-chain decisions

---

## Related Files

- [TON Scanner Overview](../SKILL.md) — Architecture overview, language comparison
- [TON Audit Workflow](../workflows/ton-audit.md) — Step-by-step audit methodology
