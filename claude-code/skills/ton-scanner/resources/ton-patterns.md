# TON Vulnerability Patterns

Detailed vulnerability patterns for TON blockchain smart contracts.

---

## MH-01: Unbounded Message Handling

### Description
Processing messages without limiting computation or storage, allowing DoS.

### Vulnerable Code (FunC)
```func
() recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    ;; ❌ Processing unbounded data from message
    int count = in_msg_body~load_uint(32);
    int i = 0;
    while (i < count) {  ;; Attacker sets count = huge number
        ;; Process each item
        i += 1;
    }
}
```

### Secure Code
```func
int max_items() asm "100 PUSHINT";

() recv_internal(...) impure {
    int count = in_msg_body~load_uint(32);
    
    ;; ✅ Bound the processing
    throw_if(400, count > max_items());
    
    int i = 0;
    while (i < count) {
        ;; Process each item
        i += 1;
    }
}
```

---

## MH-02: Missing Bounce Flag Check

### Description
Not handling bounced messages can lead to double-spending or state corruption.

### Vulnerable Code
```func
() recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    slice cs = in_msg_full.begin_parse();
    int flags = cs~load_uint(4);
    ;; ❌ Not checking bounce flag
    
    slice sender = cs~load_msg_addr();
    int op = in_msg_body~load_uint(32);
    
    if (op == op::transfer) {
        ;; Process transfer - but this might be a bounced message!
    }
}
```

### Secure Code
```func
() recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    slice cs = in_msg_full.begin_parse();
    int flags = cs~load_uint(4);
    
    ;; ✅ Check bounce flag
    if (flags & 1) {
        ;; This is a bounced message
        on_bounce(in_msg_body);
        return ();
    }
    
    slice sender = cs~load_msg_addr();
    int op = in_msg_body~load_uint(32);
    
    if (op == op::transfer) {
        ;; Safe to process
    }
}

() on_bounce(slice in_msg_body) impure {
    ;; Handle bounce - refund state, etc.
    int op = in_msg_body~load_uint(32);
    if (op == op::transfer) {
        ;; Restore balance that was deducted
    }
}
```

---

## MH-03: External Message Replay

### Description
External messages can be replayed if sequence number not properly checked.

### Vulnerable Code
```func
() recv_external(slice in_msg) impure {
    var signature = in_msg~load_bits(512);
    var hash = slice_hash(in_msg);
    
    (int seqno, int pubkey, _, _) = load_data();
    
    ;; ✅ Check signature
    throw_unless(401, check_signature(hash, signature, pubkey));
    
    ;; ❌ Not checking seqno
    accept_message();
    
    ;; Process message...
}
```

### Secure Code
```func
() recv_external(slice in_msg) impure {
    var signature = in_msg~load_bits(512);
    var cs = in_msg;
    var hash = slice_hash(cs);
    
    var (msg_seqno, valid_until) = (cs~load_uint(32), cs~load_uint(32));
    
    (int stored_seqno, int pubkey, _, _) = load_data();
    
    ;; ✅ Check sequence number
    throw_unless(33, msg_seqno == stored_seqno);
    
    ;; ✅ Check expiration
    throw_unless(34, valid_until > now());
    
    ;; ✅ Check signature
    throw_unless(35, check_signature(hash, signature, pubkey));
    
    accept_message();
    
    ;; ✅ Increment seqno
    save_data(stored_seqno + 1, pubkey, ...);
    
    ;; Process message...
}
```

---

## AC-01: Missing Sender Validation

### Description
Not validating message sender before processing privileged operations.

### Vulnerable Code
```func
() recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    int op = in_msg_body~load_uint(32);
    
    if (op == op::withdraw_all) {
        ;; ❌ Anyone can withdraw!
        (_, _, int balance, slice owner) = load_data();
        
        send_raw_message(begin_cell()
            .store_uint(0x18, 6)
            .store_slice(owner)
            .store_coins(balance)
            .end_cell(), 0);
    }
}
```

### Secure Code
```func
() recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    slice cs = in_msg_full.begin_parse();
    int flags = cs~load_uint(4);
    slice sender = cs~load_msg_addr();
    
    int op = in_msg_body~load_uint(32);
    
    if (op == op::withdraw_all) {
        (_, _, int balance, slice owner) = load_data();
        
        ;; ✅ Validate sender is owner
        throw_unless(401, equal_slices(sender, owner));
        
        send_raw_message(begin_cell()
            .store_uint(0x18, 6)
            .store_slice(owner)
            .store_coins(balance)
            .end_cell(), 0);
    }
}
```

---

## AC-03: Improper Address Comparison

### Description
Incorrect comparison of addresses leading to auth bypass.

### Vulnerable Code
```func
int equal_addr(slice a, slice b) {
    ;; ❌ Only comparing first bits, not full address
    return a~load_uint(256) == b~load_uint(256);
}
```

### Secure Code
```func
;; ✅ Use built-in equal_slices for full comparison
int addr_equals(slice a, slice b) {
    return equal_slices(a, b);
}

;; Or compare with workchain
int addr_equals_full(slice a, slice b) {
    (int wc_a, int hash_a) = parse_std_addr(a);
    (int wc_b, int hash_b) = parse_std_addr(b);
    return (wc_a == wc_b) & (hash_a == hash_b);
}
```

---

## GS-01: Insufficient Gas Reserve

### Description
Not reserving enough gas for storage fees, contract becomes frozen.

### Vulnerable Code
```func
() recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    ;; ❌ No gas reservation
    
    ;; Process and send all balance
    send_raw_message(msg, 128); ;; Mode 128 = send all remaining
}
```

### Secure Code
```func
const min_storage_fee = 10000000; ;; 0.01 TON

() recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    ;; ✅ Reserve gas for storage
    raw_reserve(min_storage_fee, 0);
    
    ;; Process and send remaining
    send_raw_message(msg, 128); ;; Safe - storage fee reserved
}
```

---

## GS-04: Unbounded Computation

### Description
Operations that can consume unlimited gas, making contract DoS-able.

### Vulnerable Code
```func
() process_dict(cell dict) impure {
    ;; ❌ Iterating entire dictionary
    int key = -1;
    do {
        (key, slice val, int found) = dict.udict_get_next?(256, key);
        if (found) {
            ;; Process each entry
        }
    } until (~ found);
}
```

### Secure Code
```func
const MAX_ITERATIONS = 20;

() process_dict_bounded(cell dict, int start_key) impure {
    int key = start_key;
    int count = 0;
    
    ;; ✅ Bounded iteration
    while (count < MAX_ITERATIONS) {
        (key, slice val, int found) = dict.udict_get_next?(256, key);
        ifnot (found) {
            return ();
        }
        ;; Process entry
        count += 1;
    }
    
    ;; If more entries, schedule continuation
    if (key >= 0) {
        ;; Send message to self to continue processing
    }
}
```

---

## ST-03: Missing State Persistence

### Description
Modifying state but not saving to storage.

### Vulnerable Code
```func
() process_deposit(int amount) impure {
    (int seqno, int pubkey, int balance, slice owner) = load_data();
    
    ;; ❌ Balance updated but never saved!
    balance += amount;
    
    ;; Missing: save_data(seqno, pubkey, balance, owner);
}
```

### Secure Code
```func
() process_deposit(int amount) impure {
    (int seqno, int pubkey, int balance, slice owner) = load_data();
    
    balance += amount;
    
    ;; ✅ Save updated state
    save_data(seqno, pubkey, balance, owner);
}
```

---

## TK-01: Jetton Transfer Validation

### Description
Jetton wallet not properly validating transfer requests.

### Vulnerable Code
```func
() recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    slice cs = in_msg_full.begin_parse();
    int flags = cs~load_uint(4);
    slice sender = cs~load_msg_addr();
    
    int op = in_msg_body~load_uint(32);
    
    if (op == op::transfer) {
        int query_id = in_msg_body~load_uint(64);
        int amount = in_msg_body~load_coins();
        slice destination = in_msg_body~load_msg_addr();
        
        ;; ❌ Not checking sender is owner!
        ;; Anyone can transfer from this wallet
        
        do_transfer(amount, destination, ...);
    }
}
```

### Secure Code
```func
() recv_internal(...) impure {
    slice cs = in_msg_full.begin_parse();
    int flags = cs~load_uint(4);
    slice sender = cs~load_msg_addr();
    
    int op = in_msg_body~load_uint(32);
    
    if (op == op::transfer) {
        int query_id = in_msg_body~load_uint(64);
        int amount = in_msg_body~load_coins();
        slice destination = in_msg_body~load_msg_addr();
        
        (int balance, slice owner, slice jetton_master, cell code) = load_data();
        
        ;; ✅ Verify sender is wallet owner
        throw_unless(401, equal_slices(sender, owner));
        
        ;; ✅ Verify sufficient balance
        throw_unless(402, balance >= amount);
        
        ;; Update balance and proceed
        save_data(balance - amount, owner, jetton_master, code);
        do_transfer(amount, destination, ...);
    }
}
```

---

## FC-01: Impure Function Side Effects

### Description
Functions marked impure modifying global state unexpectedly.

### Vulnerable Code
```func
;; ❌ Inline function modifying global state
(int, int) get_balances() inline {
    slice ds = get_data().begin_parse();
    int a = ds~load_coins();
    int b = ds~load_coins();
    
    ;; Side effect: ds has been modified!
    return (a, b);
}

() some_function() impure {
    (int a, int b) = get_balances();
    ;; If get_balances is called again, state might be inconsistent
}
```

### Secure Code
```func
;; ✅ Pure function, no side effects
(int, int) get_balances() inline {
    slice ds = get_data().begin_parse();
    return (ds~load_coins(), ds~load_coins());
}

;; Or clearly mark as impure and document
(int, int) load_and_consume_balances() impure inline {
    ;; Documented: this consumes the storage slice
    slice ds = get_data().begin_parse();
    return (ds~load_coins(), ds~load_coins());
}
```

---

## TC-01: Unhandled Message Types (Tact)

### Description
Contract doesn't handle all expected message types.

### Vulnerable Code
```tact
contract Vault {
    receive(msg: Deposit) {
        // Handle deposit
    }
    
    receive(msg: Withdraw) {
        // Handle withdraw
    }
    
    // ❌ Missing: What happens with unknown messages?
    // They will be silently ignored or cause issues
}
```

### Secure Code
```tact
contract Vault {
    receive(msg: Deposit) {
        // Handle deposit
    }
    
    receive(msg: Withdraw) {
        // Handle withdraw
    }
    
    // ✅ Handle empty messages
    receive() {
        // Handle TON deposits without data
    }
    
    // ✅ Fallback for unknown messages
    receive(msg: Slice) {
        // Log or handle unknown messages
        // Could revert or accept
    }
    
    // ✅ Handle bounced messages
    bounced(msg: bounced<Withdraw>) {
        // Restore state on failed withdrawal
    }
}
```

---

## TC-02: Missing Require Checks (Tact)

### Description
Not validating inputs with require statements.

### Vulnerable Code
```tact
receive(msg: Transfer) {
    // ❌ No validation
    self.balance = self.balance - msg.amount;
    
    send(SendParameters{
        to: msg.to,
        value: msg.amount,
        mode: SendRemainingValue
    });
}
```

### Secure Code
```tact
receive(msg: Transfer) {
    // ✅ Validate sender
    require(sender() == self.owner, "Only owner");
    
    // ✅ Validate amount
    require(msg.amount > 0, "Zero amount");
    require(self.balance >= msg.amount, "Insufficient balance");
    
    // ✅ Validate destination
    require(msg.to != myAddress(), "Cannot transfer to self");
    
    self.balance = self.balance - msg.amount;
    
    send(SendParameters{
        to: msg.to,
        value: msg.amount,
        mode: SendRemainingValue
    });
}
```
