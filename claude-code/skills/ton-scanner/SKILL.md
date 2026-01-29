---
name: TON Scanner
description: TON blockchain FunC/Tact smart contract vulnerability scanner with 40+ security patterns
version: 1.0.0
author: Web3 Security Plugin
tags: [ton, func, tact, security, audit, scanner, vulnerability]
---

# TON Scanner Skill

Comprehensive security scanner for TON blockchain smart contracts. Covers both FunC (low-level) and Tact (high-level) languages with TON-specific security patterns.

## Capabilities

- **FunC Analysis**: Low-level TON Virtual Machine patterns
- **Tact Analysis**: High-level contract security
- **Message Handling**: Internal/external message security
- **Gas Management**: Gas-related vulnerabilities
- **Jetton/NFT Standards**: TEP token standard security
- **Sharding Considerations**: Multi-shard operation security

## Vulnerability Categories

### Category 1: Message Handling (MH)

| ID | Pattern | Severity | Type |
|----|---------|----------|------|
| MH-01 | Unbounded Message Handling | High | DoS |
| MH-02 | Missing Bounce Flag Check | High | Logic |
| MH-03 | External Message Replay | Critical | Security |
| MH-04 | Missing Op Code Validation | High | Validation |
| MH-05 | Improper Slice Parsing | High | Parsing |

### Category 2: Access Control (AC)

| ID | Pattern | Severity | Type |
|----|---------|----------|------|
| AC-01 | Missing Sender Validation | Critical | Auth |
| AC-02 | Unprotected Admin Functions | Critical | Auth |
| AC-03 | Improper Address Comparison | High | Auth |
| AC-04 | Missing Workchain Check | Medium | Auth |
| AC-05 | Accept Message Issues | High | Auth |

### Category 3: Gas Management (GS)

| ID | Pattern | Severity | Type |
|----|---------|----------|------|
| GS-01 | Insufficient Gas Reserve | High | DoS |
| GS-02 | Gas Draining Attack | High | DoS |
| GS-03 | Missing Gas Checks | Medium | Safety |
| GS-04 | Unbounded Computation | High | DoS |
| GS-05 | Storage Fee Exhaustion | Medium | DoS |

### Category 4: State Management (ST)

| ID | Pattern | Severity | Type |
|----|---------|----------|------|
| ST-01 | Storage Overflow | High | DoS |
| ST-02 | Incorrect State Loading | High | Logic |
| ST-03 | Missing State Persistence | Critical | Data Loss |
| ST-04 | Dictionary Key Collision | High | Logic |
| ST-05 | Cell Overflow | High | DoS |

### Category 5: Arithmetic (AR)

| ID | Pattern | Severity | Type |
|----|---------|----------|------|
| AR-01 | Integer Overflow | High | Math |
| AR-02 | Integer Underflow | High | Math |
| AR-03 | Division by Zero | High | Math |
| AR-04 | Precision Loss | Medium | Math |
| AR-05 | Incorrect Coin Calculations | Critical | Math |

### Category 6: Token Standards (TK)

| ID | Pattern | Severity | Type |
|----|---------|----------|------|
| TK-01 | Jetton Transfer Validation | Critical | Token |
| TK-02 | NFT Ownership Bypass | Critical | Token |
| TK-03 | Jetton Mint Authority | Critical | Token |
| TK-04 | Missing Balance Check | High | Token |
| TK-05 | Transfer Notification Issues | Medium | Token |

### Category 7: FunC-Specific (FC)

| ID | Pattern | Severity | Type |
|----|---------|----------|------|
| FC-01 | Impure Function Side Effects | Medium | Logic |
| FC-02 | Incorrect Method ID | High | Interface |
| FC-03 | Missing throw_unless | High | Validation |
| FC-04 | Cell Reference Limit | Medium | DoS |
| FC-05 | Improper TVM Exception Handling | High | Safety |

### Category 8: Tact-Specific (TC)

| ID | Pattern | Severity | Type |
|----|---------|----------|------|
| TC-01 | Unhandled Message Types | High | Logic |
| TC-02 | Missing Require Checks | High | Validation |
| TC-03 | Incorrect Trait Implementation | Medium | Logic |
| TC-04 | Map Key Type Issues | Medium | Logic |
| TC-05 | Init Function Security | High | Initialization |

---

## FunC Quick Reference

### Contract Structure

```func
#include "stdlib.fc";

;; Storage layout
;; uint32 seqno
;; uint256 public_key
;; uint64 balance
;; address owner

(int, int, int, slice) load_data() inline {
    slice ds = get_data().begin_parse();
    return (
        ds~load_uint(32),   ;; seqno
        ds~load_uint(256),  ;; public_key
        ds~load_coins(),    ;; balance
        ds~load_msg_addr()  ;; owner
    );
}

() save_data(int seqno, int public_key, int balance, slice owner) impure inline {
    set_data(begin_cell()
        .store_uint(seqno, 32)
        .store_uint(public_key, 256)
        .store_coins(balance)
        .store_slice(owner)
        .end_cell());
}

;; Internal message handler
() recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    slice cs = in_msg_full.begin_parse();
    int flags = cs~load_uint(4);
    
    if (flags & 1) { ;; Bounced message
        return ();
    }
    
    slice sender = cs~load_msg_addr();
    
    int op = in_msg_body~load_uint(32);
    int query_id = in_msg_body~load_uint(64);
    
    ;; Handle operations
    if (op == 0x12345678) {
        ;; Handle operation
        return ();
    }
    
    throw(0xffff); ;; Unknown op
}

;; External message handler
() recv_external(slice in_msg) impure {
    ;; Handle external message
}
```

### Common Secure Patterns

**Sender Validation:**
```func
() recv_internal(...) impure {
    ;; ...
    slice sender = cs~load_msg_addr();
    
    (int seqno, int pubkey, int balance, slice owner) = load_data();
    
    ;; ✅ Validate sender is owner
    throw_unless(401, equal_slices(sender, owner));
    
    ;; ... continue
}
```

**Gas Reservation:**
```func
int min_tons_for_storage() asm "50000000 PUSHINT"; ;; 0.05 TON

() recv_internal(int my_balance, int msg_value, ...) impure {
    ;; ✅ Reserve gas for storage
    raw_reserve(min_tons_for_storage(), 0);
    
    ;; ... operations
    
    ;; Send remaining balance
    send_raw_message(msg, 128); ;; mode 128 = carry remaining balance
}
```

---

## Tact Quick Reference

### Contract Structure

```tact
import "@stdlib/deploy";

message Withdraw {
    amount: Int as coins;
}

message Transfer {
    to: Address;
    amount: Int as coins;
}

contract Vault with Deployable {
    owner: Address;
    balance: Int as coins;

    init(owner: Address) {
        self.owner = owner;
        self.balance = 0;
    }

    receive(msg: Withdraw) {
        // ✅ Validate sender
        require(sender() == self.owner, "Only owner");
        require(self.balance >= msg.amount, "Insufficient balance");
        
        self.balance = self.balance - msg.amount;
        
        send(SendParameters{
            to: sender(),
            value: msg.amount,
            mode: SendRemainingValue
        });
    }

    receive(msg: Transfer) {
        require(sender() == self.owner, "Only owner");
        require(self.balance >= msg.amount, "Insufficient");
        
        self.balance = self.balance - msg.amount;
        
        send(SendParameters{
            to: msg.to,
            value: msg.amount,
            mode: SendRemainingValue
        });
    }

    get fun getBalance(): Int {
        return self.balance;
    }
}
```

---

## Protocol-Specific Checklists

### Jetton (TEP-74)

```markdown
## Jetton Minter Checklist
- [ ] Only authorized can mint
- [ ] Total supply tracked correctly
- [ ] Mint notification sent to wallet
- [ ] Proper gas forwarding

## Jetton Wallet Checklist
- [ ] Owner validation on transfer
- [ ] Balance checked before transfer
- [ ] Transfer notification sent
- [ ] Burn properly reduces supply
- [ ] Forward payload handled
```

### NFT (TEP-62)

```markdown
## NFT Collection Checklist
- [ ] Item index properly managed
- [ ] Owner can deploy new items
- [ ] Royalty info correct
- [ ] Metadata properly stored

## NFT Item Checklist
- [ ] Ownership correctly tracked
- [ ] Transfer validates current owner
- [ ] Collection address verified
- [ ] Sale/auction logic secure
```

---

## Analysis Commands

```bash
# FunC compilation
func -o output.fif contract.fc

# Tact compilation
tact --compile contract.tact

# Blueprint (test framework)
npx blueprint build
npx blueprint test
```

### Grep Patterns

```bash
# FunC patterns
grep -rn "recv_internal\|recv_external" *.fc
grep -rn "throw_unless\|throw_if\|throw" *.fc
grep -rn "send_raw_message\|send_message" *.fc
grep -rn "load_msg_addr\|load_coins" *.fc
grep -rn "raw_reserve" *.fc
grep -rn "accept_message" *.fc

# Tact patterns
grep -rn "receive(" *.tact
grep -rn "require(" *.tact
grep -rn "sender()" *.tact
grep -rn "send(" *.tact
grep -rn "self\." *.tact
```

---

## Resources

- [ton-patterns.md](resources/ton-patterns.md) - Detailed vulnerability patterns
- [func-security.md](resources/func-security.md) - FunC-specific security

## Workflows

- [ton-audit.md](workflows/ton-audit.md) - Complete TON contract audit process

---

## Integration with Cyfrin Solodit

```markdown
## Search Queries for TON Findings

- "ton" - All TON findings
- "func" - FunC-specific issues
- "tact" - Tact-specific issues
- "jetton" - Jetton token issues
- "nft ton" - TON NFT issues
```
