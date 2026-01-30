# TON Contract Audit Workflow

Systematic workflow for auditing TON blockchain smart contracts (FunC and Tact).

---

## Phase 1: Setup (30 minutes)

### 1.1 Environment Setup

**FunC:**
```bash
git clone [repo]
cd [repo]

# Compile FunC
func -o output.fif contract.fc

# Or with Blueprint
npx blueprint build
npx blueprint test
```

**Tact:**
```bash
git clone [repo]
cd [repo]

# Compile Tact
tact --compile contract.tact

# Or with Blueprint
npx blueprint build
npx blueprint test
```

### 1.2 Scope Mapping

```markdown
## Audit Scope

**Language:** FunC / Tact
**Commit:** [hash]

### Entry Points
| Entry | Type | Purpose |
|-------|------|---------|
| recv_internal | Internal messages | Main logic |
| recv_external | External messages | User txs |

### Operations (Op Codes)
| Op Code | Name | Access |
|---------|------|--------|
| 0x01 | Transfer | Owner |
| 0x02 | Deposit | Anyone |
| 0x03 | UpdateConfig | Admin |

### Storage Layout
| Bits | Type | Name | Purpose |
|------|------|------|---------|
| 32 | uint | seqno | Replay protection |
| 256 | uint | pubkey | Signature verification |
| var | coins | balance | Contract balance |
| 267 | addr | owner | Owner address |
```

---

## Phase 2: Message Handler Analysis (2-3 hours)

### 2.1 recv_internal Analysis

```markdown
## Internal Message Handler

### Message Parsing
- [ ] Flags extracted correctly
- [ ] Bounce flag checked
- [ ] Sender address parsed
- [ ] Op code extracted
- [ ] Query ID extracted (if applicable)

### Op Code Switch
| Op | Handler | Auth | Validated? |
|----|---------|------|------------|
| 0x01 | do_transfer | Owner |  |
| 0x02 | do_deposit | Anyone |  |
| else | throw | N/A |  |

### Bounce Handling
- [ ] Bounce flag detected
- [ ] Bounced messages handled appropriately
- [ ] State restored on bounce
```

### 2.2 recv_external Analysis

```markdown
## External Message Handler

### Replay Protection
- [ ] Sequence number checked
- [ ] Sequence number incremented after accept

### Signature Verification
- [ ] Signature extracted
- [ ] Message hash computed correctly
- [ ] check_signature called
- [ ] Throws on invalid signature

### Timing
- [ ] Valid_until checked (if applicable)
- [ ] Uses now() correctly
```

---

## Phase 3: Access Control Audit (1-2 hours)

### 3.1 Permission Matrix

```markdown
| Operation | Expected Auth | Verified? | Location |
|-----------|---------------|-----------|----------|
| transfer | Owner |  | line 45 |
| withdraw | Owner |  | line 78 |
| update_config | Admin |  ISSUE | line 112 |
| get_balance | Anyone | N/A | getter |
```

### 3.2 Address Validation

```func
;; Check these patterns are correctly implemented:

;; FunC: Owner check
throw_unless(401, equal_slices(sender, owner));

;; FunC: Workchain check (optional)
(int wc, int hash) = parse_std_addr(sender);
throw_unless(402, wc == 0); ;; Basechain only
```

```tact
// Tact: Owner check
require(sender() == self.owner, "Not owner");
```

---

## Phase 4: Gas Management (1-2 hours)

### 4.1 Gas Analysis

```markdown
## Gas Security

### Storage Reservation
- [ ] raw_reserve called before sends
- [ ] Minimum reserve amount reasonable
- [ ] Storage fees covered long-term

### Gas Limits
| Operation | Bounded? | Max Iterations |
|-----------|----------|----------------|
| Loop A |  | 100 |
| Dict iteration |  ISSUE | Unbounded |

### Send Modes
| Location | Mode | Purpose |
|----------|------|---------|
| line 45 | 0 | Regular send |
| line 78 | 64 | Carry remaining value |
| line 112 | 128 | Carry all balance |
```

### 4.2 Gas Patterns

```func
;;  Proper gas reservation
const min_storage = 50000000; ;; 0.05 TON

() process() impure {
    raw_reserve(min_storage, 0);
    ;; ... operations
    send_raw_message(msg, 128); ;; Safe with reservation
}

;;  Bounded loops
const MAX_ITER = 50;
int i = 0;
while ((i < count) & (i < MAX_ITER)) {
    ;; Process
    i += 1;
}
```

---

## Phase 5: State Management (1-2 hours)

### 5.1 Storage Analysis

```markdown
## Storage Layout

### Current Layout
| Offset | Bits | Type | Name |
|--------|------|------|------|
| 0 | 32 | uint | seqno |
| 32 | 256 | uint | pubkey |
| 288 | var | coins | balance |
| ... | 267 | addr | owner |

### Load/Save Consistency
- [ ] load_data() matches save_data() layout
- [ ] All fields loaded in same order as saved
- [ ] No fields missing in save

### State Updates
| Function | Loads? | Modifies? | Saves? |
|----------|--------|-----------|--------|
| transfer |  |  balance |  |
| deposit |  |  balance |  ISSUE |
```

### 5.2 Dictionary Security

```markdown
## Dictionary/Map Analysis

| Dict | Key Type | Key Bits | Collision Risk |
|------|----------|----------|----------------|
| users | address | 256 | Low |
| items | uint64 | 64 | Medium |
```

---

## Phase 6: Arithmetic Review (1 hour)

### 6.1 Operation Inventory

```markdown
| Location | Operation | Type | Safe? |
|----------|-----------|------|-------|
| L45 | a + b | coins |  No check |
| L78 | a - b | int |  checked |
| L112 | a * b | int |  overflow |
```

### 6.2 TON-Specific Math

```func
;;  Safe subtraction with check
throw_if(400, balance < amount);
balance -= amount;

;;  Coin validation
throw_if(401, amount <= 0);
throw_if(402, amount > max_amount);
```

---

## Phase 7: Token Standard Audit (if applicable)

### 7.1 Jetton Audit

```markdown
## Jetton Master

### Mint Security
- [ ] Only authorized can mint
- [ ] Total supply updated
- [ ] Wallet deployed correctly

### Metadata
- [ ] URI correct format
- [ ] Decimals correct

## Jetton Wallet

### Transfer Security
- [ ] Owner validation
- [ ] Balance check
- [ ] Notification sent correctly
- [ ] Gas forwarding correct

### Burn Security
- [ ] Owner validation
- [ ] Balance reduced
- [ ] Master notified
```

### 7.2 NFT Audit

```markdown
## NFT Collection

### Item Deployment
- [ ] Index managed correctly
- [ ] Only owner can deploy
- [ ] Init data correct

## NFT Item

### Transfer
- [ ] Ownership verified
- [ ] New owner set correctly
- [ ] Notification sent
```

---

## Phase 8: FunC-Specific Checks (if FunC)

```markdown
## FunC Security

### Function Modifiers
- [ ] impure on state-modifying functions
- [ ] inline on helper functions
- [ ] method_id on getters

### Exception Handling
- [ ] throw_unless for preconditions
- [ ] throw_if for error conditions
- [ ] Proper error codes

### Slice/Cell Handling
- [ ] Slices fully consumed or explicitly ended
- [ ] Cell reference count < 4
- [ ] Bit count < 1023
```

---

## Phase 9: Tact-Specific Checks (if Tact)

```markdown
## Tact Security

### Message Handlers
- [ ] All expected messages handled
- [ ] Empty receive() implemented
- [ ] Bounced handlers implemented

### State Management
- [ ] All fields initialized in init()
- [ ] State changes saved automatically

### Trait Security
- [ ] Traits correctly implemented
- [ ] Override functions secure
```

---

## Phase 10: Testing (2-3 hours)

### Blueprint Tests

```typescript
import { Blockchain, SandboxContract } from '@ton/sandbox';
import { toNano } from '@ton/core';
import { MyContract } from '../wrappers/MyContract';

describe('Security Tests', () => {
    let blockchain: Blockchain;
    let contract: SandboxContract<MyContract>;
    let owner: SandboxContract<TreasuryContract>;
    let attacker: SandboxContract<TreasuryContract>;

    beforeEach(async () => {
        blockchain = await Blockchain.create();
        owner = await blockchain.treasury('owner');
        attacker = await blockchain.treasury('attacker');
        
        contract = blockchain.openContract(
            MyContract.createFromConfig({
                owner: owner.address,
            }, code)
        );
    });

    it('should reject unauthorized withdrawal', async () => {
        const result = await contract.sendWithdraw(
            attacker.getSender(),
            toNano('1')
        );
        
        expect(result.transactions).toHaveTransaction({
            from: attacker.address,
            to: contract.address,
            success: false,
            exitCode: 401, // Unauthorized
        });
    });

    it('should handle bounce correctly', async () => {
        // Test bounce handling
    });
});
```

---

## Quick Grep Audit

```bash
# Entry points
grep -rn "recv_internal\|recv_external" *.fc

# Throws
grep -rn "throw_unless\|throw_if\|throw(" *.fc

# Sends
grep -rn "send_raw_message\|send_message" *.fc

# Storage
grep -rn "get_data\|set_data\|load_data\|save_data" *.fc

# Gas
grep -rn "raw_reserve\|accept_message" *.fc

# Address handling
grep -rn "equal_slices\|parse_std_addr\|load_msg_addr" *.fc

# Tact requires
grep -rn "require(" *.tact

# Tact receivers
grep -rn "receive(" *.tact
```

---

## Audit Completion Checklist

### Messages
- [ ] All op codes handled
- [ ] Unknown ops rejected
- [ ] Bounce flag checked
- [ ] Sender validated

### Access Control
- [ ] Owner functions protected
- [ ] Admin functions protected
- [ ] Address comparison correct

### Gas
- [ ] Storage fees reserved
- [ ] Loops bounded
- [ ] Send modes appropriate

### State
- [ ] Load/save consistent
- [ ] All modifications saved
- [ ] No data corruption paths

### Tokens (if applicable)
- [ ] Transfer validation
- [ ] Balance checks
- [ ] Notifications correct

### Testing
- [ ] Unit tests pass
- [ ] Attack tests written
- [ ] Edge cases covered

