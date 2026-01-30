# L1-L2 Messaging Security

Comprehensive guide to securing cross-layer messaging between Ethereum (L1) and StarkNet (L2).

---

## Messaging Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        ETHEREUM (L1)                        │
│  ┌─────────────────┐         ┌─────────────────────────┐   │
│  │   L1 Contract   │ ──────► │    StarkNet Core        │   │
│  │   (Bridge)      │ ◄────── │    (Message Queues)     │   │
│  └─────────────────┘         └─────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                          │  ▲
                          ▼  │
┌─────────────────────────────────────────────────────────────┐
│                       STARKNET (L2)                         │
│  ┌─────────────────┐         ┌─────────────────────────┐   │
│  │   L2 Contract   │ ◄────── │    Sequencer            │   │
│  │   (Bridge)      │ ──────► │    (Proof Generation)   │   │
│  └─────────────────┘         └─────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## L1 → L2 Messages

### Flow

1. L1 contract calls `starknetCore.sendMessageToL2()`
2. Message added to L1→L2 queue
3. Sequencer includes message in L2 block
4. L1 handler invoked on L2 contract
5. Message automatically consumed (one-time)

### L1 Side (Solidity)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IStarknetCore {
    function sendMessageToL2(
        uint256 toAddress,
        uint256 selector,
        uint256[] calldata payload
    ) external payable returns (bytes32 msgHash, uint256 nonce);
}

contract L1Bridge {
    IStarknetCore public starknetCore;
    uint256 public l2Contract;
    uint256 constant DEPOSIT_SELECTOR = 0x...; // sn_keccak("handle_deposit")
    
    function depositToL2(
        uint256 l2Recipient,
        uint256 amount
    ) external payable {
        // 1. Lock tokens on L1
        // ... transfer logic
        
        // 2. Build payload
        uint256[] memory payload = new uint256[](2);
        payload[0] = l2Recipient;
        payload[1] = amount;
        
        // 3. Send message to L2
        starknetCore.sendMessageToL2{value: msg.value}(
            l2Contract,
            DEPOSIT_SELECTOR,
            payload
        );
    }
}
```

### L2 Side (Cairo)

```cairo
use starknet::ContractAddress;

#[starknet::contract]
mod L2Bridge {
    use starknet::get_caller_address;
    
    #[storage]
    struct Storage {
        l1_bridge: felt252,  // Expected L1 contract
    }
    
    // L1 Handler - receives messages from L1
    #[l1_handler]
    fn handle_deposit(
        ref self: ContractState,
        from_address: felt252,  // L1 sender
        recipient: ContractAddress,
        amount: u256
    ) {
        // CRITICAL: Verify L1 sender
        assert(from_address == self.l1_bridge.read(), 'Invalid L1 sender');
        
        // CRITICAL: Validate recipient
        assert(!recipient.is_zero(), 'Invalid recipient');
        
        // CRITICAL: Validate amount
        assert(amount > 0, 'Invalid amount');
        
        // Process deposit
        self._mint(recipient, amount);
        
        // Emit event
        self.emit(DepositHandled { 
            from_l1: from_address, 
            recipient, 
            amount 
        });
    }
}
```

### Security Checklist - L1 → L2

- [ ] **L1 sender verified**: Always check `from_address` matches expected L1 contract
- [ ] **Payload validated**: All parameters validated for range and validity
- [ ] **Zero address check**: Recipients checked for zero address
- [ ] **Amount validation**: Amounts > 0, within expected bounds
- [ ] **Event emission**: Events emitted for off-chain tracking
- [ ] **Selector correct**: L1 using correct function selector

---

## L2 → L1 Messages

### Flow

1. L2 contract calls `send_message_to_l1_syscall()`
2. Message hash included in state diff
3. State diff proven on L1 (may take hours)
4. L1 contract calls `starknetCore.consumeMessageFromL2()`
5. Message consumed (one-time, must match exactly)

### L2 Side (Cairo)

```cairo
use starknet::send_message_to_l1_syscall;

#[starknet::contract]
mod L2Bridge {
    #[storage]
    struct Storage {
        l1_contract: felt252,
        message_nonce: u256,
    }
    
    fn withdraw_to_l1(
        ref self: ContractState,
        l1_recipient: felt252,
        amount: u256
    ) {
        let caller = get_caller_address();
        
        // 1. Validate
        assert(!caller.is_zero(), 'Invalid caller');
        assert(amount > 0, 'Invalid amount');
        
        // 2. Burn tokens on L2
        self._burn(caller, amount);
        
        // 3. Get nonce for ordering
        let nonce = self.message_nonce.read();
        self.message_nonce.write(nonce + 1);
        
        // 4. Build payload
        // Message format must match L1 expectation exactly
        let mut payload = array![];
        payload.append(l1_recipient);
        payload.append(amount.low.into());
        payload.append(amount.high.into());
        payload.append(nonce.low.into());
        
        // 5. Send to L1
        send_message_to_l1_syscall(
            self.l1_contract.read(),
            payload.span()
        ).unwrap();
        
        // 6. Emit event
        self.emit(WithdrawInitiated {
            user: caller,
            l1_recipient,
            amount,
            nonce
        });
    }
}
```

### L1 Side (Solidity)

```solidity
interface IStarknetCore {
    function consumeMessageFromL2(
        uint256 fromAddress,
        uint256[] calldata payload
    ) external returns (bytes32);
}

contract L1Bridge {
    IStarknetCore public starknetCore;
    uint256 public l2Contract;
    
    // Track processed withdrawals to prevent replay
    mapping(bytes32 => bool) public processedWithdrawals;
    
    function completeWithdrawal(
        address recipient,
        uint256 amount,
        uint256 nonce
    ) external {
        // 1. Build payload (must match L2 exactly)
        uint256[] memory payload = new uint256[](4);
        payload[0] = uint256(uint160(recipient));
        payload[1] = amount & type(uint128).max;  // low
        payload[2] = amount >> 128;               // high
        payload[3] = nonce;
        
        // 2. Compute withdrawal hash for replay protection
        bytes32 withdrawalHash = keccak256(
            abi.encodePacked(recipient, amount, nonce)
        );
        
        // 3. Check not already processed
        require(!processedWithdrawals[withdrawalHash], "Already processed");
        processedWithdrawals[withdrawalHash] = true;
        
        // 4. Consume message from StarkNet
        // This will revert if message doesn't exist
        starknetCore.consumeMessageFromL2(l2Contract, payload);
        
        // 5. Transfer tokens to recipient
        // ... transfer logic
    }
}
```

### Security Checklist - L2 → L1

- [ ] **Tokens burned before message**: Prevent double-spend
- [ ] **Nonce included**: For ordering and replay protection
- [ ] **Payload format exact match**: L1 and L2 must agree on format
- [ ] **L1 replay protection**: Track consumed withdrawals by hash
- [ ] **Message consumption verified**: StarkNet core handles existence check
- [ ] **Events emitted**: Both L2 initiation and L1 completion

---

## Common Vulnerabilities

### 1. Missing L1 Origin Verification

```cairo
// ❌ VULNERABLE - No sender check
#[l1_handler]
fn handle_deposit(
    ref self: ContractState,
    from_address: felt252,  // Ignored!
    amount: u256
) {
    // Any L1 address can trigger this
    self._mint(get_caller_address(), amount);
}

// ✅ SECURE
#[l1_handler]
fn handle_deposit(
    ref self: ContractState,
    from_address: felt252,
    amount: u256
) {
    assert(from_address == self.l1_bridge.read(), 'Unknown sender');
    // ... continue
}
```

### 2. Payload Mismatch

```cairo
// L2 sends with this format:
let payload = array![recipient, amount.low, amount.high];

// L1 expects this format (WRONG ORDER):
// payload[0] = amount
// payload[1] = recipient

// Message consumption will fail or process wrong data!
```

### 3. Missing L1 Replay Protection

```solidity
// ❌ VULNERABLE - No replay tracking on L1
function completeWithdrawal(uint256[] calldata payload) external {
    starknetCore.consumeMessageFromL2(l2Contract, payload);
    // What if message already processed by different means?
    transfer(payload);
}

// ✅ SECURE - Track processed messages
mapping(bytes32 => bool) public processed;

function completeWithdrawal(uint256[] calldata payload) external {
    bytes32 hash = keccak256(abi.encodePacked(payload));
    require(!processed[hash], "Already processed");
    processed[hash] = true;
    
    starknetCore.consumeMessageFromL2(l2Contract, payload);
    transfer(payload);
}
```

### 4. Message Frontrunning

```
Attack:
1. User initiates withdrawal on L2
2. Attacker sees pending L2→L1 message
3. Attacker calls completeWithdrawal before user
4. Tokens sent to wrong address if recipient not verified

Defense:
- Include caller verification in payload
- Or bind recipient to msg.sender on L1
```

### 5. Timing Assumptions

```
L2 → L1 messages require:
1. L2 block finalization
2. State diff generation
3. Proof submission to L1
4. L1 block confirmation

Total time: Hours to days

Don't assume messages arrive quickly!
```

---

## Message Hash Calculation

### L1 → L2 Message Hash

```solidity
// StarkNet calculates:
bytes32 msgHash = keccak256(
    abi.encodePacked(
        uint256(msg.sender),           // L1 sender
        uint256(toAddress),            // L2 recipient
        uint256(nonce),                // Message nonce
        uint256(selector),             // Function selector
        uint256(payload.length),       // Payload length
        payload                        // Payload data
    )
);
```

### L2 → L1 Message Hash

```cairo
// Message hash on L2:
// pedersen(pedersen(from, to), pedersen(payload_hash, nonce))

// Payload hash:
// pedersen(len, payload[0], payload[1], ...)
```

---

## Bridge Security Patterns

### Deposit/Withdraw Pattern

```
Deposit (L1 → L2):
1. User calls L1.deposit(amount)
2. L1 locks tokens in bridge contract
3. L1 sends message to L2
4. L2 mints equivalent tokens to user

Withdraw (L2 → L1):
1. User calls L2.withdraw(amount)
2. L2 burns tokens
3. L2 sends message to L1
4. User/relayer calls L1.completeWithdraw()
5. L1 releases tokens to user
```

### Emergency Pause

```cairo
// L2 Contract
#[storage]
struct Storage {
    paused: bool,
}

#[l1_handler]
fn handle_deposit(ref self: ContractState, ...) {
    assert(!self.paused.read(), 'Bridge paused');
    // ... continue
}

fn set_paused(ref self: ContractState, paused: bool) {
    self._only_owner();
    self.paused.write(paused);
}
```

### Rate Limiting

```cairo
#[storage]
struct Storage {
    daily_volume: u256,
    last_reset: u64,
    max_daily_volume: u256,
}

fn check_rate_limit(ref self: ContractState, amount: u256) {
    let now = get_block_timestamp();
    let last = self.last_reset.read();
    
    if now > last + 86400 {  // 24 hours
        self.daily_volume.write(0);
        self.last_reset.write(now);
    }
    
    let new_volume = self.daily_volume.read() + amount;
    assert(new_volume <= self.max_daily_volume.read(), 'Rate limit exceeded');
    self.daily_volume.write(new_volume);
}
```

---

## Testing Messaging

### Local Testing

```cairo
#[cfg(test)]
mod tests {
    use starknet::testing::set_caller_address;
    
    #[test]
    fn test_l1_handler_validates_origin() {
        let mut state = setup();
        
        // Set invalid L1 sender
        // Note: Testing L1 handlers requires special setup
        // Use Starknet Foundry for proper L1 handler testing
    }
}
```

### Integration Testing

```bash
# Using Starknet Foundry
snforge test --fork-url https://...

# Test L1-L2 messaging with devnet
# 1. Run starknet-devnet
# 2. Deploy contracts
# 3. Use messaging test framework
```

