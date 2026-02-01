---
id: ATTACK-INTENT-BASED
title: Intent-Based Protocol Attacks
category: attack-patterns
difficulty: advanced
tags: [intent, solver, cow-protocol, 1inch-fusion, uniswap-x]
last_updated: 2026-01-31
---

# Intent-Based Protocol Attacks

## Overview

Intent-based protocols let users express WHAT they want (swap X for Y) rather than HOW to do it. Solvers compete to fulfill these intents, creating new attack surfaces.

```
┌─────────────────────────────────────────────────────────────────┐
│                    INTENT ARCHITECTURE                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   USER                  SOLVER NETWORK              SETTLEMENT  │
│  ┌──────┐              ┌─────────────┐            ┌──────────┐ │
│  │Intent│   Compete    │  Solver 1   │  Execute   │          │ │
│  │"Swap │─────────────►│  Solver 2   │───────────►│ On-Chain │ │
│  │A→B"  │   to fill    │  Solver 3   │            │ Settle   │ │
│  └──────┘              └─────────────┘            └──────────┘ │
│                              │                                  │
│                              ▼                                  │
│              ┌───────────────────────────────┐                  │
│              │ ATTACK SURFACES:              │                  │
│              │ • Solver collusion            │                  │
│              │ • Intent front-running        │                  │
│              │ • Order flow manipulation     │                  │
│              │ • Signature replay            │                  │
│              │ • Fill optimization games     │                  │
│              └───────────────────────────────┘                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Intent Protocol Comparison

| Protocol | Settlement | Solver Selection | Risk Profile |
|----------|------------|------------------|--------------|
| **CoW Protocol** | Batch auctions | Competition | Solver collusion |
| **UniswapX** | Dutch auction | First valid fill | Front-running |
| **1inch Fusion** | Dutch auction | Resolver network | Fill manipulation |
| **Across** | Optimistic | Relayer competition | Fill delays |
| **Anoma** | Intent matching | P2P | Double-spend |

---

## Attack Vector 1: Solver Collusion

### Mechanism

```
Malicious solvers coordinate to extract maximum value from users

ATTACK FLOW:
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  1. User submits intent: "Swap 1000 USDC for max ETH"          │
│                                                                 │
│  2. Solver A wins auction with bid: 0.45 ETH                   │
│                                                                 │
│  3. BUT Solver A colluded with Solver B:                       │
│     - They agreed not to compete aggressively                  │
│     - Fair market rate was 0.50 ETH                            │
│     - User loses 0.05 ETH ($100+) to collusion                 │
│                                                                 │
│  4. Solvers split the extracted value                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Detection Patterns

```solidity
// Audit checklist for solver collusion resistance

contract IntentSettlement {
    // VULNERABLE: No solver diversity requirement
    function settle(Order calldata order, address solver) external {
        // Any solver can settle
        _executeSettlement(order, solver);
    }
    
    // BETTER: Require solver rotation/diversity
    mapping(uint256 => address) public epochWinner;
    uint256 public constant MIN_UNIQUE_SOLVERS = 5;
    
    function settle(Order calldata order, address solver) external {
        // Track solver distribution
        require(
            getUniqueSolversLastEpoch() >= MIN_UNIQUE_SOLVERS,
            "Insufficient solver diversity"
        );
        _executeSettlement(order, solver);
    }
}
```

### Audit Questions

```markdown
□ How many active solvers are in the network?
□ Is there solver staking/slashing for misbehavior?
□ Are solver bids publicly visible (enables collusion)?
□ Can users choose/exclude specific solvers?
□ Is there solver rotation enforcement?
```

---

## Attack Vector 2: Intent Front-Running

### Off-Chain Front-Running

```
Attacker sees intent in mempool/API before settlement

ATTACK:
1. User creates intent: Swap 1M USDC → ETH (large order)
2. Attacker sees intent (mempool, API, solver leak)
3. Attacker front-runs: Buy ETH
4. User's intent settles (moves price up)
5. Attacker back-runs: Sell ETH at profit

IMPACT: Same as sandwich attack, but at intent layer
```

### Dutch Auction Manipulation

```solidity
// UniswapX Dutch Auction Attack

// User intent starts at premium price, decays to minimum
struct DutchOrder {
    uint256 startAmount;      // Best price for user (1.05 ETH per 1000 USDC)
    uint256 endAmount;        // Worst acceptable (0.95 ETH per 1000 USDC)
    uint256 decayStartTime;
    uint256 decayEndTime;
}

// ATTACK: Wait for price to decay, then fill at minimum
// User wanted: 1.05 ETH
// User gets: 0.95 ETH (minimum)
// Solver keeps: 0.10 ETH difference

// DEFENSE: 
// - Shorter decay windows
// - Steeper decay curves (punish waiting)
// - User-set price floors
```

### Protection Mechanisms

```solidity
// Intent protection patterns

contract SecureIntentProtocol {
    // 1. Commit-reveal scheme for intents
    mapping(bytes32 => bool) public commitments;
    
    function commitIntent(bytes32 hash) external {
        commitments[hash] = true;
    }
    
    function revealAndExecute(
        Intent calldata intent,
        bytes32 salt
    ) external {
        require(
            commitments[keccak256(abi.encode(intent, salt))],
            "No commitment"
        );
        // Execute after delay
    }
    
    // 2. Private intent submission (encrypted to solver)
    function submitEncryptedIntent(
        bytes calldata encryptedIntent,
        bytes calldata solverPubKey
    ) external {
        // Only designated solver can decrypt
    }
    
    // 3. Threshold decryption
    function submitSharedIntent(
        bytes[] calldata encryptedShares
    ) external {
        // Requires threshold of solvers to decrypt
    }
}
```

---

## Attack Vector 3: Order Flow Manipulation

### Toxic Order Flow Routing

```
Solver selectively routes orders to extract value

SCENARIO:
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  Informed Order (price will move)                               │
│  └── Route to: External venues (pass off risk)                  │
│                                                                 │
│  Uninformed Order (retail, stable)                              │
│  └── Route to: Solver's own inventory (profit from spread)      │
│                                                                 │
│  RESULT: Solver keeps good flow, dumps bad flow elsewhere       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Detection

```python
# Analyzing solver behavior for toxic flow routing

def detect_toxic_routing(solver_fills: list) -> dict:
    """
    Check if solver selectively fills profitable orders
    """
    
    analysis = {
        "total_fills": len(solver_fills),
        "profitable_fills": 0,
        "unprofitable_fills": 0,
        "fill_rate_by_size": {},
        "routing_patterns": {}
    }
    
    for fill in solver_fills:
        post_fill_price = get_price_after_fill(fill)
        fill_direction = fill.side  # buy or sell
        
        # Did price move favorably for solver?
        if price_moved_favorably(fill.price, post_fill_price, fill_direction):
            analysis["profitable_fills"] += 1
        else:
            analysis["unprofitable_fills"] += 1
    
    # Suspicious if highly skewed toward profitable fills
    profit_ratio = analysis["profitable_fills"] / analysis["total_fills"]
    analysis["suspicious"] = profit_ratio > 0.7  # >70% profitable is suspicious
    
    return analysis
```

---

## Attack Vector 4: Signature Replay

### Cross-Chain Replay

```solidity
// Intent signed for Chain A can be replayed on Chain B

// VULNERABLE intent structure:
struct Intent {
    address tokenIn;
    address tokenOut;
    uint256 amountIn;
    uint256 minAmountOut;
    address recipient;
    uint256 deadline;
    // MISSING: chainId!
}

// ATTACK:
// 1. User signs intent on Ethereum mainnet
// 2. Attacker replays same intent on Arbitrum
// 3. If user has tokens on both chains, funds stolen

// SECURE intent structure:
struct SecureIntent {
    address tokenIn;
    address tokenOut;
    uint256 amountIn;
    uint256 minAmountOut;
    address recipient;
    uint256 deadline;
    uint256 chainId;        // REQUIRED
    address intentContract; // REQUIRED
    uint256 nonce;          // REQUIRED
}
```

### Nonce Management Attacks

```solidity
// Intent protocols often use nonces for replay protection

contract IntentNonces {
    // VULNERABLE: Simple incrementing nonce
    mapping(address => uint256) public nonces;
    
    function executeIntent(Intent calldata intent, bytes calldata sig) external {
        require(intent.nonce == nonces[intent.maker], "Invalid nonce");
        nonces[intent.maker]++;
        // Execute...
    }
    
    // ATTACK: Cancel pending intent by using its nonce
    // 1. User creates intent with nonce 5
    // 2. Attacker (or user mistake) executes different intent with nonce 5
    // 3. Original intent is now unexecutable
    
    // BETTER: Bitmap nonces (allow any unused nonce)
    mapping(address => mapping(uint256 => uint256)) public nonceBitmap;
    
    function executeIntent(Intent calldata intent, bytes calldata sig) external {
        uint256 wordIndex = intent.nonce / 256;
        uint256 bitIndex = intent.nonce % 256;
        
        uint256 word = nonceBitmap[intent.maker][wordIndex];
        uint256 mask = 1 << bitIndex;
        
        require(word & mask == 0, "Nonce used");
        nonceBitmap[intent.maker][wordIndex] = word | mask;
        // Execute...
    }
}
```

---

## Attack Vector 5: Fill Optimization Attacks

### Partial Fill Exploitation

```solidity
// Some protocols allow partial fills

struct PartialFillIntent {
    uint256 totalAmount;
    uint256 minFillAmount;  // Minimum per fill
    uint256 filledAmount;   // Track total filled
}

// ATTACK: Fill only during favorable conditions
// 1. User intent: Sell 1000 ETH, min fill 10 ETH
// 2. Price is volatile
// 3. Solver fills 10 ETH when price dips (profitable for solver)
// 4. Solver waits for next dip, fills another 10 ETH
// 5. User gets worst execution across entire fill

// Result: User's order is "drip filled" at worst prices

// DEFENSE: Time-weighted fill requirements
function validateFill(Intent storage intent, uint256 fillAmount) internal {
    uint256 elapsed = block.timestamp - intent.createdAt;
    uint256 expectedFill = intent.totalAmount * elapsed / intent.maxDuration;
    
    require(
        intent.filledAmount + fillAmount >= expectedFill,
        "Fill behind schedule"
    );
}
```

### Auction Manipulation

```
CoW Protocol Batch Auction Attack:

1. Submit large intent at auction deadline
2. Force auction to include your order
3. Manipulate clearing price

DEFENSE: 
- Earlier deadlines
- Order size limits per auction
- Randomized batch creation
```

---

## Audit Checklist

### Intent Creation Security

```markdown
□ Chain ID included in signed message?
□ Contract address included in signed message?
□ Deadline/expiry enforced?
□ Nonce system prevents replay?
□ Maker address cannot be spoofed?
□ Intent cancellation possible?
```

### Solver Security

```markdown
□ Solver staking/bonding required?
□ Slashing for misbehavior implemented?
□ Minimum solver diversity enforced?
□ Solver selection is fair (not first-come)?
□ Solver cannot see other bids before committing?
```

### Settlement Security

```markdown
□ Settlement atomic with intent verification?
□ Price bounds enforced on-chain?
□ Fill price verified against intent limits?
□ Partial fill handling correct?
□ Failed settlement doesn't lock funds?
```

### Economic Security

```markdown
□ Dutch auction decay parameters secure?
□ MEV extraction limited by design?
□ Users can set slippage protection?
□ Time-to-fill metrics monitored?
□ Solver profitability vs user experience balanced?
```

---

## Code Examples

### Secure Intent Structure

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecureIntentProtocol is EIP712 {
    using ECDSA for bytes32;
    
    bytes32 public constant INTENT_TYPEHASH = keccak256(
        "Intent(address maker,address tokenIn,address tokenOut,uint256 amountIn,uint256 minAmountOut,address recipient,uint256 deadline,uint256 nonce)"
    );
    
    struct Intent {
        address maker;
        address tokenIn;
        address tokenOut;
        uint256 amountIn;
        uint256 minAmountOut;
        address recipient;
        uint256 deadline;
        uint256 nonce;
    }
    
    mapping(address => mapping(uint256 => uint256)) public nonceBitmap;
    
    constructor() EIP712("SecureIntentProtocol", "1") {}
    
    function executeIntent(
        Intent calldata intent,
        bytes calldata signature,
        uint256 fillAmount
    ) external {
        // 1. Verify deadline
        require(block.timestamp <= intent.deadline, "Intent expired");
        
        // 2. Verify signature
        bytes32 structHash = keccak256(abi.encode(
            INTENT_TYPEHASH,
            intent.maker,
            intent.tokenIn,
            intent.tokenOut,
            intent.amountIn,
            intent.minAmountOut,
            intent.recipient,
            intent.deadline,
            intent.nonce
        ));
        
        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = digest.recover(signature);
        require(signer == intent.maker, "Invalid signature");
        
        // 3. Check and invalidate nonce
        _useNonce(intent.maker, intent.nonce);
        
        // 4. Verify fill amount meets minimum
        require(fillAmount >= intent.minAmountOut, "Fill below minimum");
        
        // 5. Execute settlement
        _settle(intent, fillAmount);
    }
    
    function _useNonce(address maker, uint256 nonce) internal {
        uint256 wordIndex = nonce / 256;
        uint256 bitIndex = nonce % 256;
        uint256 mask = 1 << bitIndex;
        
        uint256 word = nonceBitmap[maker][wordIndex];
        require(word & mask == 0, "Nonce already used");
        
        nonceBitmap[maker][wordIndex] = word | mask;
    }
    
    function _settle(Intent calldata intent, uint256 fillAmount) internal {
        // Settlement logic...
    }
}
```

---

## Related Resources

- [CoW Protocol Documentation](https://docs.cow.fi/)
- [UniswapX Whitepaper](https://uniswap.org/whitepaper-uniswapx.pdf)
- [Intent-Centric Architecture (Paradigm)](https://www.paradigm.xyz/2023/06/intents)
- [1inch Fusion Documentation](https://docs.1inch.io/docs/fusion-swap/introduction/)
