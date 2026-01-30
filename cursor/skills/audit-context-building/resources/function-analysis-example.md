# Function Analysis Example

Complete walkthrough of ultra-granular function analysis using a DEX swap function.

---

## Target Function

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract SimpleDEX {
    IERC20 public tokenA;
    IERC20 public tokenB;
    uint256 public reserveA;
    uint256 public reserveB;
    uint256 public constant FEE_NUMERATOR = 997;
    uint256 public constant FEE_DENOMINATOR = 1000;
    
    mapping(address => uint256) public liquidityShares;
    uint256 public totalShares;
    
    event Swap(
        address indexed user,
        address indexed tokenIn,
        uint256 amountIn,
        address indexed tokenOut,
        uint256 amountOut
    );

    function swap(
        address tokenIn,
        uint256 amountIn,
        uint256 minAmountOut
    ) external returns (uint256 amountOut) {
        // Block 1: Token validation
        require(
            tokenIn == address(tokenA) || tokenIn == address(tokenB),
            "Invalid token"
        );
        require(amountIn > 0, "Zero amount");
        
        // Block 2: Determine swap direction
        bool isAtoB = tokenIn == address(tokenA);
        (IERC20 inputToken, IERC20 outputToken) = isAtoB 
            ? (tokenA, tokenB) 
            : (tokenB, tokenA);
        (uint256 reserveIn, uint256 reserveOut) = isAtoB 
            ? (reserveA, reserveB) 
            : (reserveB, reserveA);
            
        // Block 3: Calculate output with fee
        uint256 amountInWithFee = amountIn * FEE_NUMERATOR;
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = (reserveIn * FEE_DENOMINATOR) + amountInWithFee;
        amountOut = numerator / denominator;
        
        // Block 4: Slippage protection
        require(amountOut >= minAmountOut, "Slippage exceeded");
        require(amountOut > 0, "Zero output");
        
        // Block 5: Transfer tokens in
        inputToken.transferFrom(msg.sender, address(this), amountIn);
        
        // Block 6: Update reserves
        if (isAtoB) {
            reserveA += amountIn;
            reserveB -= amountOut;
        } else {
            reserveB += amountIn;
            reserveA -= amountOut;
        }
        
        // Block 7: Transfer tokens out
        outputToken.transfer(msg.sender, amountOut);
        
        // Block 8: Emit event
        emit Swap(msg.sender, tokenIn, amountIn, address(outputToken), amountOut);
        
        return amountOut;
    }
}
```

---

## Complete Analysis

### Function: swap(address tokenIn, uint256 amountIn, uint256 minAmountOut)

### Purpose

This function enables users to exchange one token for another within the DEX's liquidity pool. It implements the constant product AMM formula (x * y = k) with a 0.3% fee, providing core swap functionality for the protocol. The function is the primary value extraction point of the DEX and handles user-initiated token exchanges with slippage protection.

### Inputs & Assumptions

| Input | Type | Validation | Trust Level |
|-------|------|------------|-------------|
| tokenIn | address | Must be tokenA or tokenB | Untrusted |
| amountIn | uint256 | Must be > 0 | Untrusted |
| minAmountOut | uint256 | Used for slippage check | Untrusted |

**Implicit Inputs:**
- `msg.sender`: Assumed to have approved sufficient tokens for transferFrom
- `reserveA` / `reserveB`: Current pool reserves, assumed accurate
- `tokenA` / `tokenB`: Contract addresses, assumed to be valid ERC20s
- `block.timestamp`: Not used (no deadline), potential concern

**Preconditions:**
1. `tokenIn` is one of the pool's tokens
2. `amountIn` is greater than zero
3. User has approved at least `amountIn` tokens
4. User has sufficient token balance
5. Pool has sufficient output reserve

**Assumptions:**
1. Token contracts are standard ERC20 (transfer/transferFrom return nothing or true)
2. Token contracts don't have fee-on-transfer
3. Token contracts don't have rebasing behavior
4. Pool reserves accurately reflect contract balances
5. No external parties can manipulate reserves between calculation and execution

### Outputs & Effects

**Returns:** `uint256 amountOut` - The amount of output tokens received

**State Changes:**
1. `reserveA` updated: +amountIn if swapping A→B, -amountOut if swapping B→A
2. `reserveB` updated: +amountIn if swapping B→A, -amountOut if swapping A→B

**Events:**
- `Swap(msg.sender, tokenIn, amountIn, outputToken, amountOut)`

**External Calls:**
1. `inputToken.transferFrom(msg.sender, address(this), amountIn)` - Line 55
2. `outputToken.transfer(msg.sender, amountOut)` - Line 66

**Postconditions:**
1. Constant product invariant maintained (with fee extraction)
2. User received >= minAmountOut tokens
3. Contract received exactly amountIn tokens
4. Reserves updated to reflect new balances

---

### Block-by-Block Analysis

#### Block 1: Token Validation (Lines 30-35)

```solidity
require(
    tokenIn == address(tokenA) || tokenIn == address(tokenB),
    "Invalid token"
);
require(amountIn > 0, "Zero amount");
```

**What:** Validates that the input token is one of the pool's supported tokens and that the amount is positive.

**Why Here:** Fail-fast pattern. Invalid tokens or zero amounts should be rejected immediately before any computation or state access. Gas efficiency.

**Assumptions:**
- `tokenA` and `tokenB` are immutable or at least stable during execution
- Zero-amount swaps are invalid (no economic purpose)
- The set of valid tokens is exactly {tokenA, tokenB}

**Invariant Maintained:** Only valid pool tokens can be swapped.

**Depends On:** State variables `tokenA`, `tokenB`

**Later Logic Depends On:** `tokenIn` is definitely one of the two pool tokens

**First Principles Application:**
- Q: Why check tokenIn at all?
- A: Without this check, an attacker could pass any address. The swap direction logic would produce unpredictable results. Arbitrary token addresses could be used to drain funds.

**5 Whys:**
1. Why must tokenIn be tokenA or tokenB? → Because swap logic assumes two-token pool
2. Why only two tokens? → Constant product formula works for pairs
3. Why constant product? → It's the simplest AMM model
4. Why use AMM? → Enables permissionless liquidity provision
5. Why permissionless? → Core DeFi value proposition

---

#### Block 2: Determine Swap Direction (Lines 37-43)

```solidity
bool isAtoB = tokenIn == address(tokenA);
(IERC20 inputToken, IERC20 outputToken) = isAtoB 
    ? (tokenA, tokenB) 
    : (tokenB, tokenA);
(uint256 reserveIn, uint256 reserveOut) = isAtoB 
    ? (reserveA, reserveB) 
    : (reserveB, reserveA);
```

**What:** Determines swap direction and assigns the correct token contracts and reserve values based on which token is being provided.

**Why Here:** After validation, need to set up correct variables for the swap. Before calculation, need correct reserves.

**Assumptions:**
- Boolean algebra: if tokenIn isn't tokenA, it must be tokenB (guaranteed by Block 1)
- Reserve values accurately reflect actual token balances in contract
- Token contract references are stable

**Invariant Maintained:** Correct pairing of input/output tokens with their reserves.

**Depends On:** Block 1 validation (tokenIn is valid)

**Later Logic Depends On:** 
- `inputToken`/`outputToken` for transfers
- `reserveIn`/`reserveOut` for calculation

**5 Hows:**
1. How does direction affect calculation? → Changes which reserve is numerator vs denominator
2. How does it affect transfers? → Determines which token to receive and which to send
3. How could direction be manipulated? → Only by providing different tokenIn
4. How does reserve assignment work? → Memory copies of storage values
5. How could reserve values be wrong? → If external calls modified balances without updating reserves

---

#### Block 3: Calculate Output with Fee (Lines 45-49)

```solidity
uint256 amountInWithFee = amountIn * FEE_NUMERATOR;
uint256 numerator = amountInWithFee * reserveOut;
uint256 denominator = (reserveIn * FEE_DENOMINATOR) + amountInWithFee;
amountOut = numerator / denominator;
```

**What:** Implements constant product AMM formula with 0.3% fee: `amountOut = (amountIn * 997 * reserveOut) / (reserveIn * 1000 + amountIn * 997)`

**Why Here:** Core swap calculation. Must happen after reserve assignment, before slippage check.

**Assumptions:**
1. Multiplication won't overflow (Solidity 0.8+ checks)
2. Division truncates toward zero (acceptable, favors pool)
3. `reserveIn * FEE_DENOMINATOR + amountInWithFee` won't overflow
4. Fee parameters (997/1000) are correct and immutable
5. Integer division precision loss is acceptable

**Invariant Maintained:** Constant product k = reserveIn * reserveOut (approximately, with fee extraction)

**Depends On:** Block 2 (correct reserveIn, reserveOut values)

**Later Logic Depends On:** Calculated `amountOut` for slippage check and transfer

**First Principles Application:**
- Q: Why this specific formula?
- A: Derived from constant product invariant. Before swap: k = x * y. After swap: (x + dx) * (y - dy) = k. Solving for dy with fee adjustment gives this formula.

**5 Whys:**
1. Why multiply by FEE_NUMERATOR (997)? → To subtract 0.3% fee
2. Why 0.3% fee? → Standard AMM fee, balances LP returns vs trader cost
3. Why is fee in numerator not denominator? → Reduces effective input amount
4. Why integer division? → Solidity doesn't have native floats
5. Why truncate toward zero? → Protects pool from rounding attacks

**Risk Analysis:**
- **Precision Loss:** Integer division loses decimals. For very small swaps relative to pool size, output could round to zero.
- **Overflow:** `amountInWithFee * reserveOut` could overflow for large pools/amounts. Solidity 0.8+ reverts on overflow.

---

#### Block 4: Slippage Protection (Lines 51-52)

```solidity
require(amountOut >= minAmountOut, "Slippage exceeded");
require(amountOut > 0, "Zero output");
```

**What:** Ensures calculated output meets user's minimum expectation and is non-zero.

**Why Here:** After calculation, before any state changes or transfers. User protection before commitment.

**Assumptions:**
1. User has correctly calculated their minAmountOut
2. Zero output is always invalid (waste of gas)
3. Front-running protection is user's responsibility

**Invariant Maintained:** User always receives at least their specified minimum.

**Depends On:** Block 3 (calculated amountOut)

**Later Logic Depends On:** amountOut is valid for transfer

**5 Whys:**
1. Why check minAmountOut? → Protect user from sandwich attacks/slippage
2. Why allow user to set this? → User knows their risk tolerance
3. Why check zero output separately? → Edge case where calculation underflows to 0
4. Why is zero output possible? → Precision loss for tiny amounts or manipulation
5. Why here instead of earlier? → Need calculated value first

**Missing Feature Analysis:**
- No deadline parameter (vulnerable to long-pending txs)
- No maximum slippage limit from protocol

---

#### Block 5: Transfer Tokens In (Line 55)

```solidity
inputToken.transferFrom(msg.sender, address(this), amountIn);
```

**What:** Pulls input tokens from user to contract using pre-approved allowance.

**Why Here:** After all validation and calculation, before reserve updates. CEI pattern would suggest this should be after reserve updates.

**Assumptions:**
1. User has approved sufficient allowance
2. User has sufficient balance
3. transferFrom will revert on failure (standard ERC20)
4. No fee-on-transfer (contract receives exactly amountIn)
5. No callback during transfer (reentrancy risk)

**Invariant at Risk:** Reserve accuracy if token has non-standard behavior

**Depends On:** All previous blocks validated the swap

**Later Logic Depends On:** Contract now holds the input tokens

**5 Hows:**
1. How could this fail? → Insufficient balance, insufficient allowance, paused token
2. How does fee-on-transfer break this? → Contract receives less than amountIn, but reserveA updates by amountIn
3. How does rebasing break this? → Similar balance mismatch
4. How is reentrancy possible? → ERC777 or malicious token could callback
5. How is reentrancy mitigated? → Not mitigated! No reentrancy guard.

**CRITICAL ISSUE IDENTIFIED:**
⚠️ **Potential Reentrancy:** If inputToken is ERC777 or has hooks, it could callback into swap() before reserves are updated, allowing double-spend or manipulation.

⚠️ **Fee-on-Transfer Vulnerability:** If inputToken has transfer fees, the contract receives less than `amountIn` but reserves update by full `amountIn`, causing permanent accounting error.

---

#### Block 6: Update Reserves (Lines 57-62)

```solidity
if (isAtoB) {
    reserveA += amountIn;
    reserveB -= amountOut;
} else {
    reserveB += amountIn;
    reserveA -= amountOut;
}
```

**What:** Updates internal reserve tracking to reflect the swap.

**Why Here:** After tokens received, before tokens sent. Reflects new state.

**Assumptions:**
1. amountIn was fully received (no fee-on-transfer)
2. No underflow on reserve subtraction (amountOut < reserve)
3. No reentrancy has modified reserves since calculation

**Invariant Maintained:** Reserves track actual token balances (when assumptions hold)

**Depends On:** Block 5 (tokens transferred in), Block 3 (amountOut calculated)

**Later Logic Depends On:** Updated reserves for subsequent swaps

**Risk Analysis:**
- **Underflow:** If amountOut > reserveOut, Solidity 0.8+ reverts. But this shouldn't happen if formula is correct.
- **Stale Reads:** If reentrancy occurred, reserves could be wrong
- **Balance Desync:** Fee-on-transfer permanently desyncs reserves from balances

---

#### Block 7: Transfer Tokens Out (Line 66)

```solidity
outputToken.transfer(msg.sender, amountOut);
```

**What:** Sends calculated output tokens to user.

**Why Here:** After reserve updates, as final state change. Follows CEI for output.

**Assumptions:**
1. Contract has sufficient outputToken balance
2. transfer will succeed (standard ERC20)
3. User's address can receive tokens

**Invariant at Risk:** User receives tokens only if transfer succeeds

**Depends On:** Block 6 (reserves updated), Block 3 (amountOut calculated)

**Later Logic Depends On:** None (final meaningful operation)

**5 Hows:**
1. How could this fail? → Contract lacks balance, token paused, user blacklisted
2. How is contract balance ensured? → Reserves should track balances
3. How could balance be wrong? → Fee-on-transfer, direct transfers, exploits
4. How is failure handled? → Reverts entire transaction (good)
5. How is user protected? → Gets tokens or entire tx reverts

---

#### Block 8: Emit Event (Line 68)

```solidity
emit Swap(msg.sender, tokenIn, amountIn, address(outputToken), amountOut);
```

**What:** Logs swap details for off-chain indexing and monitoring.

**Why Here:** After all state changes, standard practice.

**Assumptions:**
- Event data accurately reflects what happened
- Off-chain systems will parse this correctly

---

### Invariants Identified

1. **Constant Product (Approximate):** After swap, `newReserveA * newReserveB >= oldReserveA * oldReserveB` (with fee extraction, k increases)

2. **Reserve-Balance Parity:** `reserveA == tokenA.balanceOf(address(this))` and same for B (broken by fee-on-transfer, direct transfers)

3. **Slippage Guarantee:** User always receives `>= minAmountOut` or transaction reverts

4. **Valid Token Only:** Only tokenA or tokenB can be swapped (no arbitrary tokens)

5. **Non-Zero Output:** Every successful swap produces `amountOut > 0`

6. **Fee Extraction:** Protocol retains 0.3% of each swap in the pool

---

### Risk Analysis

| Risk | Likelihood | Impact | Mitigation | Status |
|------|------------|--------|------------|--------|
| Reentrancy via ERC777 | Medium | Critical | Add nonReentrant | ❌ Missing |
| Fee-on-transfer desync | Medium | High | Check actual balance received | ❌ Missing |
| No deadline parameter | High | Medium | Add deadline check | ❌ Missing |
| Flash loan manipulation | Medium | High | Use TWAP oracle | ❌ Missing |
| Precision loss on small swaps | Low | Low | Minimum amount checks | ⚠️ Partial |
| Overflow in calculation | Very Low | Critical | Solidity 0.8+ | ✅ Mitigated |

---

### Cross-References

**Calls:**
- `IERC20.transferFrom()` - External, ERC20 standard
- `IERC20.transfer()` - External, ERC20 standard

**Called By:**
- External users (public function)
- Potentially routers or aggregators

**Shares State With:**
- Any function that reads/writes reserveA, reserveB
- Liquidity add/remove functions (not shown)

---

### Summary of Issues Found During Context Building

1. **Reentrancy Vulnerability:** No reentrancy guard, vulnerable to ERC777 hooks
2. **Fee-on-Transfer Incompatibility:** Reserve desync with non-standard tokens  
3. **No Deadline:** Pending transactions can be executed at unfavorable prices
4. **No Flash Loan Protection:** Price can be manipulated atomically

These issues were identified through systematic context building, NOT vulnerability hunting. The vulnerabilities emerged naturally from understanding the code deeply.

