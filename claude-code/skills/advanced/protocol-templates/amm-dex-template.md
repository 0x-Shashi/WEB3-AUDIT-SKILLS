# AMM/DEX Protocol Template

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                       AMM/DEX PROTOCOL                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐   │
│  │   ROUTER    │────▶│    POOL     │────▶│   TOKENS    │   │
│  │  (Swaps)    │     │ (Liquidity) │     │  (Assets)   │   │
│  └─────────────┘     └─────────────┘     └─────────────┘   │
│         │                   │                   │           │
│         ▼                   ▼                   ▼           │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐   │
│  │  FACTORY    │     │  LP TOKENS  │     │   ORACLE    │   │
│  │ (Pool mgmt) │     │  (Shares)   │     │  (Prices)   │   │
│  └─────────────┘     └─────────────┘     └─────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## AMM Types

### Constant Product (x * y = k)
- Uniswap V2 style
- Simple but high slippage
- MEV vulnerable

### Concentrated Liquidity
- Uniswap V3 style
- Capital efficient
- Complex position management

### Stable Swap
- Curve style
- Low slippage for pegged assets
- Amplification factor risks

### Weighted Pools
- Balancer style
- Multiple assets
- Weight manipulation risks

---

## Critical Functions

### 1. Swap Functions

```solidity
function swap(
    uint256 amountIn,
    uint256 amountOutMin,    // Slippage protection
    address[] path,
    address to,
    uint256 deadline         // Timing protection
)
```

**Audit Points:**
- [ ] Slippage check (amountOutMin enforced)
- [ ] Deadline check (prevents stale txs)
- [ ] Path validation (no malicious intermediates)
- [ ] Fee calculation correct
- [ ] Reentrancy protection

### 2. Add Liquidity

```solidity
function addLiquidity(
    address tokenA,
    address tokenB,
    uint256 amountADesired,
    uint256 amountBDesired,
    uint256 amountAMin,
    uint256 amountBMin,
    address to,
    uint256 deadline
)
```

**Audit Points:**
- [ ] First depositor attack prevention
- [ ] Ratio calculation correct
- [ ] Minimum amounts enforced
- [ ] LP token minting correct
- [ ] No value extraction on deposit

### 3. Remove Liquidity

```solidity
function removeLiquidity(
    address tokenA,
    address tokenB,
    uint256 liquidity,
    uint256 amountAMin,
    uint256 amountBMin,
    address to,
    uint256 deadline
)
```

**Audit Points:**
- [ ] LP tokens burned before transfer
- [ ] Correct share calculation
- [ ] Minimum amounts enforced
- [ ] No reentrancy through tokens

---

## Common Vulnerabilities

### AMM-01: First Depositor Attack

**Risk:** Critical

**Description:** First LP depositor can manipulate initial price to drain subsequent depositors.

**Vulnerable Pattern:**
```solidity
function addLiquidity(uint256 amountA, uint256 amountB) {
    if (totalSupply == 0) {
        liquidity = sqrt(amountA * amountB);  // Attacker controls ratio
    }
}
```

**Attack:**
1. Deposit 1 wei of each token
2. Get 1 LP token
3. Donate large amount of tokenA
4. Next depositor's tokens mostly go to first depositor

**Mitigation:**
```solidity
if (totalSupply == 0) {
    liquidity = sqrt(amountA * amountB) - MINIMUM_LIQUIDITY;
    _mint(address(0), MINIMUM_LIQUIDITY);  // Lock initial liquidity
}
```

---

### AMM-02: Missing Slippage Protection

**Risk:** High

**Description:** No minimum output enforced, MEV bots extract value.

**Vulnerable Pattern:**
```solidity
function swap(uint256 amountIn) returns (uint256 amountOut) {
    amountOut = getAmountOut(amountIn);
    // No minimum check!
    transfer(msg.sender, amountOut);
}
```

**Attack:**
1. Bot sees user's swap in mempool
2. Front-runs with large swap (moves price)
3. User's swap executes at worse price
4. Bot back-runs to profit

**Mitigation:**
```solidity
function swap(uint256 amountIn, uint256 amountOutMin) {
    amountOut = getAmountOut(amountIn);
    require(amountOut >= amountOutMin, "Slippage");
}
```

---

### AMM-03: Missing Deadline Check

**Risk:** Medium

**Description:** Stale transactions can execute at unfavorable prices.

**Vulnerable Pattern:**
```solidity
function swap(...) {
    // No deadline parameter!
}
```

**Attack:**
1. User submits swap with low gas
2. Transaction sits in mempool for hours
3. Price moves significantly
4. Transaction finally executes at bad price

**Mitigation:**
```solidity
modifier checkDeadline(uint256 deadline) {
    require(block.timestamp <= deadline, "Expired");
    _;
}
```

---

### AMM-04: K Value Manipulation

**Risk:** Critical

**Description:** Constant product K can be manipulated through donations.

**Vulnerable Pattern:**
```solidity
function swap(uint256 amountIn) {
    uint256 balanceA = tokenA.balanceOf(address(this));
    uint256 balanceB = tokenB.balanceOf(address(this));
    // Using actual balances instead of tracked reserves
}
```

**Mitigation:**
- Track reserves internally
- Use `reserve0`, `reserve1` not `balanceOf`
- Skim excess tokens

---

### AMM-05: Fee-on-Transfer Token Issues

**Risk:** High

**Description:** Tokens with transfer fees break AMM assumptions.

**Vulnerable Pattern:**
```solidity
function deposit(uint256 amount) {
    token.transferFrom(msg.sender, address(this), amount);
    // Received less than `amount` due to fee!
    balances[msg.sender] += amount;  // Credited full amount
}
```

**Mitigation:**
```solidity
function deposit(uint256 amount) {
    uint256 before = token.balanceOf(address(this));
    token.transferFrom(msg.sender, address(this), amount);
    uint256 received = token.balanceOf(address(this)) - before;
    balances[msg.sender] += received;  // Credit actual received
}
```

---

### AMM-06: Oracle Manipulation via Reserves

**Risk:** Critical

**Description:** Using pool reserves as price oracle enables manipulation.

**Vulnerable Pattern:**
```solidity
function getPrice() view returns (uint256) {
    (uint112 r0, uint112 r1,) = pair.getReserves();
    return r0 * 1e18 / r1;  // Instantly manipulatable!
}
```

**Attack:**
Flash loan → Large swap → Manipulated price → Attack → Swap back

**Mitigation:**
- Use TWAP (time-weighted average)
- Use external oracles (Chainlink)

---

### AMM-07: Concentrated Liquidity Position Attacks

**Risk:** High (Uniswap V3 style)

**Description:** Narrow liquidity positions can be manipulated.

**Vulnerable Scenario:**
1. Attacker sees large position in narrow range
2. Pushes price out of range
3. Position earns no fees, loses value
4. Returns price, profits

---

## Real Exploit Examples

| Protocol | Date | Loss | Vulnerability |
|----------|------|------|---------------|
| Bancor V2 | 2020 | $460K | Oracle manipulation |
| Saddle Finance | 2022 | $10M | Metapool exploit |
| Platypus | 2023 | $8.5M | Flash loan + collateral |
| Curve | 2023 | $70M | Vyper compiler bug |

---

## AMM Audit Checklist

### Core Swap Logic
- [ ] Slippage protection enforced
- [ ] Deadline checks present
- [ ] Fee calculation correct
- [ ] Reentrancy protection
- [ ] K value maintained correctly

### Liquidity Management
- [ ] First depositor attack prevented
- [ ] LP token math correct
- [ ] Withdrawal calculations secure
- [ ] No sandwich on add/remove liquidity

### Token Handling
- [ ] Fee-on-transfer supported or blocked
- [ ] Rebasing tokens handled
- [ ] Token decimals handled correctly
- [ ] Zero address checks

### Oracle Security
- [ ] TWAP used (not spot)
- [ ] Sufficient TWAP window
- [ ] Manipulation cost calculated

### Access Control
- [ ] Fee changes protected
- [ ] Pool creation controls
- [ ] Emergency pause mechanism

---

## Detection Commands

```bash
# Find swap functions
grep -rn "function swap\|function swapExact" --include="*.sol"

# Find slippage parameters
grep -rn "amountOutMin\|minAmount\|slippage" --include="*.sol"

# Find deadline checks
grep -rn "deadline\|block.timestamp.*<\|expired" --include="*.sol"

# Find reserve usage
grep -rn "getReserves\|reserve0\|reserve1" --include="*.sol"

# Find fee calculations
grep -rn "fee\|FEE\|997\|9970\|10000" --include="*.sol"

# Find LP token logic
grep -rn "totalSupply\|_mint\|_burn.*liquidity" --include="*.sol"

# Find TWAP
grep -rn "twap\|TWAP\|cumulative.*price" --include="*.sol"
```

---

## Protocol-Specific Patterns

### Uniswap V2 Forks
- `UniswapV2Pair`, `UniswapV2Router`, `UniswapV2Factory`
- 0.3% fee hardcoded
- Check for fee switch mechanism

### Uniswap V3 Forks
- Tick-based liquidity
- Position NFTs
- Check oracle implementation

### Curve Forks
- StableSwap algorithm
- Amplification factor (A)
- Check A manipulation

### Balancer Forks
- Weighted math
- Flash loans built-in
- Check weight manipulation
