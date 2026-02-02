# Math & Precision Anti-Patterns

> Security anti-patterns for mathematical operations, rounding, precision loss, and numeric handling in smart contracts.
> 45 anti-patterns covering overflow, rounding, fixed-point math, and calculation order issues.

---

## Category Overview

| Category | ID Range | Count | Focus Area |
|----------|----------|-------|------------|
| Overflow/Underflow | MATH-AP-01 to 08 | 8 | Integer overflow, unchecked blocks |
| Rounding Errors | MATH-AP-09 to 16 | 8 | Direction, accumulation, truncation |
| Precision Loss | MATH-AP-17 to 24 | 8 | Division, decimal handling, scaling |
| Fixed-Point Math | MATH-AP-25 to 32 | 8 | WAD/RAY, scaling, conversion |
| Calculation Order | MATH-AP-33 to 39 | 7 | Operation sequence, intermediate values |
| Edge Cases | MATH-AP-40 to 45 | 6 | Zero, extremes, special values |

---

## Category 1: Overflow/Underflow Anti-Patterns

### MATH-AP-01: Unchecked Block Overflow

**Severity:** Critical | **Likelihood:** Medium

**Description:**
Using `unchecked` blocks for gas optimization enables overflow/underflow without revert.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Unchecked allows overflow
contract VulnerableUnchecked {
    function addRewards(uint256 amount) external {
        unchecked {
            // If totalRewards near max, this overflows to small number
            totalRewards += amount;
        }
    }
    
    function calculateShare(uint256 userBalance, uint256 total) internal returns (uint256) {
        unchecked {
            // userBalance * multiplier can overflow
            return userBalance * MULTIPLIER / total;
        }
    }
}

// Attack: totalRewards = type(uint256).max - 100
// addRewards(200) → totalRewards = 99 (overflow)
```

**Real Exploits:**
- **Multiple DeFi protocols (2022-2023):** Unchecked blocks in reward calculations
- **NFT contracts:** Unchecked mint counters

**Secure Pattern:**
```solidity
// SECURE: Explicit overflow check or avoid unchecked for critical ops
contract SecureUnchecked {
    function addRewards(uint256 amount) external {
        // Let Solidity 0.8+ handle overflow checking
        totalRewards += amount;
    }
    
    // Only use unchecked where overflow is impossible
    function incrementCounter() external {
        unchecked {
            // Counter can't realistically overflow (would need 2^256 calls)
            counter++;
        }
    }
    
    // Or: Explicit check in unchecked block
    function safeAdd(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            uint256 c = a + b;
            require(c >= a, "Overflow");
            return c;
        }
    }
}
```

**Detection Methods:**
- [ ] Search for `unchecked` blocks
- [ ] Analyze operations within unchecked
- [ ] Check if overflow is possible given constraints
- [ ] Trace input sources to unchecked math

---

### MATH-AP-02: Subtraction Underflow

**Severity:** High | **Likelihood:** Medium

**Description:**
Subtraction without checking for underflow causes wraparound to max uint.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No underflow check
contract VulnerableSubtraction {
    mapping(address => uint256) public balances;
    
    function withdraw(uint256 amount) external {
        unchecked {
            // If amount > balance, wraps to huge number
            balances[msg.sender] -= amount;
        }
        token.transfer(msg.sender, amount);
    }
    
    function calculateRemaining(uint256 total, uint256 used) internal pure returns (uint256) {
        unchecked {
            // If used > total, underflows
            return total - used;
        }
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Check before subtraction
contract SecureSubtraction {
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Now safe in unchecked if needed for gas
        unchecked {
            balances[msg.sender] -= amount;
        }
        token.transfer(msg.sender, amount);
    }
    
    // Or: Use SafeMath-style function
    function safeSub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a, "Underflow");
        return a - b;
    }
}
```

---

### MATH-AP-03: Multiplication Overflow

**Severity:** High | **Likelihood:** Medium

**Description:**
Large number multiplication overflows, returning incorrect results.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Multiplication can overflow
contract VulnerableMultiplication {
    function calculateReward(
        uint256 balance,
        uint256 rewardRate,
        uint256 duration
    ) internal pure returns (uint256) {
        unchecked {
            // balance * rewardRate * duration can easily overflow
            return balance * rewardRate * duration / PRECISION;
        }
    }
    
    function getTokenAmount(uint256 ethAmount, uint256 price) internal pure returns (uint256) {
        unchecked {
            // If ethAmount = 1e20 and price = 1e20, result = 1e40 (overflow!)
            return ethAmount * price / 1e18;
        }
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Use mulDiv or check order
contract SecureMultiplication {
    function calculateReward(
        uint256 balance,
        uint256 rewardRate,
        uint256 duration
    ) internal pure returns (uint256) {
        // Use OpenZeppelin's mulDiv for safe intermediate calculation
        return Math.mulDiv(balance, rewardRate * duration, PRECISION);
    }
    
    // Or: Divide early to keep numbers small
    function getTokenAmount(uint256 ethAmount, uint256 price) internal pure returns (uint256) {
        // Divide first if result fits
        return (ethAmount / 1e9) * (price / 1e9);
        
        // Or use FullMath for full precision
        return FullMath.mulDiv(ethAmount, price, 1e18);
    }
}
```

---

### MATH-AP-04: Type Casting Overflow

**Severity:** High | **Likelihood:** Medium

**Description:**
Casting larger type to smaller type truncates value without error.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Unsafe downcast
contract VulnerableCasting {
    function storeAmount(uint256 amount) external {
        // If amount > type(uint128).max, high bits are lost
        storedAmounts[msg.sender] = uint128(amount);
    }
    
    function convertToInt(uint256 value) internal pure returns (int256) {
        // If value > type(int256).max, wraps to negative
        return int256(value);
    }
    
    function getBlockDelta() internal view returns (uint32) {
        // Block numbers can exceed uint32 on some chains
        return uint32(block.number - startBlock);
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Safe casting with checks
import "@openzeppelin/contracts/utils/math/SafeCast.sol";

contract SecureCasting {
    using SafeCast for uint256;
    using SafeCast for int256;
    
    function storeAmount(uint256 amount) external {
        // Reverts if amount doesn't fit in uint128
        storedAmounts[msg.sender] = amount.toUint128();
    }
    
    function convertToInt(uint256 value) internal pure returns (int256) {
        // Reverts if value > type(int256).max
        return value.toInt256();
    }
    
    // Manual check
    function safeUint128(uint256 value) internal pure returns (uint128) {
        require(value <= type(uint128).max, "Overflow");
        return uint128(value);
    }
}
```

---

### MATH-AP-05: Signed Integer Overflow

**Severity:** High | **Likelihood:** Low

**Description:**
Signed integer operations can overflow in both directions (positive and negative).

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Signed overflow not checked
contract VulnerableSigned {
    function addPnL(int256 currentPnL, int256 delta) internal pure returns (int256) {
        unchecked {
            // If both large positive, overflows to negative
            // If both large negative, underflows to positive
            return currentPnL + delta;
        }
    }
    
    function negateSafe(int256 value) internal pure returns (int256) {
        unchecked {
            // If value = type(int256).min, -value overflows!
            // Because |min| > |max| for signed ints
            return -value;
        }
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Handle signed edge cases
contract SecureSigned {
    function addPnL(int256 currentPnL, int256 delta) internal pure returns (int256) {
        // Solidity 0.8+ checks overflow by default
        return currentPnL + delta;
    }
    
    function negateSafe(int256 value) internal pure returns (int256) {
        require(value != type(int256).min, "Cannot negate min");
        return -value;
    }
    
    // Safe absolute value
    function abs(int256 value) internal pure returns (uint256) {
        if (value >= 0) {
            return uint256(value);
        }
        // Handle min value specially
        if (value == type(int256).min) {
            return uint256(type(int256).max) + 1;
        }
        return uint256(-value);
    }
}
```

---

### MATH-AP-06: Exponentiation Overflow

**Severity:** Medium | **Likelihood:** Low

**Description:**
Power operations grow extremely fast and easily overflow.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Exponential growth
contract VulnerableExponent {
    function compoundInterest(
        uint256 principal,
        uint256 rate,
        uint256 periods
    ) internal pure returns (uint256) {
        unchecked {
            // (1 + rate)^periods grows very fast
            // Even small rate with many periods overflows
            uint256 factor = (1e18 + rate) ** periods;
            return principal * factor / (1e18 ** periods);
        }
    }
    
    function power(uint256 base, uint256 exp) internal pure returns (uint256) {
        unchecked {
            uint256 result = 1;
            for (uint i = 0; i < exp; i++) {
                result *= base;  // Quick overflow
            }
            return result;
        }
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Bounded exponentiation
contract SecureExponent {
    uint256 public constant MAX_PERIODS = 365;
    
    function compoundInterest(
        uint256 principal,
        uint256 rate,
        uint256 periods
    ) internal pure returns (uint256) {
        require(periods <= MAX_PERIODS, "Too many periods");
        
        // Use iterative approach with overflow checks
        uint256 result = principal;
        for (uint256 i = 0; i < periods; i++) {
            result = result + Math.mulDiv(result, rate, 1e18);
        }
        return result;
    }
    
    // Or: Use logarithm-based approach for large exponents
    function safePow(uint256 base, uint256 exp) internal pure returns (uint256) {
        if (exp == 0) return 1;
        if (base == 0) return 0;
        if (base == 1) return 1;
        
        // Check if result would overflow
        uint256 maxExp = 256 / log2(base);
        require(exp <= maxExp, "Would overflow");
        
        return base ** exp;
    }
}
```

---

### MATH-AP-07: Array Length Overflow

**Severity:** Medium | **Likelihood:** Low

**Description:**
Operations on array length can overflow in older Solidity or unchecked blocks.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Array length manipulation
contract VulnerableArrayLength {
    uint256[] public values;
    
    function addMany(uint256 count) external {
        unchecked {
            // If values.length + count > type(uint256).max
            for (uint256 i = 0; i < count; i++) {
                values.push(0);
            }
        }
    }
    
    function processBackward() external {
        unchecked {
            // If values.length == 0, underflows
            for (uint256 i = values.length - 1; i >= 0; i--) {
                process(values[i]);
                if (i == 0) break;  // Doesn't help - already underflowed
            }
        }
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Safe array operations
contract SecureArrayLength {
    uint256[] public values;
    uint256 public constant MAX_ARRAY_LENGTH = 1000;
    
    function addMany(uint256 count) external {
        require(values.length + count <= MAX_ARRAY_LENGTH, "Array too large");
        
        for (uint256 i = 0; i < count; i++) {
            values.push(0);
        }
    }
    
    function processBackward() external {
        uint256 len = values.length;
        if (len == 0) return;
        
        // Process from end, stop at 0
        for (uint256 i = len; i > 0; ) {
            unchecked { i--; }  // Safe: i > 0 checked in condition
            process(values[i]);
        }
    }
}
```

---

### MATH-AP-08: Timestamp/Block Overflow

**Severity:** Low | **Likelihood:** Low

**Description:**
Time-based calculations can overflow with large timestamps or durations.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Timestamp multiplication
contract VulnerableTimestamp {
    function calculateInterest(
        uint256 principal,
        uint256 ratePerSecond,
        uint256 startTime
    ) internal view returns (uint256) {
        unchecked {
            uint256 elapsed = block.timestamp - startTime;
            // If elapsed is large and ratePerSecond not tiny, overflows
            return principal * ratePerSecond * elapsed / 1e18;
        }
    }
    
    function futureTimestamp(uint256 delay) internal view returns (uint256) {
        unchecked {
            // If delay is maliciously large, wraps around
            return block.timestamp + delay;
        }
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Bounded time calculations
contract SecureTimestamp {
    uint256 public constant MAX_DURATION = 365 days;
    uint256 public constant MAX_FUTURE = 10 * 365 days;
    
    function calculateInterest(
        uint256 principal,
        uint256 ratePerSecond,
        uint256 startTime
    ) internal view returns (uint256) {
        require(startTime <= block.timestamp, "Future start");
        uint256 elapsed = block.timestamp - startTime;
        require(elapsed <= MAX_DURATION, "Duration too long");
        
        return Math.mulDiv(principal * elapsed, ratePerSecond, 1e18);
    }
    
    function futureTimestamp(uint256 delay) internal view returns (uint256) {
        require(delay <= MAX_FUTURE, "Delay too long");
        return block.timestamp + delay;
    }
}
```

---

## Category 2: Rounding Errors Anti-Patterns

### MATH-AP-09: Incorrect Rounding Direction

**Severity:** High | **Likelihood:** High

**Description:**
Rounding in wrong direction allows users to extract value or receive more than deserved.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Always rounds same direction
contract VulnerableRounding {
    // Division always rounds down in Solidity
    
    function mintShares(uint256 assets) external returns (uint256 shares) {
        // Rounds DOWN - user gets fewer shares (correct)
        shares = assets * totalSupply / totalAssets;
    }
    
    function burnShares(uint256 shares) external returns (uint256 assets) {
        // Also rounds DOWN - user gets fewer assets (correct)
        assets = shares * totalAssets / totalSupply;
    }
    
    function requiredShares(uint256 assets) external view returns (uint256) {
        // Rounds DOWN - user burns fewer shares (WRONG!)
        // Should round UP for amount user pays
        return assets * totalSupply / totalAssets;
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Correct rounding per operation type
contract SecureRounding {
    // Round DOWN when calculating what user receives
    function convertToShares(uint256 assets) public view returns (uint256) {
        return Math.mulDiv(assets, totalSupply, totalAssets, Math.Rounding.Down);
    }
    
    // Round UP when calculating what user pays
    function previewMint(uint256 shares) public view returns (uint256 assets) {
        return Math.mulDiv(shares, totalAssets, totalSupply, Math.Rounding.Up);
    }
    
    // Round UP when calculating shares to burn
    function previewWithdraw(uint256 assets) public view returns (uint256 shares) {
        return Math.mulDiv(assets, totalSupply, totalAssets, Math.Rounding.Up);
    }
    
    // Manual round up
    function divUp(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a + b - 1) / b;
    }
}
```

---

### MATH-AP-10: Rounding Error Accumulation

**Severity:** Medium | **Likelihood:** Medium

**Description:**
Small rounding errors accumulate over many operations to become significant.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Per-user rounding accumulates
contract VulnerableAccumulation {
    function distributeRewards(address[] memory users, uint256 totalReward) external {
        uint256 rewardPerUser = totalReward / users.length;
        
        for (uint i = 0; i < users.length; i++) {
            // Each user gets rounded-down amount
            rewards[users[i]] += rewardPerUser;
        }
        
        // Lost rewards: totalReward - (rewardPerUser * users.length)
        // Could be up to (users.length - 1) units lost
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Track remainder and distribute fairly
contract SecureAccumulation {
    function distributeRewards(address[] memory users, uint256 totalReward) external {
        uint256 usersLength = users.length;
        uint256 rewardPerUser = totalReward / usersLength;
        uint256 remainder = totalReward % usersLength;
        
        for (uint i = 0; i < usersLength; i++) {
            uint256 reward = rewardPerUser;
            
            // Distribute remainder to first users
            if (i < remainder) {
                reward += 1;
            }
            
            rewards[users[i]] += reward;
        }
    }
    
    // Alternative: Use running calculation
    function distributeExact(address[] memory users, uint256 totalReward) external {
        uint256 distributed = 0;
        
        for (uint i = 0; i < users.length; i++) {
            uint256 share = (totalReward * (i + 1) / users.length) - distributed;
            rewards[users[i]] += share;
            distributed += share;
        }
    }
}
```

---

### MATH-AP-11: Zero Result from Small Inputs

**Severity:** High | **Likelihood:** Medium

**Description:**
Small values divided by large values result in zero, losing user funds.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Small numerator, large denominator
contract VulnerableZeroResult {
    function calculateFee(uint256 amount) internal pure returns (uint256) {
        // If amount = 100 and FEE_BPS = 10, fee = 100 * 10 / 10000 = 0
        return amount * FEE_BPS / 10000;
    }
    
    function getSharePrice(uint256 shares) internal view returns (uint256) {
        // If totalAssets = 1e6 and totalSupply = 1e18
        // Price = 1e6 / 1e18 = 0
        return totalAssets / totalSupply;
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Scale up or set minimums
contract SecureZeroResult {
    uint256 public constant PRECISION = 1e18;
    uint256 public constant MIN_FEE = 1;
    
    function calculateFee(uint256 amount) internal pure returns (uint256) {
        uint256 fee = amount * FEE_BPS / 10000;
        // Ensure minimum fee if amount warrants it
        if (fee == 0 && amount > 10000 / FEE_BPS) {
            return MIN_FEE;
        }
        return fee;
    }
    
    function getSharePrice(uint256 shares) internal view returns (uint256) {
        // Return price in PRECISION units
        return totalAssets * PRECISION / totalSupply;
    }
    
    // Alternative: Require minimum amounts
    function deposit(uint256 amount) external {
        require(amount >= MIN_DEPOSIT, "Amount too small");
        uint256 shares = amount * totalSupply / totalAssets;
        require(shares > 0, "Shares would be zero");
        // ...
    }
}
```

---

### MATH-AP-12: Truncation in Token Conversions

**Severity:** Medium | **Likelihood:** High

**Description:**
Converting between tokens with different decimals truncates value.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Simple division truncates
contract VulnerableTruncation {
    // USDC: 6 decimals, DAI: 18 decimals
    
    function convertUsdcToDai(uint256 usdcAmount) internal pure returns (uint256) {
        // Correct: multiply up
        return usdcAmount * 1e12;
    }
    
    function convertDaiToUsdc(uint256 daiAmount) internal pure returns (uint256) {
        // DANGEROUS: Truncates 12 decimal places
        return daiAmount / 1e12;
        // 1.5e6 DAI (1.5 tokens) → 1 USDC (0.000001 tokens)
        // Lost: 0.5e6 worth
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Handle truncation explicitly
contract SecureTruncation {
    function convertDaiToUsdc(uint256 daiAmount) internal pure returns (uint256) {
        // Round down (caller receives less - safe)
        return daiAmount / 1e12;
    }
    
    function convertDaiToUsdcUp(uint256 daiAmount) internal pure returns (uint256) {
        // Round up when user is paying
        return (daiAmount + 1e12 - 1) / 1e12;
    }
    
    // Track dust
    function convertWithDust(uint256 daiAmount) internal returns (uint256 usdc, uint256 dustDai) {
        usdc = daiAmount / 1e12;
        dustDai = daiAmount % 1e12;
        // Handle dust separately (return to user, accumulate, etc.)
    }
}
```

---

### MATH-AP-13: Fee Rounding Exploitation

**Severity:** Medium | **Likelihood:** High

**Description:**
Fee calculations that round to zero allow free transactions.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Fee rounds to zero for small amounts
contract VulnerableFeeRounding {
    uint256 public constant FEE_PERCENT = 3; // 0.03%
    
    function calculateFee(uint256 amount) public pure returns (uint256) {
        return amount * FEE_PERCENT / 10000;
        // amount = 100 → fee = 0
        // User can do many small txs fee-free
    }
    
    function swap(uint256 amountIn) external {
        uint256 fee = calculateFee(amountIn);
        uint256 amountOut = amountIn - fee;
        // If fee = 0, no protocol revenue
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Minimum fee enforcement
contract SecureFeeRounding {
    uint256 public constant FEE_PERCENT = 3;
    uint256 public constant MIN_FEE = 1;
    uint256 public constant MIN_AMOUNT = 10000; // Minimum where fee > 0
    
    function calculateFee(uint256 amount) public pure returns (uint256) {
        uint256 fee = amount * FEE_PERCENT / 10000;
        
        // Enforce minimum fee for non-trivial amounts
        if (amount >= MIN_AMOUNT && fee < MIN_FEE) {
            return MIN_FEE;
        }
        return fee;
    }
    
    // Alternative: Require minimum trade size
    function swap(uint256 amountIn) external {
        require(amountIn >= MIN_AMOUNT, "Amount too small");
        // ...
    }
}
```

---

### MATH-AP-14: Share/Asset Rounding Asymmetry

**Severity:** High | **Likelihood:** Medium

**Description:**
Asymmetric rounding in deposit/withdraw creates arbitrage opportunity.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Rounding creates free value
contract VulnerableAsymmetry {
    function deposit(uint256 assets) external returns (uint256 shares) {
        // User deposits assets, gets shares (round down - they get less)
        shares = assets * totalSupply / totalAssets;
    }
    
    function withdraw(uint256 assets) external returns (uint256 shares) {
        // User requests assets, burns shares
        // Round DOWN - they burn fewer shares (WRONG!)
        shares = assets * totalSupply / totalAssets;
    }
    
    // Attack:
    // 1. Deposit small amount, round down on shares received
    // 2. Withdraw same assets, round down on shares burned
    // 3. Net: Burned fewer shares than received
    // 4. Repeat to extract value
}
```

**Secure Pattern:**
```solidity
// SECURE: Consistent rounding against user
contract SecureSymmetry {
    function deposit(uint256 assets) external returns (uint256 shares) {
        // Round DOWN - user receives fewer shares
        shares = Math.mulDiv(assets, totalSupply, totalAssets, Math.Rounding.Down);
    }
    
    function withdraw(uint256 assets) external returns (uint256 shares) {
        // Round UP - user burns more shares
        shares = Math.mulDiv(assets, totalSupply, totalAssets, Math.Rounding.Up);
    }
    
    function redeem(uint256 shares) external returns (uint256 assets) {
        // Round DOWN - user receives fewer assets
        assets = Math.mulDiv(shares, totalAssets, totalSupply, Math.Rounding.Down);
    }
    
    function mint(uint256 shares) external returns (uint256 assets) {
        // Round UP - user pays more assets
        assets = Math.mulDiv(shares, totalAssets, totalSupply, Math.Rounding.Up);
    }
}
```

---

### MATH-AP-15: Price Rounding in AMMs

**Severity:** Medium | **Likelihood:** High

**Description:**
AMM price calculations round incorrectly, allowing extraction.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Rounding favors trader
contract VulnerableAMM {
    function getAmountOut(
        uint256 amountIn,
        uint256 reserveIn,
        uint256 reserveOut
    ) public pure returns (uint256) {
        uint256 amountInWithFee = amountIn * 997;
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = (reserveIn * 1000) + amountInWithFee;
        
        // Rounds DOWN - but for small trades, might give 1 more than deserved
        return numerator / denominator;
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Always round against trader
contract SecureAMM {
    function getAmountOut(
        uint256 amountIn,
        uint256 reserveIn,
        uint256 reserveOut
    ) public pure returns (uint256) {
        require(amountIn > 0, "Zero input");
        require(reserveIn > 0 && reserveOut > 0, "Zero reserves");
        
        uint256 amountInWithFee = amountIn * 997;
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = (reserveIn * 1000) + amountInWithFee;
        
        // Round DOWN for amount out (trader receives less)
        return numerator / denominator;
    }
    
    function getAmountIn(
        uint256 amountOut,
        uint256 reserveIn,
        uint256 reserveOut
    ) public pure returns (uint256) {
        require(amountOut > 0 && amountOut < reserveOut, "Invalid output");
        
        uint256 numerator = reserveIn * amountOut * 1000;
        uint256 denominator = (reserveOut - amountOut) * 997;
        
        // Round UP for amount in (trader pays more)
        return (numerator / denominator) + 1;
    }
}
```

---

### MATH-AP-16: Percentage Rounding Issues

**Severity:** Medium | **Likelihood:** Medium

**Description:**
Percentage calculations don't round correctly for basis points.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Percentage math issues
contract VulnerablePercentage {
    function applyPercentage(uint256 amount, uint256 percent) internal pure returns (uint256) {
        // percent = 100 means 1%, but what if percent = 1 (0.01%)?
        return amount * percent / 10000;
        
        // amount = 50, percent = 1 → 0 (should be ~0.005)
    }
    
    function calculateAllocation(uint256 total, uint256[] memory percentages) internal pure returns (uint256[] memory) {
        uint256[] memory amounts = new uint256[](percentages.length);
        
        for (uint i = 0; i < percentages.length; i++) {
            amounts[i] = total * percentages[i] / 10000;
        }
        
        // Sum of amounts might not equal total due to rounding
        return amounts;
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Handle percentage edge cases
contract SecurePercentage {
    function applyPercentage(
        uint256 amount,
        uint256 basisPoints,
        bool roundUp
    ) internal pure returns (uint256) {
        if (roundUp) {
            return (amount * basisPoints + 9999) / 10000;
        }
        return amount * basisPoints / 10000;
    }
    
    function calculateAllocationExact(
        uint256 total,
        uint256[] memory percentages
    ) internal pure returns (uint256[] memory) {
        uint256[] memory amounts = new uint256[](percentages.length);
        uint256 distributed = 0;
        
        // Last allocation gets remainder
        for (uint i = 0; i < percentages.length - 1; i++) {
            amounts[i] = total * percentages[i] / 10000;
            distributed += amounts[i];
        }
        
        // Final gets remainder to ensure sum = total
        amounts[percentages.length - 1] = total - distributed;
        
        return amounts;
    }
}
```

---

## Category 3: Precision Loss Anti-Patterns

### MATH-AP-17: Division Before Multiplication

**Severity:** High | **Likelihood:** High

**Description:**
Dividing before multiplying causes precision loss from truncation.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Divide first, then multiply
contract VulnerableDivisionFirst {
    function calculateShare(
        uint256 userAmount,
        uint256 totalAmount,
        uint256 totalReward
    ) internal pure returns (uint256) {
        // Division first loses precision
        uint256 ratio = userAmount / totalAmount;  // Often = 0!
        return ratio * totalReward;  // = 0
    }
    
    function getPrice(uint256 amount) internal view returns (uint256) {
        // If basePrice = 100, amount = 50, FACTOR = 1000
        // (100 / 1000) * 50 = 0 * 50 = 0 (WRONG)
        return (basePrice / FACTOR) * amount;
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Multiply first, then divide
contract SecureMultiplyFirst {
    function calculateShare(
        uint256 userAmount,
        uint256 totalAmount,
        uint256 totalReward
    ) internal pure returns (uint256) {
        // Multiply first maintains precision
        return userAmount * totalReward / totalAmount;
        
        // Or use mulDiv for overflow protection
        return Math.mulDiv(userAmount, totalReward, totalAmount);
    }
    
    function getPrice(uint256 amount) internal view returns (uint256) {
        // (100 * 50) / 1000 = 5000 / 1000 = 5 (CORRECT)
        return basePrice * amount / FACTOR;
    }
}
```

---

### MATH-AP-18: Precision Loss in Price Feeds

**Severity:** High | **Likelihood:** Medium

**Description:**
Oracle prices with limited decimals lose precision in calculations.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Price precision too low
contract VulnerablePricePrecision {
    // Chainlink ETH/USD has 8 decimals
    // Price = 200000000000 ($2000.00000000)
    
    function getEthValue(uint256 usdAmount) internal view returns (uint256) {
        uint256 ethPrice = oracle.latestAnswer();  // 8 decimals
        
        // usdAmount in 6 decimals (USDC)
        // Want ETH in 18 decimals
        // This loses precision:
        return usdAmount * 1e18 / ethPrice;
        // Better to scale properly
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Handle decimal differences explicitly
contract SecurePricePrecision {
    uint8 public constant USD_DECIMALS = 6;
    uint8 public constant ETH_DECIMALS = 18;
    uint8 public constant PRICE_DECIMALS = 8;
    
    function getEthValue(uint256 usdAmount) internal view returns (uint256) {
        uint256 ethPrice = oracle.latestAnswer();  // 8 decimals
        
        // Scale to common precision before division
        // usdAmount (6 dec) * 1e18 (ETH dec) * 1e8 (price dec) / price / 1e6 (USD dec)
        return Math.mulDiv(
            usdAmount * 10**(ETH_DECIMALS + PRICE_DECIMALS - USD_DECIMALS),
            1,
            ethPrice
        );
    }
    
    // Alternative: Use scaled multiplication
    function getEthValueScaled(uint256 usdAmount) internal view returns (uint256) {
        uint256 ethPrice = oracle.latestAnswer();
        
        // Scale USD to 18 decimals first
        uint256 usdScaled = usdAmount * 10**(ETH_DECIMALS - USD_DECIMALS);
        
        // Convert using price (with 8 decimal adjustment)
        return usdScaled * 10**PRICE_DECIMALS / ethPrice;
    }
}
```

---

### MATH-AP-19: Interest Rate Precision Loss

**Severity:** High | **Likelihood:** Medium

**Description:**
Interest calculations lose precision over time or with small rates.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Per-second rate loses precision
contract VulnerableInterest {
    uint256 public constant ANNUAL_RATE = 500; // 5% in basis points
    
    function accrueInterest(uint256 principal, uint256 secondsElapsed) internal pure returns (uint256) {
        // Convert annual to per-second (loses precision)
        uint256 ratePerSecond = ANNUAL_RATE / (365 days * 10000);  // = 0!
        return principal + principal * ratePerSecond * secondsElapsed;
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Use high-precision rate constants
contract SecureInterest {
    // Rate in RAY (27 decimals) per second
    uint256 public constant RATE_PER_SECOND = 1000000001547125957863212448; // ~5% APY
    uint256 public constant RAY = 1e27;
    
    function accrueInterest(
        uint256 principal,
        uint256 secondsElapsed
    ) internal pure returns (uint256) {
        // Compound interest with high precision
        uint256 rate = rpow(RATE_PER_SECOND, secondsElapsed, RAY);
        return principal * rate / RAY;
    }
    
    // Exponentiation for compound interest
    function rpow(uint256 x, uint256 n, uint256 base) internal pure returns (uint256 z) {
        assembly {
            switch x
            case 0 {
                switch n
                case 0 { z := base }
                default { z := 0 }
            }
            default {
                switch mod(n, 2)
                case 0 { z := base }
                default { z := x }
                let half := div(base, 2)
                for { n := div(n, 2) } n { n := div(n, 2) } {
                    let xx := mul(x, x)
                    if iszero(eq(div(xx, x), x)) { revert(0, 0) }
                    let xxRound := add(xx, half)
                    if lt(xxRound, xx) { revert(0, 0) }
                    x := div(xxRound, base)
                    if mod(n, 2) {
                        let zx := mul(z, x)
                        if and(iszero(iszero(x)), iszero(eq(div(zx, x), z))) { revert(0, 0) }
                        let zxRound := add(zx, half)
                        if lt(zxRound, zx) { revert(0, 0) }
                        z := div(zxRound, base)
                    }
                }
            }
        }
    }
}
```

---

### MATH-AP-20: Decimal Mismatch

**Severity:** High | **Likelihood:** High

**Description:**
Operations between values with different decimal scales produce wrong results.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Mixing decimals without scaling
contract VulnerableDecimalMix {
    function calculateTotal(
        uint256 usdcAmount,  // 6 decimals
        uint256 daiAmount    // 18 decimals
    ) internal pure returns (uint256) {
        // WRONG: Different decimal scales
        return usdcAmount + daiAmount;
        // 1 USDC + 1 DAI = 1000000 + 1000000000000000000 
        // = 1000000000001000000 (completely wrong)
    }
    
    function getPrice(
        uint256 token0Amount,  // Unknown decimals
        uint256 token1Amount   // Unknown decimals
    ) internal pure returns (uint256) {
        // Assumes same decimals - dangerous
        return token0Amount * 1e18 / token1Amount;
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Explicit decimal handling
contract SecureDecimalMix {
    function calculateTotal(
        uint256 usdcAmount,
        uint256 daiAmount
    ) internal pure returns (uint256) {
        // Normalize to 18 decimals
        uint256 usdcNormalized = usdcAmount * 1e12; // 6 → 18
        return usdcNormalized + daiAmount;
    }
    
    function getPrice(
        IERC20Metadata token0,
        uint256 token0Amount,
        IERC20Metadata token1,
        uint256 token1Amount
    ) internal view returns (uint256) {
        uint8 dec0 = token0.decimals();
        uint8 dec1 = token1.decimals();
        
        // Normalize both to 18 decimals
        uint256 normalized0 = token0Amount * 10**(18 - dec0);
        uint256 normalized1 = token1Amount * 10**(18 - dec1);
        
        return normalized0 * 1e18 / normalized1;
    }
}
```

---

### MATH-AP-21: Reward Rate Underflow

**Severity:** High | **Likelihood:** Medium

**Description:**
Reward per share/token becomes zero when distributed over too many tokens.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Reward rate can underflow to zero
contract VulnerableRewardRate {
    uint256 public rewardPerTokenStored;
    
    function updateReward(uint256 reward, uint256 duration) external {
        // If totalSupply = 1e24 and reward = 1e18 and duration = 7 days
        // rewardRate = 1e18 / 604800 = ~1.6e12
        // rewardPerToken = 1.6e12 / 1e24 = 0!
        uint256 rewardRate = reward / duration;
        rewardPerTokenStored += rewardRate * duration / totalSupply;
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: High-precision reward accounting
contract SecureRewardRate {
    uint256 public constant PRECISION = 1e36;
    uint256 public rewardPerTokenStored;
    
    function updateReward(uint256 reward, uint256 duration) external {
        require(totalSupply > 0, "No stakers");
        
        // Use high precision multiplier
        uint256 rewardRate = reward * PRECISION / duration;
        rewardPerTokenStored += rewardRate * duration / totalSupply;
        
        // rewardPerToken has PRECISION scaling
        // Divide by PRECISION when claiming
    }
    
    function earned(address account) public view returns (uint256) {
        uint256 perToken = rewardPerTokenStored - userRewardPerTokenPaid[account];
        return balances[account] * perToken / PRECISION;
    }
}
```

---

### MATH-AP-22: LP Token Precision

**Severity:** Medium | **Likelihood:** Medium

**Description:**
LP token calculations lose precision with extreme reserve ratios.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: LP mint precision loss
contract VulnerableLPPrecision {
    function mint(address to) external returns (uint256 liquidity) {
        uint256 balance0 = token0.balanceOf(address(this));
        uint256 balance1 = token1.balanceOf(address(this));
        uint256 amount0 = balance0 - reserve0;
        uint256 amount1 = balance1 - reserve1;
        
        if (totalSupply == 0) {
            liquidity = sqrt(amount0 * amount1);  // Might underflow for small amounts
        } else {
            // If reserves very large and amounts small
            // liquidity could be 0
            liquidity = min(
                amount0 * totalSupply / reserve0,
                amount1 * totalSupply / reserve1
            );
        }
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Minimum liquidity + precision handling
contract SecureLPPrecision {
    uint256 public constant MINIMUM_LIQUIDITY = 1000;
    
    function mint(address to) external returns (uint256 liquidity) {
        uint256 amount0 = token0.balanceOf(address(this)) - reserve0;
        uint256 amount1 = token1.balanceOf(address(this)) - reserve1;
        
        if (totalSupply == 0) {
            liquidity = sqrt(amount0 * amount1) - MINIMUM_LIQUIDITY;
            _mint(address(0), MINIMUM_LIQUIDITY);  // Permanently lock
        } else {
            liquidity = Math.min(
                Math.mulDiv(amount0, totalSupply, reserve0),
                Math.mulDiv(amount1, totalSupply, reserve1)
            );
        }
        
        require(liquidity > 0, "Insufficient liquidity minted");
        _mint(to, liquidity);
    }
}
```

---

### MATH-AP-23: Collateral Ratio Precision

**Severity:** High | **Likelihood:** Medium

**Description:**
Collateral ratio calculations lose precision, affecting liquidation thresholds.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: CR calculation loses precision
contract VulnerableCR {
    uint256 public constant MIN_CR = 15000; // 150% in basis points
    
    function isLiquidatable(address user) public view returns (bool) {
        uint256 collateralValue = getCollateralValue(user);
        uint256 debtValue = getDebtValue(user);
        
        // If values are small, CR calculation loses precision
        uint256 cr = collateralValue * 10000 / debtValue;
        return cr < MIN_CR;
        
        // collateral = 150, debt = 100
        // cr = 150 * 10000 / 100 = 15000 (exactly at threshold)
        // But rounding could make it 14999 and trigger liquidation
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: High-precision CR with buffer
contract SecureCR {
    uint256 public constant PRECISION = 1e18;
    uint256 public constant MIN_CR = 15e17; // 150% with 18 decimal precision
    
    function isLiquidatable(address user) public view returns (bool) {
        uint256 collateralValue = getCollateralValue(user);
        uint256 debtValue = getDebtValue(user);
        
        if (debtValue == 0) return false;
        
        // Use high precision and mulDiv
        uint256 cr = Math.mulDiv(collateralValue, PRECISION, debtValue);
        return cr < MIN_CR;
    }
    
    // Alternative: Avoid division entirely
    function isLiquidatableNoDivision(address user) public view returns (bool) {
        uint256 collateralValue = getCollateralValue(user);
        uint256 debtValue = getDebtValue(user);
        
        // collateral / debt < 1.5 equivalent to collateral * 10 < debt * 15
        return collateralValue * 10 < debtValue * 15;
    }
}
```

---

### MATH-AP-24: Voting Power Precision

**Severity:** Medium | **Likelihood:** Medium

**Description:**
Governance voting power calculations lose precision for small holders.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Small holders have 0 voting power
contract VulnerableVoting {
    function getVotingPower(address user) public view returns (uint256) {
        uint256 balance = token.balanceOf(user);
        uint256 totalSupply = token.totalSupply();
        
        // User with 100 tokens, total 1e24
        // Power = 100 * 10000 / 1e24 = 0
        return balance * 10000 / totalSupply;
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Raw balance as voting power
contract SecureVoting {
    // Use raw balance as voting power
    function getVotingPower(address user) public view returns (uint256) {
        return token.balanceOf(user);
    }
    
    // Calculate percentage only when needed for display
    function getVotingPowerPercentage(address user) public view returns (uint256) {
        uint256 balance = token.balanceOf(user);
        uint256 totalSupply = token.totalSupply();
        
        // Return with 18 decimal precision
        return Math.mulDiv(balance, 1e18, totalSupply);
    }
    
    // For quorum checks, use absolute amounts
    function hasQuorum(uint256 votesFor) public view returns (bool) {
        // 4% quorum
        return votesFor >= token.totalSupply() * 4 / 100;
    }
}
```

---

## Category 4: Fixed-Point Math Anti-Patterns

### MATH-AP-25: WAD/RAY Mixing

**Severity:** Critical | **Likelihood:** Medium

**Description:**
Mixing different fixed-point scales (WAD=1e18, RAY=1e27) causes massive errors.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Mixing WAD and RAY
contract VulnerableWadRay {
    uint256 public constant WAD = 1e18;
    uint256 public constant RAY = 1e27;
    
    function calculate(uint256 wadValue, uint256 rayRate) internal pure returns (uint256) {
        // WRONG: Different scales
        return wadValue * rayRate / WAD;  // Result is off by 1e9!
    }
    
    function addRates(uint256 wadRate, uint256 rayRate) internal pure returns (uint256) {
        // WRONG: Adding different scales
        return wadRate + rayRate;  // Nonsensical result
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Explicit scale conversions
contract SecureWadRay {
    uint256 public constant WAD = 1e18;
    uint256 public constant RAY = 1e27;
    uint256 public constant WAD_RAY_RATIO = 1e9;
    
    function wadToRay(uint256 wad) internal pure returns (uint256) {
        return wad * WAD_RAY_RATIO;
    }
    
    function rayToWad(uint256 ray) internal pure returns (uint256) {
        return ray / WAD_RAY_RATIO;
    }
    
    function calculate(uint256 wadValue, uint256 rayRate) internal pure returns (uint256) {
        // Convert to same scale first
        uint256 rayValue = wadToRay(wadValue);
        return rayValue * rayRate / RAY;
    }
    
    // Aave-style RAY multiplication
    function rayMul(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a * b + RAY / 2) / RAY;
    }
    
    function rayDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a * RAY + b / 2) / b;
    }
}
```

---

### MATH-AP-26: Fixed-Point Overflow

**Severity:** High | **Likelihood:** Medium

**Description:**
Fixed-point multiplication overflows before division can reduce the result.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Overflow in intermediate calculation
contract VulnerableFixedOverflow {
    uint256 public constant WAD = 1e18;
    
    function wadMul(uint256 a, uint256 b) internal pure returns (uint256) {
        // If a = 1e40 and b = 1e40
        // a * b = 1e80 (OVERFLOW!)
        return a * b / WAD;
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Use mulDiv or split calculation
contract SecureFixedOverflow {
    uint256 public constant WAD = 1e18;
    
    function wadMul(uint256 a, uint256 b) internal pure returns (uint256) {
        // OpenZeppelin's mulDiv handles overflow
        return Math.mulDiv(a, b, WAD);
    }
    
    // Or: FullMath from Uniswap V3
    function mulDiv(
        uint256 a,
        uint256 b,
        uint256 denominator
    ) internal pure returns (uint256 result) {
        // 512-bit intermediate calculation
        uint256 prod0;
        uint256 prod1;
        assembly {
            let mm := mulmod(a, b, not(0))
            prod0 := mul(a, b)
            prod1 := sub(sub(mm, prod0), lt(mm, prod0))
        }
        
        if (prod1 == 0) {
            return prod0 / denominator;
        }
        
        // Full precision division...
    }
}
```

---

### MATH-AP-27: Fixed-Point Rounding

**Severity:** Medium | **Likelihood:** High

**Description:**
Fixed-point operations always round down, which may not be desired.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No rounding control
contract VulnerableFixedRounding {
    uint256 public constant WAD = 1e18;
    
    function wadDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        // Always rounds down
        return a * WAD / b;
    }
    
    function getAmountToPay(uint256 price, uint256 quantity) internal pure returns (uint256) {
        // User should pay more if rounding, not less
        return wadDiv(price, quantity);  // Rounds down = user pays less
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Explicit rounding control
contract SecureFixedRounding {
    uint256 public constant WAD = 1e18;
    
    function wadDivDown(uint256 a, uint256 b) internal pure returns (uint256) {
        return a * WAD / b;
    }
    
    function wadDivUp(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a * WAD + b - 1) / b;
    }
    
    function wadMulDown(uint256 a, uint256 b) internal pure returns (uint256) {
        return a * b / WAD;
    }
    
    function wadMulUp(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a * b + WAD - 1) / WAD;
    }
    
    // Aave-style with half-rounding
    function rayMul(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a * b + RAY / 2) / RAY;  // Round to nearest
    }
}
```

---

### MATH-AP-28: Scale Conversion Loss

**Severity:** Medium | **Likelihood:** Medium

**Description:**
Converting between fixed-point scales loses precision.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Precision loss in conversion
contract VulnerableScaleConversion {
    uint256 public constant WAD = 1e18;
    uint256 public constant BPS = 1e4;
    
    function wadToBps(uint256 wadValue) internal pure returns (uint256) {
        // 1.5e18 WAD → 15000 BPS → loses sub-BPS precision
        return wadValue / 1e14;
    }
    
    function bpsToWad(uint256 bpsValue) internal pure returns (uint256) {
        // Information already lost
        return bpsValue * 1e14;
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Avoid unnecessary conversions
contract SecureScaleConversion {
    uint256 public constant WAD = 1e18;
    
    // Keep in highest precision as long as possible
    // Only convert for display/external interfaces
    
    function calculateWithBps(uint256 amount, uint256 bps) internal pure returns (uint256) {
        // Convert BPS to WAD for calculation, not vice versa
        uint256 wadRate = bps * 1e14;  // BPS to WAD
        return amount * wadRate / WAD;
    }
    
    // When conversion is necessary, round appropriately
    function wadToBpsRoundUp(uint256 wadValue) internal pure returns (uint256) {
        return (wadValue + 1e14 - 1) / 1e14;
    }
}
```

---

### MATH-AP-29: Compound Interest Fixed-Point

**Severity:** Medium | **Likelihood:** Medium

**Description:**
Compound interest with fixed-point math accumulates errors.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Simple compounding loses precision
contract VulnerableCompound {
    uint256 public constant WAD = 1e18;
    
    function compound(
        uint256 principal,
        uint256 rate,
        uint256 periods
    ) internal pure returns (uint256) {
        uint256 result = principal;
        
        for (uint256 i = 0; i < periods; i++) {
            // Each iteration loses precision
            result = result + result * rate / WAD;
        }
        
        return result;
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Use exponentiation for compound interest
contract SecureCompound {
    uint256 public constant RAY = 1e27;
    
    function compound(
        uint256 principal,
        uint256 rayRatePerPeriod,
        uint256 periods
    ) internal pure returns (uint256) {
        // (1 + rate)^periods using rayPow
        uint256 compoundFactor = rayPow(RAY + rayRatePerPeriod, periods);
        return principal * compoundFactor / RAY;
    }
    
    function rayPow(uint256 x, uint256 n) internal pure returns (uint256 z) {
        z = n % 2 != 0 ? x : RAY;
        
        for (n /= 2; n != 0; n /= 2) {
            x = rayMul(x, x);
            if (n % 2 != 0) {
                z = rayMul(z, x);
            }
        }
    }
    
    function rayMul(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a * b + RAY / 2) / RAY;
    }
}
```

---

### MATH-AP-30: Fixed-Point Division By Small Number

**Severity:** High | **Likelihood:** Medium

**Description:**
Fixed-point division by small numbers amplifies precision issues.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Division by small number
contract VulnerableDivSmall {
    uint256 public constant WAD = 1e18;
    
    function wadDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        // If b is small, result is huge and loses precision
        // a = 1e18, b = 1 → result = 1e36 (overflow possible)
        return a * WAD / b;
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Validate divisor and use safe math
contract SecureDivSmall {
    uint256 public constant WAD = 1e18;
    uint256 public constant MIN_DIVISOR = 1e9; // Minimum divisor
    
    function wadDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b >= MIN_DIVISOR, "Divisor too small");
        return Math.mulDiv(a, WAD, b);
    }
    
    // Alternative: Cap result
    function wadDivCapped(uint256 a, uint256 b) internal pure returns (uint256) {
        if (b == 0) return type(uint256).max;
        uint256 result = Math.mulDiv(a, WAD, b);
        return Math.min(result, type(uint128).max); // Cap to reasonable value
    }
}
```

---

### MATH-AP-31: Percentage as Fixed-Point

**Severity:** Medium | **Likelihood:** Medium

**Description:**
Mixing percentage (0-100) with fixed-point (0-1e18) causes errors.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Percentage treated as fixed-point
contract VulnerablePercentFixed {
    uint256 public constant WAD = 1e18;
    
    function applyPercentage(uint256 amount, uint256 percent) internal pure returns (uint256) {
        // If percent = 50 (meaning 50%), this treats it as WAD
        // 100 * 50 / 1e18 = 0 (WRONG, should be 50)
        return amount * percent / WAD;
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Clear percentage handling
contract SecurePercentFixed {
    uint256 public constant WAD = 1e18;
    uint256 public constant PERCENT_BASE = 100;
    uint256 public constant BPS_BASE = 10000;
    
    // Percentage (0-100)
    function applyPercent(uint256 amount, uint256 percent) internal pure returns (uint256) {
        return amount * percent / PERCENT_BASE;
    }
    
    // Basis points (0-10000)
    function applyBps(uint256 amount, uint256 bps) internal pure returns (uint256) {
        return amount * bps / BPS_BASE;
    }
    
    // WAD (0-1e18)
    function applyWad(uint256 amount, uint256 wadRate) internal pure returns (uint256) {
        return amount * wadRate / WAD;
    }
    
    // Convert between formats
    function percentToWad(uint256 percent) internal pure returns (uint256) {
        return percent * WAD / PERCENT_BASE;
    }
}
```

---

### MATH-AP-32: Price Scaling Issues

**Severity:** High | **Likelihood:** Medium

**Description:**
Price values with inconsistent scaling cause trade execution errors.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Price scale assumption
contract VulnerablePriceScale {
    function executeTrade(
        uint256 amount,
        uint256 price  // What decimals?
    ) internal pure returns (uint256) {
        // Assumes price has 18 decimals
        // But might have 8 (Chainlink) or 6 (USDC quote)
        return amount * price / 1e18;
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Explicit price scaling
contract SecurePriceScale {
    struct Price {
        uint256 value;
        uint8 decimals;
    }
    
    function executeTrade(
        uint256 amount,
        uint8 amountDecimals,
        Price memory price,
        uint8 outputDecimals
    ) internal pure returns (uint256) {
        // Normalize everything
        uint256 numerator = amount * price.value;
        
        // Adjust for decimal differences
        int8 decimalAdjustment = int8(outputDecimals) - int8(amountDecimals) - int8(price.decimals);
        
        if (decimalAdjustment > 0) {
            return numerator * 10**uint8(decimalAdjustment);
        } else if (decimalAdjustment < 0) {
            return numerator / 10**uint8(-decimalAdjustment);
        }
        return numerator;
    }
}
```

---

## Category 5: Calculation Order Anti-Patterns

### MATH-AP-33: Order of Operations

**Severity:** High | **Likelihood:** High

**Description:**
Incorrect operation order causes dramatically different results.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Wrong operation order
contract VulnerableOrder {
    function calculate(uint256 a, uint256 b, uint256 c) internal pure returns (uint256) {
        // Intention: (a + b) * c
        // Actual: a + (b * c) due to precedence
        return a + b * c;
    }
    
    function fee(uint256 amount) internal pure returns (uint256) {
        // Intention: amount - (amount * 3 / 100)
        // But: (amount - amount) * 3 / 100 = 0
        return amount - amount * 3 / 100;  // Actually correct, but confusing
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Explicit parentheses
contract SecureOrder {
    function calculate(uint256 a, uint256 b, uint256 c) internal pure returns (uint256) {
        return (a + b) * c;  // Clear intention
    }
    
    function fee(uint256 amount) internal pure returns (uint256) {
        uint256 feeAmount = amount * 3 / 100;
        return amount - feeAmount;  // Break into steps for clarity
    }
}
```

---

### MATH-AP-34: Intermediate Value Overflow

**Severity:** High | **Likelihood:** Medium

**Description:**
Intermediate calculation results overflow even if final result would fit.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Intermediate overflow
contract VulnerableIntermediate {
    function calculateShare(
        uint256 userBalance,
        uint256 totalReward,
        uint256 totalSupply
    ) internal pure returns (uint256) {
        // userBalance * totalReward might overflow
        // even though final result fits in uint256
        return userBalance * totalReward / totalSupply;
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Use mulDiv
contract SecureIntermediate {
    function calculateShare(
        uint256 userBalance,
        uint256 totalReward,
        uint256 totalSupply
    ) internal pure returns (uint256) {
        // Handles 512-bit intermediate
        return Math.mulDiv(userBalance, totalReward, totalSupply);
    }
    
    // Or reorder if possible
    function calculateShareReordered(
        uint256 userBalance,
        uint256 totalReward,
        uint256 totalSupply
    ) internal pure returns (uint256) {
        // If userBalance < totalSupply, divide first
        if (userBalance < totalSupply) {
            return totalReward * userBalance / totalSupply;
        }
        // Otherwise use mulDiv
        return Math.mulDiv(userBalance, totalReward, totalSupply);
    }
}
```

---

### MATH-AP-35: Sequential Division Precision Loss

**Severity:** Medium | **Likelihood:** Medium

**Description:**
Multiple sequential divisions compound precision loss.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Multiple divisions
contract VulnerableSequentialDiv {
    function calculate(uint256 a, uint256 b, uint256 c, uint256 d) internal pure returns (uint256) {
        // Each division loses precision
        return a / b / c / d;
        
        // a=1000, b=3, c=3, d=3
        // 1000/3 = 333, 333/3 = 111, 111/3 = 37
        // Actual: 1000/27 = 37.037...
        // Lost: 0.037 * scaling
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Single division
contract SecureSequentialDiv {
    function calculate(uint256 a, uint256 b, uint256 c, uint256 d) internal pure returns (uint256) {
        // Single division preserves more precision
        return a / (b * c * d);
        
        // Or multiply first
        // a * X / (b * c * d) where X is scaling factor
    }
}
```

---

### MATH-AP-36: Average Calculation Issues

**Severity:** Medium | **Likelihood:** Medium

**Description:**
Average calculations can overflow or lose precision.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Average overflow
contract VulnerableAverage {
    function average(uint256 a, uint256 b) internal pure returns (uint256) {
        // If a + b > type(uint256).max, overflows
        return (a + b) / 2;
    }
    
    function weightedAverage(
        uint256 value1,
        uint256 weight1,
        uint256 value2,
        uint256 weight2
    ) internal pure returns (uint256) {
        // Multiple overflow possibilities
        return (value1 * weight1 + value2 * weight2) / (weight1 + weight2);
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Overflow-safe average
contract SecureAverage {
    function average(uint256 a, uint256 b) internal pure returns (uint256) {
        // From OpenZeppelin
        return (a & b) + (a ^ b) / 2;
    }
    
    function weightedAverage(
        uint256 value1,
        uint256 weight1,
        uint256 value2,
        uint256 weight2
    ) internal pure returns (uint256) {
        uint256 totalWeight = weight1 + weight2;
        require(totalWeight > 0, "Zero weights");
        
        // Use mulDiv for each component
        uint256 weighted1 = Math.mulDiv(value1, weight1, totalWeight);
        uint256 weighted2 = Math.mulDiv(value2, weight2, totalWeight);
        
        return weighted1 + weighted2;
    }
}
```

---

### MATH-AP-37: Time-Weighted Calculation Order

**Severity:** Medium | **Likelihood:** Medium

**Description:**
Time-weighted calculations are sensitive to operation order.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: TWAP calculation order
contract VulnerableTWAP {
    function updateTWAP(
        uint256 currentPrice,
        uint256 lastPrice,
        uint256 timeElapsed,
        uint256 cumulativePrice
    ) internal pure returns (uint256) {
        // (price * time) can overflow for large time periods
        cumulativePrice += currentPrice * timeElapsed;
        return cumulativePrice;
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Bounded TWAP with overflow protection
contract SecureTWAP {
    uint256 public constant MAX_TIME_ELAPSED = 1 hours;
    
    struct Observation {
        uint256 timestamp;
        uint256 priceCumulative;
    }
    
    function updateTWAP(
        uint256 currentPrice,
        uint256 timeElapsed,
        Observation memory lastObs
    ) internal view returns (Observation memory) {
        // Bound time elapsed
        timeElapsed = Math.min(timeElapsed, MAX_TIME_ELAPSED);
        
        // Safe multiplication
        uint256 priceDelta = Math.mulDiv(currentPrice, timeElapsed, 1);
        
        return Observation({
            timestamp: block.timestamp,
            priceCumulative: lastObs.priceCumulative + priceDelta
        });
    }
    
    function getTWAP(
        Observation memory obs1,
        Observation memory obs2
    ) internal pure returns (uint256) {
        require(obs2.timestamp > obs1.timestamp, "Invalid observations");
        
        uint256 timeElapsed = obs2.timestamp - obs1.timestamp;
        uint256 priceDelta = obs2.priceCumulative - obs1.priceCumulative;
        
        return priceDelta / timeElapsed;
    }
}
```

---

### MATH-AP-38: Ratio Calculation Precision

**Severity:** Medium | **Likelihood:** Medium

**Description:**
Ratio calculations lose precision when numerator is smaller than denominator.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Small ratio = 0
contract VulnerableRatio {
    function getRatio(uint256 part, uint256 whole) internal pure returns (uint256) {
        // If part < whole, result = 0
        return part / whole;
    }
    
    function getPercentage(uint256 part, uint256 whole) internal pure returns (uint256) {
        // Still loses precision for sub-percent values
        return part * 100 / whole;
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Scale ratio appropriately
contract SecureRatio {
    uint256 public constant PRECISION = 1e18;
    
    function getRatio(uint256 part, uint256 whole) internal pure returns (uint256) {
        require(whole > 0, "Division by zero");
        // Returns ratio scaled by PRECISION
        return part * PRECISION / whole;
    }
    
    function getPercentage(uint256 part, uint256 whole) internal pure returns (uint256) {
        // Returns percentage with 18 decimal precision
        // 0.01% = 1e14, 100% = 1e18
        return getRatio(part, whole);
    }
    
    // Usage: actual ratio = result / PRECISION
}
```

---

### MATH-AP-39: Accumulator Update Order

**Severity:** High | **Likelihood:** Medium

**Description:**
Order of accumulator updates affects final values.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Order-dependent accumulator
contract VulnerableAccumulator {
    uint256 public rewardPerTokenStored;
    mapping(address => uint256) public userRewardPerTokenPaid;
    mapping(address => uint256) public rewards;
    
    function updateReward(address user) internal {
        // Wrong order: user earnings calculated with OLD rewardPerToken
        rewards[user] += earned(user);
        userRewardPerTokenPaid[user] = rewardPerTokenStored;
        
        // Then global updated
        rewardPerTokenStored = calculateNewRewardPerToken();
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Correct update order
contract SecureAccumulator {
    function updateReward(address user) internal {
        // First: Update global state
        rewardPerTokenStored = calculateNewRewardPerToken();
        lastUpdateTime = block.timestamp;
        
        // Then: Update user based on NEW global state
        if (user != address(0)) {
            rewards[user] += earned(user);
            userRewardPerTokenPaid[user] = rewardPerTokenStored;
        }
    }
    
    function earned(address user) public view returns (uint256) {
        return balanceOf(user) * 
            (rewardPerTokenStored - userRewardPerTokenPaid[user]) / PRECISION;
    }
}
```

---

## Category 6: Edge Cases Anti-Patterns

### MATH-AP-40: Division by Zero

**Severity:** Critical | **Likelihood:** Medium

**Description:**
Division by zero causes transaction revert or undefined behavior.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No zero check
contract VulnerableDivZero {
    function getPrice(uint256 reserve0, uint256 reserve1) internal pure returns (uint256) {
        // Reverts if reserve1 = 0
        return reserve0 * 1e18 / reserve1;
    }
    
    function getShareValue(uint256 shares) internal view returns (uint256) {
        // Reverts if totalSupply = 0
        return shares * totalAssets / totalSupply;
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Handle zero cases
contract SecureDivZero {
    function getPrice(uint256 reserve0, uint256 reserve1) internal pure returns (uint256) {
        if (reserve1 == 0) return 0;  // Or revert with message
        return reserve0 * 1e18 / reserve1;
    }
    
    function getShareValue(uint256 shares) internal view returns (uint256) {
        if (totalSupply == 0) {
            // First deposit case
            return shares;  // 1:1 ratio
        }
        return shares * totalAssets / totalSupply;
    }
}
```

---

### MATH-AP-41: Maximum Value Edge Cases

**Severity:** High | **Likelihood:** Low

**Description:**
type(uint256).max and similar max values cause unexpected behavior.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Max value issues
contract VulnerableMaxValue {
    function approve(address spender, uint256 amount) external {
        if (amount == type(uint256).max) {
            // Infinite approval - but what if balance checked?
            allowances[msg.sender][spender] = type(uint256).max;
        }
    }
    
    function transfer(address to, uint256 amount) external {
        // If allowance is max, this underflows/wraps
        allowances[msg.sender][to] -= amount;
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Handle max values explicitly
contract SecureMaxValue {
    function transferFrom(address from, address to, uint256 amount) external {
        uint256 currentAllowance = allowances[from][msg.sender];
        
        // Don't decrease infinite allowance
        if (currentAllowance != type(uint256).max) {
            require(currentAllowance >= amount, "Insufficient allowance");
            unchecked {
                allowances[from][msg.sender] = currentAllowance - amount;
            }
        }
        
        _transfer(from, to, amount);
    }
}
```

---

### MATH-AP-42: Zero Amount Operations

**Severity:** Medium | **Likelihood:** High

**Description:**
Zero amount operations may have unintended effects or waste gas.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Zero amounts allowed
contract VulnerableZeroAmount {
    function deposit(uint256 amount) external {
        // Zero deposit does nothing but wastes gas
        // And might emit misleading events
        balances[msg.sender] += amount;
        emit Deposit(msg.sender, amount);  // Emits Deposit(user, 0)
    }
    
    function transfer(uint256 amount) external {
        // Zero transfer might bypass checks or trigger callbacks
        token.transfer(recipient, amount);
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Validate non-zero
contract SecureZeroAmount {
    function deposit(uint256 amount) external {
        require(amount > 0, "Zero amount");
        balances[msg.sender] += amount;
        emit Deposit(msg.sender, amount);
    }
    
    function transfer(uint256 amount) external {
        require(amount > 0, "Zero amount");
        // Or: return early for zero
        if (amount == 0) return;
        token.transfer(recipient, amount);
    }
}
```

---

### MATH-AP-43: Negative Zero in Signed Math

**Severity:** Low | **Likelihood:** Low

**Description:**
Signed integers have edge cases around zero and negation.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Signed math edge cases
contract VulnerableSignedZero {
    function abs(int256 x) internal pure returns (uint256) {
        // -0 doesn't exist, but type(int256).min is special
        return x >= 0 ? uint256(x) : uint256(-x);
        // If x = type(int256).min, -x overflows!
    }
    
    function isPositive(int256 x) internal pure returns (bool) {
        return x > 0;  // 0 is not positive
    }
    
    function isNegative(int256 x) internal pure returns (bool) {
        return x < 0;  // 0 is not negative
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Handle signed edge cases
contract SecureSignedZero {
    function abs(int256 x) internal pure returns (uint256) {
        if (x == type(int256).min) {
            // |min| = |max| + 1
            return uint256(type(int256).max) + 1;
        }
        return x >= 0 ? uint256(x) : uint256(-x);
    }
    
    function isNonNegative(int256 x) internal pure returns (bool) {
        return x >= 0;
    }
    
    function isNonPositive(int256 x) internal pure returns (bool) {
        return x <= 0;
    }
}
```

---

### MATH-AP-44: Modulo Edge Cases

**Severity:** Medium | **Likelihood:** Low

**Description:**
Modulo operations have edge cases with zero and negative numbers.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Modulo issues
contract VulnerableModulo {
    function distribute(uint256 total, uint256 recipients) internal pure returns (uint256 each, uint256 remainder) {
        each = total / recipients;  // Reverts if recipients = 0
        remainder = total % recipients;  // Also reverts
    }
    
    function cyclicIndex(int256 index, uint256 length) internal pure returns (uint256) {
        // Solidity % with negative can return negative
        return uint256(index % int256(length));  // Dangerous cast
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Safe modulo
contract SecureModulo {
    function distribute(uint256 total, uint256 recipients) internal pure returns (uint256 each, uint256 remainder) {
        require(recipients > 0, "Zero recipients");
        each = total / recipients;
        remainder = total % recipients;
    }
    
    function cyclicIndex(int256 index, uint256 length) internal pure returns (uint256) {
        require(length > 0, "Zero length");
        
        int256 len = int256(length);
        int256 result = index % len;
        
        // Handle negative result
        if (result < 0) {
            result += len;
        }
        
        return uint256(result);
    }
}
```

---

### MATH-AP-45: Square Root Edge Cases

**Severity:** Low | **Likelihood:** Low

**Description:**
Square root calculations have precision and edge case issues.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Imprecise sqrt
contract VulnerableSqrt {
    function sqrt(uint256 x) internal pure returns (uint256) {
        if (x == 0) return 0;
        
        uint256 z = (x + 1) / 2;
        uint256 y = x;
        
        while (z < y) {
            y = z;
            z = (x / z + z) / 2;
        }
        
        return y;
        // May be off by 1 for some inputs
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Verified sqrt from OpenZeppelin
contract SecureSqrt {
    function sqrt(uint256 a) internal pure returns (uint256) {
        if (a == 0) return 0;
        
        // Compute sqrt using Newton's method
        uint256 result = 1 << (log2(a) >> 1);
        
        unchecked {
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            return min(result, a / result);
        }
    }
    
    function log2(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >> 128 > 0) { value >>= 128; result += 128; }
            if (value >> 64 > 0) { value >>= 64; result += 64; }
            if (value >> 32 > 0) { value >>= 32; result += 32; }
            if (value >> 16 > 0) { value >>= 16; result += 16; }
            if (value >> 8 > 0) { value >>= 8; result += 8; }
            if (value >> 4 > 0) { value >>= 4; result += 4; }
            if (value >> 2 > 0) { value >>= 2; result += 2; }
            if (value >> 1 > 0) { result += 1; }
        }
        return result;
    }
}
```

---

## Audit Checklist Summary

### Overflow/Underflow
- [ ] All unchecked blocks reviewed for overflow potential
- [ ] Subtraction has underflow checks
- [ ] Multiplication overflow handled (use mulDiv)
- [ ] Type casting checked (use SafeCast)
- [ ] Signed integer edge cases handled

### Rounding
- [ ] Rounding direction correct per operation type
- [ ] Rounding accumulation tracked
- [ ] Zero results handled
- [ ] Fee rounding has minimum
- [ ] Share/asset rounding symmetric

### Precision
- [ ] Multiply before divide
- [ ] Decimal mismatches handled
- [ ] Oracle precision accounted for
- [ ] Interest rate precision sufficient
- [ ] Reward rate precision adequate

### Fixed-Point
- [ ] WAD/RAY scales not mixed
- [ ] Fixed-point overflow handled
- [ ] Rounding direction explicit
- [ ] Scale conversions preserve precision
- [ ] Compound interest uses exponentiation

### Calculation Order
- [ ] Operation order explicit (parentheses)
- [ ] Intermediate overflow handled
- [ ] Sequential divisions minimized
- [ ] Accumulators updated correctly

### Edge Cases
- [ ] Division by zero handled
- [ ] Maximum values handled
- [ ] Zero amounts validated
- [ ] Signed math edge cases covered
- [ ] Square root verified

---

## References

- [OpenZeppelin Math](https://docs.openzeppelin.com/contracts/4.x/api/utils#Math)
- [Uniswap V3 FullMath](https://github.com/Uniswap/v3-core/blob/main/contracts/libraries/FullMath.sol)
- [Aave WadRayMath](https://github.com/aave/aave-v3-core/blob/master/contracts/protocol/libraries/math/WadRayMath.sol)
- [Trail of Bits: Integer Overflow](https://blog.trailofbits.com/)

---

## Related Documents

- [vault-specific-anti-patterns.md](vault-specific-anti-patterns.md)
- [oracle-anti-patterns.md](oracle-anti-patterns.md)
- [arithmetic-patterns.md](../patterns/arithmetic-patterns.md)
