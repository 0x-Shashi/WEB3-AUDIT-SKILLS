# Vault-Specific Anti-Patterns

> Security anti-patterns for ERC4626 vaults, yield aggregators, and tokenized vault strategies.
> 42 anti-patterns covering share manipulation, accounting errors, strategy risks, and integration failures.

---

## Category Overview

| Category | ID Range | Count | Focus Area |
|----------|----------|-------|------------|
| Share Calculation | VAULT-AP-01 to 08 | 8 | First depositor, inflation, rounding |
| Deposit/Withdraw | VAULT-AP-09 to 16 | 8 | Frontrunning, reentrancy, limits |
| Yield/Strategy | VAULT-AP-17 to 24 | 8 | Harvest, compound, strategy risks |
| Accounting | VAULT-AP-25 to 31 | 7 | Token handling, fee calculation |
| Access Control | VAULT-AP-32 to 37 | 6 | Strategy changes, emergency |
| Integration | VAULT-AP-38 to 42 | 5 | Composability, oracle dependencies |

---

## Category 1: Share Calculation Anti-Patterns

### VAULT-AP-01: First Depositor Inflation Attack

**Severity:** Critical | **Likelihood:** High

**Description:**
First depositor can manipulate share price through direct asset transfer, causing subsequent depositors to receive zero shares.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Standard share calculation without protection
contract VulnerableVault is ERC4626 {
    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply();
        // First deposit gets shares = assets
        // Attack: deposit 1 wei, donate 1e18 assets, next depositor gets 0 shares
        return supply == 0 ? assets : assets * supply / totalAssets();
    }
}

// Attack sequence:
// 1. Attacker deposits 1 wei → receives 1 share
// 2. Attacker donates 1e18 tokens directly to vault
// 3. totalAssets = 1e18 + 1, totalSupply = 1
// 4. Victim deposits 1e18 → shares = 1e18 * 1 / (1e18+1) = 0
// 5. Victim's tokens stolen
```

**Real Exploits:**
- **Multiple ERC4626 Vaults (2022-2023):** Inflation attacks on newly deployed vaults
- **Yearn-style Vaults:** Similar first depositor issues

**Secure Pattern:**
```solidity
// SECURE: Virtual offset / dead shares
contract SecureVault is ERC4626 {
    uint256 internal constant VIRTUAL_SHARES = 1e3;
    uint256 internal constant VIRTUAL_ASSETS = 1;
    
    function totalAssets() public view override returns (uint256) {
        return _asset.balanceOf(address(this)) + VIRTUAL_ASSETS;
    }
    
    function totalSupply() public view override returns (uint256) {
        return super.totalSupply() + VIRTUAL_SHARES;
    }
    
    // Alternative: Burn initial shares
    constructor() {
        // Mint dead shares on deployment
        _mint(address(0xdead), 1000);
    }
}
```

**Detection Methods:**
- [ ] Check initial deposit protection
- [ ] Verify virtual shares/assets implementation
- [ ] Test with 1 wei deposits
- [ ] Simulate donation attacks

---

### VAULT-AP-02: Share Price Manipulation via Donation

**Severity:** High | **Likelihood:** Medium

**Description:**
Attacker donates assets to vault to manipulate share price, affecting other users' conversions.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: totalAssets based on balance
contract VulnerableVault {
    function totalAssets() public view returns (uint256) {
        // Directly reads balance - manipulatable
        return asset.balanceOf(address(this));
    }
    
    function withdraw(uint256 shares) external {
        uint256 assets = shares * totalAssets() / totalSupply();
        // If attacker donated, assets calculation inflated
        // But actual withdrawable may be less
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Track assets internally
contract SecureVault {
    uint256 internal _totalManagedAssets;
    
    function totalAssets() public view returns (uint256) {
        // Use tracked value, not balance
        return _totalManagedAssets;
    }
    
    function deposit(uint256 assets) external {
        _totalManagedAssets += assets;
        // ... mint shares
    }
    
    function withdraw(uint256 shares) external {
        uint256 assets = previewRedeem(shares);
        _totalManagedAssets -= assets;
        // ...
    }
    
    // Sweep donations separately (to treasury or distribute)
    function sweepDonations() external onlyAdmin {
        uint256 donations = asset.balanceOf(address(this)) - _totalManagedAssets;
        if (donations > 0) {
            asset.transfer(treasury, donations);
        }
    }
}
```

---

### VAULT-AP-03: Rounding Direction Exploitation

**Severity:** Medium | **Likelihood:** High

**Description:**
Incorrect rounding direction allows users to extract small amounts over many transactions.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Always rounds same direction
contract VulnerableVault {
    function convertToShares(uint256 assets) public view returns (uint256) {
        // Always rounds down - correct for deposits
        return assets * totalSupply() / totalAssets();
    }
    
    function convertToAssets(uint256 shares) public view returns (uint256) {
        // Also rounds down - WRONG for withdrawals
        // Should round down for withdrawals (against user)
        return shares * totalAssets() / totalSupply();
    }
    
    function previewMint(uint256 shares) public view returns (uint256) {
        // Rounds down - WRONG, should round up
        // User pays fewer assets than they should
        return shares * totalAssets() / totalSupply();
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Proper rounding per ERC4626 spec
contract SecureVault {
    function convertToShares(uint256 assets) public view returns (uint256) {
        // Round DOWN for deposits (user receives fewer shares)
        return _mulDivDown(assets, totalSupply() + 1, totalAssets() + 1);
    }
    
    function previewDeposit(uint256 assets) public view returns (uint256) {
        return convertToShares(assets); // Round DOWN
    }
    
    function previewMint(uint256 shares) public view returns (uint256) {
        // Round UP for mints (user pays more assets)
        return _mulDivUp(shares, totalAssets() + 1, totalSupply() + 1);
    }
    
    function previewWithdraw(uint256 assets) public view returns (uint256) {
        // Round UP for withdrawals (user burns more shares)
        return _mulDivUp(assets, totalSupply() + 1, totalAssets() + 1);
    }
    
    function previewRedeem(uint256 shares) public view returns (uint256) {
        // Round DOWN for redeems (user receives fewer assets)
        return _mulDivDown(shares, totalAssets() + 1, totalSupply() + 1);
    }
}
```

---

### VAULT-AP-04: Zero Share Minting

**Severity:** High | **Likelihood:** Medium

**Description:**
Small deposits can result in zero shares due to rounding, with assets trapped in vault.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No minimum share check
contract VulnerableVault {
    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = previewDeposit(assets);
        // No check if shares == 0!
        
        asset.transferFrom(msg.sender, address(this), assets);
        _mint(receiver, shares);  // Mints 0 shares
        
        // User's assets now trapped - they have 0 shares
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Minimum share validation
contract SecureVault {
    uint256 public constant MIN_SHARES = 1000;
    
    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = previewDeposit(assets);
        
        require(shares >= MIN_SHARES, "Deposit too small");
        
        asset.transferFrom(msg.sender, address(this), assets);
        _mint(receiver, shares);
    }
    
    // Alternative: revert on zero
    function depositWithRevert(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = previewDeposit(assets);
        require(shares > 0, "Zero shares");
        // ...
    }
}
```

---

### VAULT-AP-05: Share Dilution During Rebase

**Severity:** High | **Likelihood:** Medium

**Description:**
Rebasing tokens cause share value changes without corresponding share supply changes.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Vault holds rebasing token
contract VulnerableRebaseVault {
    IERC20 public stETH; // Rebasing token
    
    function totalAssets() public view returns (uint256) {
        return stETH.balanceOf(address(this));
    }
    
    // Problem: stETH balance changes on rebase
    // Depositor A: deposits 100 stETH, gets 100 shares
    // Rebase: balance becomes 110 stETH
    // Depositor B: deposits 100 stETH, gets ~91 shares (100 * 100 / 110)
    // Depositor A benefited from rebase without risk
}
```

**Secure Pattern:**
```solidity
// SECURE: Use wrapped non-rebasing version
contract SecureRebaseVault {
    IWstETH public wstETH; // Wrapped, non-rebasing
    
    function deposit(uint256 stETHAmount) external {
        // Convert rebasing to non-rebasing on deposit
        stETH.transferFrom(msg.sender, address(this), stETHAmount);
        uint256 wstETHAmount = wstETH.wrap(stETHAmount);
        
        uint256 shares = calculateShares(wstETHAmount);
        _mint(msg.sender, shares);
    }
    
    function withdraw(uint256 shares) external {
        uint256 wstETHAmount = calculateAssets(shares);
        _burn(msg.sender, shares);
        
        // Convert back to rebasing on withdrawal
        uint256 stETHAmount = wstETH.unwrap(wstETHAmount);
        stETH.transfer(msg.sender, stETHAmount);
    }
}
```

---

### VAULT-AP-06: Exchange Rate Frontrunning

**Severity:** High | **Likelihood:** High

**Description:**
Attackers front-run rate-changing events (harvests, yields) to profit from predictable share price changes.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Public harvest updates share price instantly
contract VulnerableYieldVault {
    function harvest() public {
        uint256 yield = strategy.claimRewards();
        
        // Instantly increases totalAssets
        // Share price jumps immediately
        totalManagedAssets += yield;
        
        emit Harvested(yield);
    }
    
    // Attack:
    // 1. Attacker sees harvest tx in mempool
    // 2. Front-runs with large deposit (before yield)
    // 3. Harvest executes, share price increases
    // 4. Back-runs with withdrawal (after yield)
    // 5. Profit = share of harvested yield without risk
}
```

**Secure Pattern:**
```solidity
// SECURE: Time-weighted yield distribution
contract SecureYieldVault {
    uint256 public lastHarvestTime;
    uint256 public pendingYield;
    uint256 public yieldRate;
    uint256 public constant YIELD_DISTRIBUTION_PERIOD = 24 hours;
    
    function harvest() external {
        uint256 yield = strategy.claimRewards();
        
        // Distribute remaining pending yield first
        _distributeYield();
        
        // Queue new yield for gradual distribution
        pendingYield = yield;
        yieldRate = yield / YIELD_DISTRIBUTION_PERIOD;
        lastHarvestTime = block.timestamp;
    }
    
    function totalAssets() public view returns (uint256) {
        uint256 base = _baseAssets;
        uint256 distributed = _calculateDistributedYield();
        return base + distributed;
    }
    
    function _calculateDistributedYield() internal view returns (uint256) {
        uint256 elapsed = block.timestamp - lastHarvestTime;
        if (elapsed >= YIELD_DISTRIBUTION_PERIOD) {
            return pendingYield;
        }
        return elapsed * yieldRate;
    }
}
```

---

### VAULT-AP-07: Sandwich Attack on Share Price

**Severity:** Medium | **Likelihood:** High

**Description:**
Attackers sandwich deposits/withdrawals to profit from share price impact.

**Vulnerable Pattern:**
```solidity
// Sandwich attack on vault:
// 1. Attacker sees large deposit in mempool
// 2. Front-run: Deposit (before victim)
// 3. Victim's large deposit increases share price
// 4. Back-run: Withdraw (after victim)
// 5. Attacker profits from price movement

// VULNERABLE: No slippage protection
contract VulnerableVault {
    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = previewDeposit(assets);
        // No minimum shares parameter
        // Victim might get fewer shares than expected
        
        asset.transferFrom(msg.sender, address(this), assets);
        _mint(receiver, shares);
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Slippage protection
contract SecureVault {
    function deposit(
        uint256 assets,
        address receiver,
        uint256 minShares  // Slippage protection
    ) external returns (uint256 shares) {
        shares = previewDeposit(assets);
        require(shares >= minShares, "Slippage exceeded");
        
        asset.transferFrom(msg.sender, address(this), assets);
        _mint(receiver, shares);
    }
    
    function withdraw(
        uint256 assets,
        address receiver,
        address owner,
        uint256 maxShares  // Slippage protection
    ) external returns (uint256 shares) {
        shares = previewWithdraw(assets);
        require(shares <= maxShares, "Slippage exceeded");
        
        _withdraw(msg.sender, receiver, owner, assets, shares);
    }
}
```

---

### VAULT-AP-08: Price Per Share Overflow

**Severity:** Medium | **Likelihood:** Low

**Description:**
Extreme price per share values cause overflow in calculations.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No overflow protection for extreme values
contract VulnerableVault {
    function convertToShares(uint256 assets) public view returns (uint256) {
        // If totalAssets very high and totalSupply very low
        // assets * totalSupply might overflow
        return assets * totalSupply() / totalAssets();
    }
    
    // Scenario:
    // totalSupply = 1
    // totalAssets = 1e77 (due to manipulation or token quirk)
    // assets = 1e18
    // Result: 1e18 * 1 / 1e77 = 0 (or overflow depending on order)
}
```

**Secure Pattern:**
```solidity
// SECURE: Use mulDiv with overflow protection
contract SecureVault {
    function convertToShares(uint256 assets) public view returns (uint256) {
        return Math.mulDiv(
            assets,
            totalSupply() + VIRTUAL_SHARES,
            totalAssets() + VIRTUAL_ASSETS,
            Math.Rounding.Down
        );
    }
    
    // OpenZeppelin's Math.mulDiv handles:
    // - Overflow in intermediate calculation
    // - Division by zero protection
    // - Proper rounding
}
```

---

## Category 2: Deposit/Withdraw Anti-Patterns

### VAULT-AP-09: Reentrancy in Deposit/Withdraw

**Severity:** Critical | **Likelihood:** Medium

**Description:**
State changes after external calls allow reentrancy exploitation.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: State update after transfer
contract VulnerableVault {
    function withdraw(uint256 shares, address receiver, address owner) external {
        uint256 assets = previewRedeem(shares);
        
        // Transfer first (WRONG!)
        asset.transfer(receiver, assets);
        
        // State update after (vulnerable to reentrancy)
        _burn(owner, shares);
        totalManagedAssets -= assets;
    }
}

// Attack with ERC777 or callback token:
// 1. Withdraw triggers transfer
// 2. Transfer callback reenters withdraw
// 3. Shares not yet burned, can withdraw again
// 4. Drain vault
```

**Secure Pattern:**
```solidity
// SECURE: CEI + reentrancy guard
contract SecureVault is ReentrancyGuard {
    function withdraw(
        uint256 shares,
        address receiver,
        address owner
    ) external nonReentrant {
        uint256 assets = previewRedeem(shares);
        
        // Checks
        require(shares <= balanceOf(owner), "Insufficient shares");
        
        // Effects (state changes first)
        _burn(owner, shares);
        totalManagedAssets -= assets;
        
        // Interactions (external calls last)
        asset.safeTransfer(receiver, assets);
    }
}
```

---

### VAULT-AP-10: Deposit Frontrunning for MEV

**Severity:** Medium | **Likelihood:** High

**Description:**
Deposits can be front-run to capture yield or manipulate share allocation.

**Vulnerable Pattern:**
```solidity
// MEV opportunity in deposits:
// 1. Large pending deposit in mempool
// 2. MEV bot front-runs with own deposit
// 3. Large deposit executes (might have positive impact)
// 4. MEV bot back-runs with withdrawal
// Or captures upcoming yield

contract VulnerableVault {
    // No private mempool or commitment scheme
    function deposit(uint256 assets) external {
        // Public, front-runnable
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Commit-reveal deposits for large amounts
contract SecureVault {
    uint256 public constant COMMIT_THRESHOLD = 100_000e18;
    uint256 public constant COMMIT_DELAY = 2; // blocks
    
    mapping(bytes32 => DepositCommit) public commits;
    
    struct DepositCommit {
        address depositor;
        uint256 blockNumber;
        bool revealed;
    }
    
    function commitDeposit(bytes32 commitHash) external {
        commits[commitHash] = DepositCommit({
            depositor: msg.sender,
            blockNumber: block.number,
            revealed: false
        });
    }
    
    function revealDeposit(
        uint256 assets,
        bytes32 salt
    ) external {
        bytes32 commitHash = keccak256(abi.encode(msg.sender, assets, salt));
        DepositCommit storage commit = commits[commitHash];
        
        require(commit.depositor == msg.sender, "Invalid commit");
        require(!commit.revealed, "Already revealed");
        require(
            block.number >= commit.blockNumber + COMMIT_DELAY,
            "Too early"
        );
        
        commit.revealed = true;
        _deposit(assets, msg.sender);
    }
    
    // Small deposits can skip commit-reveal
    function depositSmall(uint256 assets) external {
        require(assets < COMMIT_THRESHOLD, "Use commit-reveal");
        _deposit(assets, msg.sender);
    }
}
```

---

### VAULT-AP-11: Withdrawal Queue Manipulation

**Severity:** Medium | **Likelihood:** Medium

**Description:**
Withdrawal queues can be gamed to skip ahead or block other users.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: FIFO queue without rate limiting
contract VulnerableVault {
    struct WithdrawalRequest {
        address user;
        uint256 shares;
        uint256 requestTime;
    }
    WithdrawalRequest[] public queue;
    
    function requestWithdrawal(uint256 shares) external {
        queue.push(WithdrawalRequest({
            user: msg.sender,
            shares: shares,
            requestTime: block.timestamp
        }));
    }
    
    function processWithdrawals() external {
        // Process FIFO - attacker can flood queue
        while (queue.length > 0 && hasLiquidity(queue[0].shares)) {
            _processWithdrawal(queue[0]);
            _removeFirst();
        }
    }
    
    // Attack: Sybil requests to clog queue
    // Or: Large request blocks smaller ones
}
```

**Secure Pattern:**
```solidity
// SECURE: Pro-rata processing + rate limiting
contract SecureVault {
    mapping(address => WithdrawalRequest) public requests;
    uint256 public totalPendingWithdrawals;
    uint256 public constant MAX_REQUESTS_PER_USER = 3;
    
    function requestWithdrawal(uint256 shares) external {
        require(
            userRequestCount[msg.sender] < MAX_REQUESTS_PER_USER,
            "Too many requests"
        );
        
        requests[msg.sender] = WithdrawalRequest({
            shares: shares,
            requestTime: block.timestamp
        });
        totalPendingWithdrawals += shares;
        userRequestCount[msg.sender]++;
    }
    
    function processWithdrawals() external {
        uint256 availableLiquidity = getAvailableLiquidity();
        
        // Pro-rata distribution if insufficient liquidity
        uint256 ratio = availableLiquidity >= totalPendingWithdrawals
            ? 1e18
            : availableLiquidity * 1e18 / totalPendingWithdrawals;
        
        // Process all eligible requests pro-rata
        for (address user : requestUsers) {
            uint256 processShares = requests[user].shares * ratio / 1e18;
            if (processShares > 0) {
                _processPartialWithdrawal(user, processShares);
            }
        }
    }
}
```

---

### VAULT-AP-12: Max Deposit/Withdraw Bypass

**Severity:** Medium | **Likelihood:** Medium

**Description:**
Deposit/withdrawal limits can be bypassed through multiple transactions or transfers.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Per-tx limits without accounting
contract VulnerableVault {
    uint256 public constant MAX_DEPOSIT = 1_000_000e18;
    
    function maxDeposit(address) public pure returns (uint256) {
        return MAX_DEPOSIT;
    }
    
    function deposit(uint256 assets, address receiver) external {
        require(assets <= maxDeposit(receiver), "Exceeds max");
        // No tracking of total deposited
        // User can deposit MAX_DEPOSIT multiple times
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Track cumulative limits
contract SecureVault {
    uint256 public constant MAX_TOTAL_DEPOSIT = 1_000_000e18;
    uint256 public constant MAX_USER_DEPOSIT = 100_000e18;
    uint256 public constant DAILY_LIMIT = 500_000e18;
    
    mapping(address => uint256) public userTotalDeposited;
    mapping(uint256 => uint256) public dailyDeposits; // day => amount
    
    function maxDeposit(address user) public view returns (uint256) {
        uint256 globalRemaining = MAX_TOTAL_DEPOSIT - totalAssets();
        uint256 userRemaining = MAX_USER_DEPOSIT - userTotalDeposited[user];
        uint256 dailyRemaining = DAILY_LIMIT - dailyDeposits[today()];
        
        return min(globalRemaining, min(userRemaining, dailyRemaining));
    }
    
    function deposit(uint256 assets, address receiver) external {
        require(assets <= maxDeposit(receiver), "Exceeds limits");
        
        userTotalDeposited[receiver] += assets;
        dailyDeposits[today()] += assets;
        
        _deposit(assets, receiver);
    }
}
```

---

### VAULT-AP-13: Instant Withdrawal DoS

**Severity:** Medium | **Likelihood:** Medium

**Description:**
Large instant withdrawals can DoS other users by depleting available liquidity.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No withdrawal throttling
contract VulnerableVault {
    function withdraw(uint256 assets, address receiver, address owner) external {
        require(assets <= totalAssets(), "Insufficient assets");
        
        // Whale can withdraw all liquidity instantly
        // Other users' withdrawals fail
        
        _processWithdrawal(assets, receiver, owner);
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Withdrawal throttling + reserves
contract SecureVault {
    uint256 public constant MIN_RESERVE_RATIO = 1000; // 10%
    uint256 public constant MAX_SINGLE_WITHDRAWAL_RATIO = 2000; // 20%
    
    function maxWithdraw(address owner) public view returns (uint256) {
        uint256 userMax = previewRedeem(balanceOf(owner));
        
        // Reserve ratio limit
        uint256 reserveLimit = totalAssets() * (10000 - MIN_RESERVE_RATIO) / 10000;
        
        // Single withdrawal limit
        uint256 singleLimit = totalAssets() * MAX_SINGLE_WITHDRAWAL_RATIO / 10000;
        
        return min(userMax, min(reserveLimit, singleLimit));
    }
    
    function withdraw(uint256 assets, address receiver, address owner) external {
        require(assets <= maxWithdraw(owner), "Exceeds withdrawal limit");
        _processWithdrawal(assets, receiver, owner);
    }
}
```

---

### VAULT-AP-14: Withdrawal Lock Bypass

**Severity:** High | **Likelihood:** Medium

**Description:**
Withdrawal locks can be bypassed through share transfers or secondary markets.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Lock on shares but shares are transferable
contract VulnerableVault is ERC20 {
    mapping(address => uint256) public lockUntil;
    
    function deposit(uint256 assets) external {
        lockUntil[msg.sender] = block.timestamp + 7 days;
        _deposit(assets);
    }
    
    function withdraw(uint256 shares) external {
        require(block.timestamp >= lockUntil[msg.sender], "Locked");
        _withdraw(shares);
    }
    
    // BUT: Shares can be transferred to another address
    // That address has no lock! Bypass complete.
}
```

**Secure Pattern:**
```solidity
// SECURE: Lock on shares themselves
contract SecureVault is ERC20 {
    mapping(address => uint256) public lockUntil;
    
    function deposit(uint256 assets) external {
        lockUntil[msg.sender] = block.timestamp + 7 days;
        _deposit(assets);
    }
    
    // Override transfer to enforce locks
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 amount
    ) internal override {
        if (from != address(0)) { // Not minting
            require(
                block.timestamp >= lockUntil[from],
                "Shares locked"
            );
        }
    }
    
    function withdraw(uint256 shares) external {
        require(block.timestamp >= lockUntil[msg.sender], "Locked");
        _withdraw(shares);
    }
}
```

---

### VAULT-AP-15: Flash Deposit Attack

**Severity:** High | **Likelihood:** Medium

**Description:**
Flash loans used to temporarily inflate deposit for governance or yield capture.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Instant deposit affects governance/rewards
contract VulnerableVault {
    function deposit(uint256 assets) external {
        _mint(msg.sender, calculateShares(assets));
        
        // Governance weight immediately updated
        governanceWeight[msg.sender] = balanceOf(msg.sender);
        
        // Reward rate immediately includes new deposit
        updateRewardRate(msg.sender);
    }
}

// Attack:
// 1. Flash loan 10M tokens
// 2. Deposit into vault
// 3. Vote on governance (10M voting power)
// 4. Or claim inflated rewards
// 5. Withdraw
// 6. Repay flash loan
```

**Secure Pattern:**
```solidity
// SECURE: Time-weighted governance and rewards
contract SecureVault {
    mapping(address => uint256) public depositTimestamp;
    uint256 public constant MIN_DEPOSIT_DURATION = 1 days;
    
    function deposit(uint256 assets) external {
        _mint(msg.sender, calculateShares(assets));
        depositTimestamp[msg.sender] = block.timestamp;
        
        // Governance weight based on time-weighted balance
        // Uses checkpoints, not instant balance
    }
    
    function getVotingPower(address user) external view returns (uint256) {
        // Only count shares held for minimum duration
        if (block.timestamp < depositTimestamp[user] + MIN_DEPOSIT_DURATION) {
            return 0;
        }
        return balanceOf(user);
    }
    
    function claimRewards() external {
        // Time-weighted rewards calculation
        uint256 duration = block.timestamp - lastClaim[msg.sender];
        uint256 avgBalance = getTimeWeightedBalance(msg.sender, duration);
        uint256 rewards = avgBalance * rewardRate * duration / 1e18;
        // ...
    }
}
```

---

### VAULT-AP-16: Emergency Withdrawal Griefing

**Severity:** Medium | **Likelihood:** Low

**Description:**
Emergency withdrawal mechanisms can be abused to grief or front-run other users.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Emergency mode affects all users
contract VulnerableVault {
    bool public emergencyMode;
    
    function enableEmergencyMode() external onlyAdmin {
        emergencyMode = true;
        // All deposits paused, only withdrawals allowed
    }
    
    function emergencyWithdraw() external {
        require(emergencyMode, "Not emergency");
        // Returns assets at potentially unfavorable rate
        uint256 assets = balanceOf(msg.sender) * emergencyAssets / totalSupply();
        _burn(msg.sender, balanceOf(msg.sender));
        asset.transfer(msg.sender, assets);
    }
    
    // Issue: Admin can trigger emergency to force unfavorable exits
    // Or: First withdrawers get more than later ones
}
```

**Secure Pattern:**
```solidity
// SECURE: Fair emergency distribution
contract SecureVault {
    bool public emergencyMode;
    uint256 public emergencyTimestamp;
    uint256 public snapshotTotalShares;
    uint256 public snapshotTotalAssets;
    
    function enableEmergencyMode() external {
        require(
            msg.sender == admin || isEmergencyCondition(),
            "Not authorized"
        );
        
        emergencyMode = true;
        emergencyTimestamp = block.timestamp;
        
        // Snapshot for fair distribution
        snapshotTotalShares = totalSupply();
        snapshotTotalAssets = totalAssets();
    }
    
    function emergencyWithdraw() external {
        require(emergencyMode, "Not emergency");
        
        uint256 shares = balanceOf(msg.sender);
        // Use snapshot values for fair calculation
        uint256 assets = shares * snapshotTotalAssets / snapshotTotalShares;
        
        _burn(msg.sender, shares);
        asset.safeTransfer(msg.sender, assets);
    }
    
    function isEmergencyCondition() internal view returns (bool) {
        // Objective conditions for emergency
        return totalAssets() < totalSupply() * MIN_RATIO / 10000;
    }
}
```

---

## Category 3: Yield/Strategy Anti-Patterns

### VAULT-AP-17: Harvest Sandwich Attack

**Severity:** High | **Likelihood:** High

**Description:**
Public harvest functions can be sandwiched for MEV extraction.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Public harvest, instant reward distribution
contract VulnerableYieldVault {
    function harvest() public {
        // Claim rewards from strategy
        uint256 rewards = strategy.claimRewards();
        
        // Convert to underlying
        uint256 assets = swapRewardsToAsset(rewards);
        
        // Instantly add to total assets
        // Share price jumps immediately
        totalManagedAssets += assets;
        
        emit Harvested(assets);
    }
}

// Sandwich attack:
// 1. Bot monitors mempool for harvest tx
// 2. Front-run: Large deposit
// 3. Harvest executes: share price increases
// 4. Back-run: Withdraw with profit
```

**Secure Pattern:**
```solidity
// SECURE: Keeper-only + gradual distribution
contract SecureYieldVault {
    address public keeper;
    uint256 public harvestCooldown = 6 hours;
    uint256 public lastHarvest;
    
    uint256 public pendingHarvest;
    uint256 public harvestPerSecond;
    uint256 public harvestDistributionEnd;
    
    function harvest() external onlyKeeper {
        require(
            block.timestamp >= lastHarvest + harvestCooldown,
            "Cooldown not passed"
        );
        
        // Finalize previous harvest distribution
        _updateHarvestDistribution();
        
        // Claim new rewards
        uint256 rewards = strategy.claimRewards();
        uint256 assets = swapRewardsToAsset(rewards);
        
        // Queue for gradual distribution (24 hours)
        pendingHarvest = assets;
        harvestPerSecond = assets / 24 hours;
        harvestDistributionEnd = block.timestamp + 24 hours;
        lastHarvest = block.timestamp;
    }
    
    function totalAssets() public view returns (uint256) {
        return baseAssets + _getDistributedHarvest();
    }
    
    function _getDistributedHarvest() internal view returns (uint256) {
        if (block.timestamp >= harvestDistributionEnd) {
            return pendingHarvest;
        }
        uint256 elapsed = block.timestamp - lastHarvest;
        return elapsed * harvestPerSecond;
    }
}
```

---

### VAULT-AP-18: Strategy Loss Socialization

**Severity:** High | **Likelihood:** Medium

**Description:**
Strategy losses immediately affect all depositors, even new ones.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Instant loss recognition
contract VulnerableStrategyVault {
    function reportLoss(uint256 lossAmount) external onlyStrategy {
        // Loss immediately reduces totalAssets
        totalManagedAssets -= lossAmount;
        
        // All current share prices drop instantly
        // New depositor right before loss = same loss as old depositors
        // Attacker: Withdraw before loss report, deposit after
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Loss queue + time-weighted distribution
contract SecureStrategyVault {
    uint256 public pendingLoss;
    uint256 public lossDistributionEnd;
    uint256 public lossPerSecond;
    
    uint256 public constant LOSS_DISTRIBUTION_PERIOD = 7 days;
    
    function reportLoss(uint256 lossAmount) external onlyStrategy {
        // Distribute pending loss first
        _finalizeLossDistribution();
        
        // Queue new loss for gradual recognition
        pendingLoss = lossAmount;
        lossPerSecond = lossAmount / LOSS_DISTRIBUTION_PERIOD;
        lossDistributionEnd = block.timestamp + LOSS_DISTRIBUTION_PERIOD;
        
        emit LossReported(lossAmount, lossDistributionEnd);
    }
    
    function totalAssets() public view returns (uint256) {
        uint256 recognizedLoss = _getRecognizedLoss();
        return baseAssets - recognizedLoss;
    }
    
    function _getRecognizedLoss() internal view returns (uint256) {
        if (block.timestamp >= lossDistributionEnd) {
            return pendingLoss;
        }
        uint256 elapsed = block.timestamp - (lossDistributionEnd - LOSS_DISTRIBUTION_PERIOD);
        return elapsed * lossPerSecond;
    }
}
```

---

### VAULT-AP-19: Malicious Strategy Drain

**Severity:** Critical | **Likelihood:** Medium

**Description:**
Compromised or malicious strategy can drain vault funds.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Strategy has unlimited access
contract VulnerableVault {
    IStrategy public strategy;
    
    function setStrategy(address newStrategy) external onlyAdmin {
        strategy = IStrategy(newStrategy);
        // Full approval to new strategy
        asset.approve(newStrategy, type(uint256).max);
    }
    
    function depositToStrategy(uint256 amount) external {
        // Strategy can request any amount
        strategy.deposit(amount);
    }
}

// Attack: Admin compromised or malicious upgrade
// New strategy drains all approved assets
```

**Secure Pattern:**
```solidity
// SECURE: Strategy limits + timelock
contract SecureVault {
    IStrategy public pendingStrategy;
    uint256 public strategyChangeTime;
    uint256 public constant STRATEGY_TIMELOCK = 3 days;
    uint256 public constant MAX_STRATEGY_ALLOCATION = 9000; // 90%
    
    function proposeStrategy(address newStrategy) external onlyAdmin {
        require(
            IStrategy(newStrategy).asset() == address(asset),
            "Asset mismatch"
        );
        pendingStrategy = IStrategy(newStrategy);
        strategyChangeTime = block.timestamp + STRATEGY_TIMELOCK;
        
        emit StrategyProposed(newStrategy, strategyChangeTime);
    }
    
    function executeStrategyChange() external {
        require(
            block.timestamp >= strategyChangeTime,
            "Timelock not passed"
        );
        require(address(pendingStrategy) != address(0), "No pending strategy");
        
        // Withdraw from old strategy first
        if (address(strategy) != address(0)) {
            strategy.withdrawAll();
            asset.approve(address(strategy), 0);
        }
        
        strategy = pendingStrategy;
        pendingStrategy = IStrategy(address(0));
        
        // Limited approval
        uint256 maxAllocation = totalAssets() * MAX_STRATEGY_ALLOCATION / 10000;
        asset.approve(address(strategy), maxAllocation);
    }
    
    function emergencyWithdrawFromStrategy() external onlyGuardian {
        strategy.withdrawAll();
        asset.approve(address(strategy), 0);
        strategy = IStrategy(address(0));
    }
}
```

---

### VAULT-AP-20: Compound Frequency Gaming

**Severity:** Medium | **Likelihood:** Medium

**Description:**
Attackers manipulate compound timing to extract value.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Anyone can trigger compound, timing manipulable
contract VulnerableAutoCompound {
    function compound() public {
        uint256 rewards = claimRewards();
        uint256 assets = swapToAsset(rewards);
        depositToStrategy(assets);
        
        // MEV: Attacker times compound right after their deposit
        // Gets credit for compounded rewards they didn't earn
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Time-locked compound with incentive
contract SecureAutoCompound {
    uint256 public lastCompound;
    uint256 public constant MIN_COMPOUND_INTERVAL = 12 hours;
    uint256 public constant COMPOUND_INCENTIVE_BPS = 10; // 0.1%
    
    function compound() external {
        require(
            block.timestamp >= lastCompound + MIN_COMPOUND_INTERVAL,
            "Too soon"
        );
        
        uint256 rewards = claimRewards();
        require(rewards > 0, "No rewards");
        
        // Caller incentive
        uint256 callerReward = rewards * COMPOUND_INCENTIVE_BPS / 10000;
        rewardToken.transfer(msg.sender, callerReward);
        
        uint256 toCompound = rewards - callerReward;
        uint256 assets = swapToAsset(toCompound);
        depositToStrategy(assets);
        
        lastCompound = block.timestamp;
    }
}
```

---

### VAULT-AP-21: Strategy Insolvency Hiding

**Severity:** Critical | **Likelihood:** Low

**Description:**
Strategy reports false value to hide insolvency from vault.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Trust strategy-reported value
contract VulnerableVault {
    function totalAssets() public view returns (uint256) {
        // Strategy could lie about its value
        return asset.balanceOf(address(this)) + strategy.totalValue();
    }
}

// Malicious strategy:
contract MaliciousStrategy {
    function totalValue() external view returns (uint256) {
        // Report inflated value to hide losses
        return fakeValue; // Not actual holdings
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Independent value verification
contract SecureVault {
    uint256 public lastVerifiedStrategyValue;
    uint256 public lastVerification;
    uint256 public constant MAX_VALUE_DEVIATION = 500; // 5%
    
    function totalAssets() public view returns (uint256) {
        uint256 strategyValue = _getVerifiedStrategyValue();
        return asset.balanceOf(address(this)) + strategyValue;
    }
    
    function _getVerifiedStrategyValue() internal view returns (uint256) {
        uint256 reportedValue = strategy.totalValue();
        
        // Check against last verified value
        if (lastVerifiedStrategyValue > 0) {
            uint256 deviation = reportedValue > lastVerifiedStrategyValue
                ? (reportedValue - lastVerifiedStrategyValue) * 10000 / lastVerifiedStrategyValue
                : (lastVerifiedStrategyValue - reportedValue) * 10000 / lastVerifiedStrategyValue;
            
            if (deviation > MAX_VALUE_DEVIATION) {
                // Use conservative estimate
                return lastVerifiedStrategyValue * (10000 - MAX_VALUE_DEVIATION) / 10000;
            }
        }
        
        return reportedValue;
    }
    
    function verifyStrategyValue() external onlyKeeper {
        // Independent verification of strategy holdings
        uint256 verified = _independentValueCheck();
        lastVerifiedStrategyValue = verified;
        lastVerification = block.timestamp;
    }
}
```

---

### VAULT-AP-22: Reward Token Sandwich

**Severity:** Medium | **Likelihood:** High

**Description:**
Reward token swaps during harvest can be sandwiched for MEV.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Market swap during harvest
contract VulnerableHarvest {
    function harvest() external {
        uint256 rewards = rewardToken.balanceOf(address(this));
        
        // Public swap - can be sandwiched
        uint256 assets = dex.swap(
            address(rewardToken),
            address(asset),
            rewards,
            0 // No slippage protection!
        );
        
        totalManagedAssets += assets;
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Private swap + slippage protection
contract SecureHarvest {
    uint256 public constant MAX_SLIPPAGE_BPS = 100; // 1%
    
    function harvest(uint256 minAssetOut) external onlyKeeper {
        uint256 rewards = rewardToken.balanceOf(address(this));
        
        // Get oracle price for slippage check
        uint256 expectedAssets = oracle.getQuote(
            address(rewardToken),
            address(asset),
            rewards
        );
        uint256 minExpected = expectedAssets * (10000 - MAX_SLIPPAGE_BPS) / 10000;
        
        // Keeper provides minOut, but validate against oracle
        require(minAssetOut >= minExpected, "Slippage too high");
        
        uint256 assets = dex.swap(
            address(rewardToken),
            address(asset),
            rewards,
            minAssetOut
        );
        
        require(assets >= minAssetOut, "Swap failed");
        totalManagedAssets += assets;
    }
}
```

---

### VAULT-AP-23: Multi-Strategy Imbalance

**Severity:** Medium | **Likelihood:** Medium

**Description:**
Imbalanced allocation across strategies creates arbitrage opportunity.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: No rebalancing, manual allocation
contract VulnerableMultiStrategy {
    IStrategy[] public strategies;
    
    function depositToStrategy(uint256 index, uint256 amount) external onlyAdmin {
        // Manual allocation - can become imbalanced
        strategies[index].deposit(amount);
    }
    
    // If Strategy A has 10% APY and Strategy B has 5% APY
    // Attacker deposits, admin allocates to A
    // Attacker gets higher yield than fair share
}
```

**Secure Pattern:**
```solidity
// SECURE: Automatic rebalancing with target weights
contract SecureMultiStrategy {
    struct StrategyConfig {
        IStrategy strategy;
        uint256 targetWeight; // BPS
        uint256 maxDeviation; // BPS
    }
    
    StrategyConfig[] public strategies;
    
    function deposit(uint256 assets) external {
        // Allocate to underweight strategies
        for (uint i = 0; i < strategies.length; i++) {
            uint256 currentWeight = getStrategyWeight(i);
            if (currentWeight < strategies[i].targetWeight) {
                uint256 needed = calculateNeededDeposit(i, assets);
                strategies[i].strategy.deposit(min(needed, assets));
                assets -= min(needed, assets);
            }
        }
    }
    
    function rebalance() external onlyKeeper {
        // Check deviation and rebalance
        for (uint i = 0; i < strategies.length; i++) {
            uint256 currentWeight = getStrategyWeight(i);
            uint256 targetWeight = strategies[i].targetWeight;
            uint256 deviation = currentWeight > targetWeight
                ? currentWeight - targetWeight
                : targetWeight - currentWeight;
            
            if (deviation > strategies[i].maxDeviation) {
                _rebalanceStrategy(i);
            }
        }
    }
}
```

---

### VAULT-AP-24: Idle Fund Exploitation

**Severity:** Low | **Likelihood:** Medium

**Description:**
Uninvested idle funds in vault reduce overall yield, creating unfair distribution.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: High idle cash ratio
contract VulnerableIdleVault {
    uint256 public constant IDLE_BUFFER = 2000; // 20% kept idle
    
    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this)) + strategy.totalValue();
    }
    
    // Problem: New depositors' funds sit idle
    // Old depositors get full strategy yield
    // New depositors dilute yield but contribute less
}
```

**Secure Pattern:**
```solidity
// SECURE: Minimal idle + yield on idle
contract SecureIdleVault {
    uint256 public constant MIN_IDLE_RATIO = 500; // 5% minimum
    IIdleYield public idleStrategy; // Low-risk yield on idle (e.g., Aave)
    
    function rebalanceIdle() external onlyKeeper {
        uint256 currentIdle = asset.balanceOf(address(this));
        uint256 targetIdle = totalAssets() * MIN_IDLE_RATIO / 10000;
        
        if (currentIdle > targetIdle * 120 / 100) {
            // Deploy excess to main strategy
            uint256 excess = currentIdle - targetIdle;
            strategy.deposit(excess);
        } else if (currentIdle < targetIdle * 80 / 100) {
            // Withdraw from strategy to refill idle
            uint256 needed = targetIdle - currentIdle;
            strategy.withdraw(needed);
        }
        
        // Remaining idle goes to low-risk yield
        uint256 toIdleYield = asset.balanceOf(address(this)) - targetIdle;
        if (toIdleYield > 0) {
            idleStrategy.deposit(toIdleYield);
        }
    }
}
```

---

## Category 4: Accounting Anti-Patterns

### VAULT-AP-25: Fee-on-Transfer Token Handling

**Severity:** High | **Likelihood:** Medium

**Description:**
Vault accounting breaks when underlying token has transfer fee.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Assumes full amount received
contract VulnerableFeeToken {
    function deposit(uint256 assets, address receiver) external {
        // User says deposit 100 tokens
        asset.transferFrom(msg.sender, address(this), assets);
        
        // But vault only received 99 (1% fee)
        // Mints shares for 100, actual assets = 99
        uint256 shares = previewDeposit(assets); // Based on 100
        _mint(receiver, shares);
        
        totalManagedAssets += assets; // Wrong: adds 100, not 99
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Measure actual received amount
contract SecureFeeToken {
    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        uint256 balanceBefore = asset.balanceOf(address(this));
        asset.safeTransferFrom(msg.sender, address(this), assets);
        uint256 actualReceived = asset.balanceOf(address(this)) - balanceBefore;
        
        // Use actual received for share calculation
        shares = previewDeposit(actualReceived);
        require(shares > 0, "Zero shares");
        
        _mint(receiver, shares);
        totalManagedAssets += actualReceived;
        
        return shares;
    }
}
```

---

### VAULT-AP-26: Rebasing Token Sync Issues

**Severity:** High | **Likelihood:** Medium

**Description:**
Vault accounting desynchronizes with rebasing token balance changes.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Cached total assets with rebasing token
contract VulnerableRebase {
    uint256 public cachedTotalAssets;
    
    function deposit(uint256 assets) external {
        cachedTotalAssets += assets;
        // ...
    }
    
    function totalAssets() public view returns (uint256) {
        return cachedTotalAssets; // Doesn't reflect rebases!
    }
    
    // If positive rebase: Users lose out on gains
    // If negative rebase: Vault becomes insolvent
}
```

**Secure Pattern:**
```solidity
// SECURE: Real-time balance for rebasing tokens
contract SecureRebase {
    function totalAssets() public view returns (uint256) {
        // Always use actual balance for rebasing tokens
        return asset.balanceOf(address(this)) + strategyValue();
    }
    
    // Or: Convert to non-rebasing wrapper on deposit
    function deposit(uint256 assets) external {
        stETH.transferFrom(msg.sender, address(this), assets);
        uint256 wstETH = wstETH.wrap(assets);
        _depositInternal(wstETH);
    }
}
```

---

### VAULT-AP-27: Performance Fee Miscalculation

**Severity:** Medium | **Likelihood:** Medium

**Description:**
Performance fee calculation errors benefit or harm fee recipient.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Fee calculated on total, not profit
contract VulnerablePerformanceFee {
    uint256 public constant PERFORMANCE_FEE = 2000; // 20%
    
    function harvest() external {
        uint256 yield = getYield();
        
        // WRONG: Fee on gross, not net
        uint256 fee = yield * PERFORMANCE_FEE / 10000;
        
        // Or: Fee calculated before expenses
        // Manager gets fee even on losses
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: High water mark performance fee
contract SecurePerformanceFee {
    uint256 public constant PERFORMANCE_FEE = 2000; // 20%
    uint256 public highWaterMark;
    
    function harvest() external {
        uint256 currentValue = totalAssets();
        
        // Only charge fee on new profits above high water mark
        if (currentValue > highWaterMark) {
            uint256 profit = currentValue - highWaterMark;
            uint256 fee = profit * PERFORMANCE_FEE / 10000;
            
            // Mint shares to fee recipient
            uint256 feeShares = fee * totalSupply() / (currentValue - fee);
            _mint(feeRecipient, feeShares);
            
            highWaterMark = currentValue - fee;
        }
    }
    
    function resetHighWaterMark() external onlyAdmin {
        // Only reset after significant time or loss recovery
        require(
            block.timestamp >= lastReset + 365 days,
            "Too soon"
        );
        highWaterMark = totalAssets();
    }
}
```

---

### VAULT-AP-28: Management Fee Timing Attack

**Severity:** Medium | **Likelihood:** Medium

**Description:**
Management fee application timing can be gamed for extraction.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Fee charged on deposit/withdraw
contract VulnerableManagementFee {
    uint256 public constant ANNUAL_FEE = 200; // 2%
    
    function applyFee() public {
        uint256 fee = totalAssets() * ANNUAL_FEE / 10000;
        // Fee minted as shares to manager
    }
    
    // Attack: Call applyFee right after large deposit
    // New depositor immediately loses 2% to fee
}
```

**Secure Pattern:**
```solidity
// SECURE: Continuous fee accrual
contract SecureManagementFee {
    uint256 public constant ANNUAL_FEE = 200; // 2%
    uint256 public lastFeeCollection;
    
    function _collectFee() internal {
        uint256 elapsed = block.timestamp - lastFeeCollection;
        if (elapsed == 0) return;
        
        // Pro-rata fee for time elapsed
        uint256 feeRate = ANNUAL_FEE * elapsed / 365 days / 10000;
        uint256 fee = totalAssets() * feeRate;
        
        if (fee > 0) {
            uint256 feeShares = fee * totalSupply() / totalAssets();
            _mint(feeRecipient, feeShares);
        }
        
        lastFeeCollection = block.timestamp;
    }
    
    // Call before any deposit/withdraw
    function deposit(uint256 assets, address receiver) external returns (uint256) {
        _collectFee();
        return _deposit(assets, receiver);
    }
}
```

---

### VAULT-AP-29: Multiple Token Decimal Handling

**Severity:** High | **Likelihood:** Medium

**Description:**
Decimal mismatches between vault shares and underlying cause calculation errors.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Assumes same decimals
contract VulnerableDecimals {
    // Vault has 18 decimals, USDC has 6 decimals
    
    function convertToShares(uint256 assets) public view returns (uint256) {
        // 1 USDC (1e6) should give ~1e18 shares
        return assets * totalSupply() / totalAssets();
        
        // Problem: If totalSupply() = 1e18 and totalAssets() = 1e6
        // 1e6 * 1e18 / 1e6 = 1e18 (correct)
        // But precision issues arise with small amounts
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Explicit decimal handling
contract SecureDecimals {
    uint8 public immutable assetDecimals;
    uint8 public constant SHARE_DECIMALS = 18;
    uint256 public immutable decimalOffset;
    
    constructor(IERC20Metadata _asset) {
        assetDecimals = _asset.decimals();
        // Offset to normalize calculations
        decimalOffset = 10 ** (SHARE_DECIMALS - assetDecimals);
    }
    
    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply();
        uint256 totalAss = totalAssets();
        
        // Normalize to 18 decimals for calculation
        return supply == 0
            ? assets * decimalOffset
            : Math.mulDiv(assets, supply, totalAss);
    }
    
    function convertToAssets(uint256 shares) public view returns (uint256) {
        uint256 supply = totalSupply();
        
        // Convert back to asset decimals
        return supply == 0
            ? shares / decimalOffset
            : Math.mulDiv(shares, totalAssets(), supply);
    }
}
```

---

### VAULT-AP-30: Dust Accumulation Exploit

**Severity:** Low | **Likelihood:** Medium

**Description:**
Small rounding remainders accumulate and become extractable.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Dust not tracked
contract VulnerableDust {
    function withdraw(uint256 shares) external {
        uint256 assets = shares * totalAssets() / totalSupply();
        
        // Rounding might leave 1-2 wei behind
        // Over millions of transactions = significant dust
        
        _burn(msg.sender, shares);
        asset.transfer(msg.sender, assets);
    }
}

// Attack: Many small withdrawals to accumulate dust
// Then somehow extract (donation reclaim, etc.)
```

**Secure Pattern:**
```solidity
// SECURE: Dust management
contract SecureDust {
    uint256 public accumulatedDust;
    uint256 public constant DUST_THRESHOLD = 1e15; // Sweep when > 0.001 tokens
    
    function withdraw(uint256 shares) external {
        uint256 totalAss = totalAssets();
        uint256 supply = totalSupply();
        
        uint256 assets = Math.mulDiv(shares, totalAss, supply, Math.Rounding.Down);
        uint256 dust = shares * totalAss - assets * supply;
        
        if (dust > 0) {
            accumulatedDust += dust / supply;
        }
        
        _burn(msg.sender, shares);
        asset.transfer(msg.sender, assets);
    }
    
    function sweepDust() external {
        require(accumulatedDust >= DUST_THRESHOLD, "Below threshold");
        
        // Distribute to all shareholders pro-rata
        // Or send to treasury
        asset.transfer(treasury, accumulatedDust);
        accumulatedDust = 0;
    }
}
```

---

### VAULT-AP-31: Unrealized PnL Accounting

**Severity:** Medium | **Likelihood:** Medium

**Description:**
Unrealized profits/losses in strategy cause incorrect share pricing.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Include unrealized PnL in totalAssets
contract VulnerableUnrealizedPnL {
    function totalAssets() public view returns (uint256) {
        // Includes unrealized gains from LP position
        return asset.balanceOf(address(this)) + strategy.unrealizedValue();
    }
    
    // Problem: Unrealized gains might not be realizable
    // New depositors buy at inflated price
    // When realized, might be less (slippage, IL, etc.)
}
```

**Secure Pattern:**
```solidity
// SECURE: Conservative unrealized valuation
contract SecureUnrealizedPnL {
    uint256 public constant UNREALIZED_DISCOUNT = 500; // 5%
    
    function totalAssets() public view returns (uint256) {
        uint256 realized = asset.balanceOf(address(this));
        uint256 unrealized = strategy.unrealizedValue();
        
        // Discount unrealized for potential slippage/realization costs
        uint256 discountedUnrealized = unrealized * (10000 - UNREALIZED_DISCOUNT) / 10000;
        
        return realized + discountedUnrealized;
    }
    
    // Or: Separate realized/unrealized accounting
    function getConservativeNav() public view returns (uint256) {
        return realizedAssets; // Only count realized
    }
}
```

---

## Category 5: Access Control Anti-Patterns

### VAULT-AP-32: Unprotected Strategy Migration

**Severity:** Critical | **Likelihood:** Medium

**Description:**
Strategy changes without proper safeguards can drain funds.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Instant strategy change
contract VulnerableStrategyMigration {
    function setStrategy(address newStrategy) external onlyAdmin {
        // Old strategy still has funds!
        strategy = IStrategy(newStrategy);
        
        // Approve new strategy
        asset.approve(newStrategy, type(uint256).max);
        
        // Malicious admin can set strategy to drain contract
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Timelock + migration process
contract SecureStrategyMigration {
    address public pendingStrategy;
    uint256 public strategyChangeTimestamp;
    uint256 public constant STRATEGY_TIMELOCK = 7 days;
    
    function proposeStrategyMigration(address newStrategy) external onlyAdmin {
        require(
            IStrategy(newStrategy).asset() == address(asset),
            "Invalid strategy"
        );
        
        pendingStrategy = newStrategy;
        strategyChangeTimestamp = block.timestamp + STRATEGY_TIMELOCK;
        
        emit StrategyMigrationProposed(newStrategy, strategyChangeTimestamp);
    }
    
    function executeMigration() external {
        require(pendingStrategy != address(0), "No pending migration");
        require(
            block.timestamp >= strategyChangeTimestamp,
            "Timelock not passed"
        );
        
        // Withdraw all from old strategy
        uint256 withdrawn = strategy.withdrawAll();
        asset.approve(address(strategy), 0);
        
        // Set new strategy
        strategy = IStrategy(pendingStrategy);
        pendingStrategy = address(0);
        
        // Deposit to new strategy
        asset.approve(address(strategy), withdrawn);
        strategy.deposit(withdrawn);
        
        emit StrategyMigrated(address(strategy));
    }
    
    function cancelMigration() external onlyAdmin {
        pendingStrategy = address(0);
        strategyChangeTimestamp = 0;
    }
}
```

---

### VAULT-AP-33: Missing Guardian Role

**Severity:** High | **Likelihood:** Medium

**Description:**
No emergency role to pause or protect vault in crisis.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Only admin can take action
contract VulnerableNoGuardian {
    address public admin;
    
    // If admin key compromised or unavailable during emergency
    // No one can protect the vault
    
    function pause() external onlyAdmin {
        _pause();
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Separate guardian with limited powers
contract SecureGuardian is Pausable {
    address public admin;
    address public guardian;
    
    modifier onlyAdminOrGuardian() {
        require(
            msg.sender == admin || msg.sender == guardian,
            "Not authorized"
        );
        _;
    }
    
    // Guardian can only pause/emergency actions
    function pause() external onlyAdminOrGuardian {
        _pause();
    }
    
    function emergencyWithdrawFromStrategy() external onlyAdminOrGuardian {
        strategy.withdrawAll();
    }
    
    // Admin can unpause and change settings
    function unpause() external onlyAdmin {
        _unpause();
    }
    
    function setStrategy(address newStrategy) external onlyAdmin {
        // ... with timelock
    }
}
```

---

### VAULT-AP-34: Unlimited Admin Extraction

**Severity:** Critical | **Likelihood:** Low

**Description:**
Admin can extract user funds without constraint.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Admin can withdraw any amount
contract VulnerableAdminExtraction {
    function adminWithdraw(address token, uint256 amount) external onlyAdmin {
        IERC20(token).transfer(admin, amount);
        
        // Can drain user deposits!
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Admin can only sweep non-core tokens
contract SecureAdminWithdraw {
    function sweepToken(address token) external onlyAdmin {
        require(token != address(asset), "Cannot sweep core asset");
        require(token != address(this), "Cannot sweep vault shares");
        
        // Check token is not part of strategy
        require(!isStrategyToken(token), "Cannot sweep strategy token");
        
        // Only sweep accidental tokens
        uint256 balance = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransfer(admin, balance);
    }
    
    // For core asset, can only take earned fees
    function collectFees() external onlyAdmin {
        uint256 fees = accruedFees;
        accruedFees = 0;
        asset.safeTransfer(feeRecipient, fees);
    }
}
```

---

### VAULT-AP-35: Missing Deposit/Withdraw Pause

**Severity:** Medium | **Likelihood:** Medium

**Description:**
Cannot selectively pause deposits or withdrawals during emergencies.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Single pause flag
contract VulnerableSinglePause is Pausable {
    function deposit(uint256 assets) external whenNotPaused {
        // ...
    }
    
    function withdraw(uint256 shares) external whenNotPaused {
        // ...
    }
    
    // Problem: Can't pause deposits while allowing withdrawals
    // During exploit: Need to let users withdraw but stop deposits
}
```

**Secure Pattern:**
```solidity
// SECURE: Granular pause controls
contract SecureGranularPause {
    bool public depositsPaused;
    bool public withdrawalsPaused;
    
    modifier whenDepositsNotPaused() {
        require(!depositsPaused, "Deposits paused");
        _;
    }
    
    modifier whenWithdrawalsNotPaused() {
        require(!withdrawalsPaused, "Withdrawals paused");
        _;
    }
    
    function deposit(uint256 assets) external whenDepositsNotPaused {
        // ...
    }
    
    function withdraw(uint256 shares) external whenWithdrawalsNotPaused {
        // ...
    }
    
    function pauseDeposits() external onlyGuardian {
        depositsPaused = true;
    }
    
    function pauseWithdrawals() external onlyGuardian {
        withdrawalsPaused = true;
    }
    
    function unpauseDeposits() external onlyAdmin {
        depositsPaused = false;
    }
    
    function unpauseWithdrawals() external onlyAdmin {
        withdrawalsPaused = false;
    }
}
```

---

### VAULT-AP-36: Privileged Role Centralization

**Severity:** High | **Likelihood:** Medium

**Description:**
Single address controls all privileged functions.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Single owner controls everything
contract VulnerableCentralized {
    address public owner;
    
    function setStrategy(address s) external onlyOwner { }
    function setFees(uint256 f) external onlyOwner { }
    function pause() external onlyOwner { }
    function upgrade(address impl) external onlyOwner { }
    function withdrawFees() external onlyOwner { }
    
    // Single point of failure
}
```

**Secure Pattern:**
```solidity
// SECURE: Separated roles with multisig
contract SecureDecentralized {
    address public admin;        // Multisig for critical
    address public guardian;     // Hot wallet for emergencies
    address public strategist;   // Strategy management
    address public feeRecipient; // Fee collection
    
    uint256 public constant TIMELOCK = 2 days;
    
    function setStrategy(address s) external onlyAdmin timelocked { }
    function setFees(uint256 f) external onlyAdmin timelocked { }
    function pause() external onlyGuardianOrAdmin { }
    function upgrade(address impl) external onlyAdmin timelocked { }
    function withdrawFees() external {
        // Anyone can trigger, goes to feeRecipient
    }
    
    // Role changes require timelock
    function setAdmin(address newAdmin) external onlyAdmin timelocked {
        require(newAdmin != address(0), "Zero address");
        admin = newAdmin;
    }
}
```

---

### VAULT-AP-37: Unprotected Initialization

**Severity:** Critical | **Likelihood:** Medium

**Description:**
Proxy vaults can be re-initialized or front-run initialized.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Initializer can be called multiple times
contract VulnerableVaultProxy {
    function initialize(address _asset, address _admin) public {
        // No initializer guard!
        asset = _asset;
        admin = _admin;
    }
}

// Or: Front-run deployment
// Attacker sees deploy tx, front-runs initialize with their address
```

**Secure Pattern:**
```solidity
// SECURE: OpenZeppelin initializer
contract SecureVaultProxy is Initializable {
    function initialize(
        address _asset,
        address _admin
    ) public initializer {
        __ERC4626_init(IERC20(_asset));
        __Ownable_init(_admin);
        __ReentrancyGuard_init();
    }
}

// Better: Initialize in same tx as deployment
contract VaultFactory {
    function deployVault(
        address asset,
        address admin
    ) external returns (address) {
        bytes memory initData = abi.encodeCall(
            SecureVaultProxy.initialize,
            (asset, admin)
        );
        
        // Deploy and initialize atomically
        address proxy = address(new ERC1967Proxy(
            implementation,
            initData
        ));
        
        return proxy;
    }
}
```

---

## Category 6: Integration Anti-Patterns

### VAULT-AP-38: Composability Reentrancy

**Severity:** Critical | **Likelihood:** Medium

**Description:**
Vault shares used in DeFi (collateral, LP) create reentrancy vectors.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Share transfer triggers callback
contract VulnerableComposable is ERC4626 {
    function withdraw(uint256 shares, address receiver, address owner) external {
        // Calculate assets
        uint256 assets = previewRedeem(shares);
        
        // Burn shares - triggers callback if receiver is contract
        _burn(owner, shares);
        
        // Transfer assets AFTER burn
        // But callback during burn could reenter
        asset.transfer(receiver, assets);
    }
}

// Composability issue:
// Vault shares used as collateral in lending protocol
// Lending protocol has callback on transfer
// Attacker manipulates state during callback
```

**Secure Pattern:**
```solidity
// SECURE: Reentrancy protection + hook safety
contract SecureComposable is ERC4626, ReentrancyGuard {
    // Override _beforeTokenTransfer to add checks
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 amount
    ) internal override {
        // Prevent transfer during withdrawal
        require(!_inWithdrawal, "No transfer during withdrawal");
    }
    
    bool private _inWithdrawal;
    
    function withdraw(
        uint256 shares,
        address receiver,
        address owner
    ) external nonReentrant {
        _inWithdrawal = true;
        
        uint256 assets = previewRedeem(shares);
        _burn(owner, shares);
        
        _inWithdrawal = false;
        
        asset.safeTransfer(receiver, assets);
    }
}
```

---

### VAULT-AP-39: Oracle Dependency Failure

**Severity:** High | **Likelihood:** Medium

**Description:**
Vault operations depend on oracle that can fail or be manipulated.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Single oracle, no fallback
contract VulnerableOracleDep {
    IOracle public oracle;
    
    function totalAssets() public view returns (uint256) {
        uint256 baseAssets = asset.balanceOf(address(this));
        
        // Strategy holds LP tokens, need to value them
        uint256 lpValue = oracle.getValue(address(lpToken));
        
        // If oracle fails, vault breaks
        // If oracle manipulated, share price wrong
        return baseAssets + lpValue;
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Multiple oracles + fallback
contract SecureOracleDep {
    IOracle[] public oracles;
    uint256 public constant MAX_DEVIATION = 300; // 3%
    
    function getOracleValue(address token) internal view returns (uint256) {
        uint256[] memory values = new uint256[](oracles.length);
        uint256 validCount = 0;
        
        for (uint i = 0; i < oracles.length; i++) {
            try oracles[i].getValue(token) returns (uint256 value) {
                values[validCount++] = value;
            } catch {
                continue;
            }
        }
        
        require(validCount >= 2, "Insufficient oracles");
        
        // Check deviation
        uint256 median = getMedian(values, validCount);
        for (uint i = 0; i < validCount; i++) {
            uint256 deviation = values[i] > median
                ? (values[i] - median) * 10000 / median
                : (median - values[i]) * 10000 / median;
            require(deviation <= MAX_DEVIATION, "Oracle deviation too high");
        }
        
        return median;
    }
    
    // Fallback: Use conservative internal valuation
    function totalAssetsConservative() public view returns (uint256) {
        try this.totalAssets() returns (uint256 value) {
            return value;
        } catch {
            // Fallback to base assets only
            return asset.balanceOf(address(this));
        }
    }
}
```

---

### VAULT-AP-40: Cross-Protocol Dependency Risk

**Severity:** High | **Likelihood:** Medium

**Description:**
Vault depends on external protocol that can fail or change behavior.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Hard dependency on external protocol
contract VulnerableCrossProtocol {
    ILendingPool public aave;
    
    function deposit(uint256 assets) external {
        asset.approve(address(aave), assets);
        aave.supply(address(asset), assets, address(this), 0);
        
        // If Aave changes interface, pauses, or fails
        // Vault becomes unusable
    }
    
    function withdraw(uint256 assets) external {
        aave.withdraw(address(asset), assets, msg.sender);
        
        // If Aave is paused or has withdrawal issues
        // Users can't withdraw
    }
}
```

**Secure Pattern:**
```solidity
// SECURE: Defensive integration
contract SecureCrossProtocol {
    ILendingPool public aave;
    bool public aaveEnabled = true;
    
    function deposit(uint256 assets) external {
        if (aaveEnabled) {
            try this._depositToAave(assets) {
                // Success
            } catch {
                // Fallback: Keep in vault
                aaveEnabled = false;
                emit AaveDisabled("Deposit failed");
            }
        }
        // else: Keep assets in vault
    }
    
    function _depositToAave(uint256 assets) external {
        require(msg.sender == address(this), "Internal only");
        asset.approve(address(aave), assets);
        aave.supply(address(asset), assets, address(this), 0);
    }
    
    function emergencyWithdrawFromAave() external onlyGuardian {
        try aave.withdraw(address(asset), type(uint256).max, address(this)) {
            // Success
        } catch {
            // Log but don't revert
            emit AaveWithdrawFailed();
        }
        aaveEnabled = false;
    }
    
    // Allow users to withdraw even if Aave is down
    function withdraw(uint256 assets) external {
        uint256 available = asset.balanceOf(address(this));
        require(assets <= available, "Insufficient liquid assets");
        // Withdraw from liquid balance
    }
}
```

---

### VAULT-AP-41: Share Token Permit Abuse

**Severity:** High | **Likelihood:** Medium

**Description:**
Permit functionality on vault shares can be abused for gasless attacks.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Standard permit without protection
contract VulnerablePermit is ERC4626, ERC20Permit {
    // Attacker can get user to sign permit for vault shares
    // Then transfer shares without user's active consent
    
    // Combined with redeem:
    // 1. Phish user to sign permit for shares
    // 2. Transfer shares to attacker
    // 3. Redeem for underlying assets
}
```

**Secure Pattern:**
```solidity
// SECURE: Permit restrictions
contract SecurePermit is ERC4626, ERC20Permit {
    mapping(address => bool) public permitDisabled;
    
    function disablePermit() external {
        permitDisabled[msg.sender] = true;
    }
    
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public override {
        require(!permitDisabled[owner], "Permit disabled for owner");
        super.permit(owner, spender, value, deadline, v, r, s);
    }
    
    // Or: Restrict permit to trusted contracts only
    mapping(address => bool) public trustedPermitSpenders;
    
    function permitRestricted(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public {
        require(trustedPermitSpenders[spender], "Untrusted spender");
        super.permit(owner, spender, value, deadline, v, r, s);
    }
}
```

---

### VAULT-AP-42: Nested Vault Loops

**Severity:** Medium | **Likelihood:** Low

**Description:**
Vault of vaults creates circular dependencies or amplified risks.

**Vulnerable Pattern:**
```solidity
// VULNERABLE: Vault invests in vault that invests back
contract VulnerableNestedVault {
    function deposit(uint256 assets) external {
        // Deposit to another vault
        otherVault.deposit(assets);
        
        // If otherVault also invests in this vault
        // Circular dependency = infinite loop risk
        // Or: Correlated failures amplified
    }
}

// Risk amplification:
// Vault A invests in Vault B
// Vault B invests in Protocol X
// Protocol X fails
// Both Vault A and B fail
// But Vault A users expected diversification
```

**Secure Pattern:**
```solidity
// SECURE: Nesting limits + dependency tracking
contract SecureNestedVault {
    uint256 public constant MAX_NESTING_DEPTH = 2;
    
    mapping(address => bool) public isAllowedVault;
    
    function validateNesting(address targetVault) internal view {
        // Check nesting depth
        uint256 depth = getVaultDepth(targetVault);
        require(depth < MAX_NESTING_DEPTH, "Too deeply nested");
        
        // Check no circular dependency
        require(
            !hasCircularDependency(address(this), targetVault),
            "Circular dependency"
        );
    }
    
    function getVaultDepth(address vault) internal view returns (uint256) {
        if (!isVault(vault)) return 0;
        
        address underlying = IVault(vault).asset();
        return 1 + getVaultDepth(underlying);
    }
    
    function hasCircularDependency(
        address start,
        address target
    ) internal view returns (bool) {
        if (!isVault(target)) return false;
        
        address underlying = IVault(target).asset();
        if (underlying == start) return true;
        
        return hasCircularDependency(start, underlying);
    }
}
```

---

## Audit Checklist Summary

### Share Calculation
- [ ] First depositor protection (virtual shares/dead shares)
- [ ] Donation attack mitigation
- [ ] Proper rounding direction per ERC4626
- [ ] Zero share prevention
- [ ] Rebasing token handling

### Deposit/Withdraw
- [ ] Reentrancy protection
- [ ] Slippage protection parameters
- [ ] Withdrawal limits/queues
- [ ] Flash deposit prevention
- [ ] Emergency withdrawal fairness

### Yield/Strategy
- [ ] Harvest frontrunning protection
- [ ] Gradual yield distribution
- [ ] Strategy change timelock
- [ ] Loss socialization mechanism
- [ ] Compound timing controls

### Accounting
- [ ] Fee-on-transfer token handling
- [ ] Rebasing token sync
- [ ] Performance fee high water mark
- [ ] Decimal normalization
- [ ] Dust management

### Access Control
- [ ] Strategy migration safeguards
- [ ] Guardian role for emergencies
- [ ] Granular pause controls
- [ ] Role separation
- [ ] Initialization protection

### Integration
- [ ] Composability reentrancy
- [ ] Oracle fallbacks
- [ ] External dependency resilience
- [ ] Permit abuse prevention
- [ ] Nesting depth limits

---

## References

- [ERC4626 Specification](https://eips.ethereum.org/EIPS/eip-4626)
- [OpenZeppelin ERC4626](https://docs.openzeppelin.com/contracts/4.x/api/token/erc20#ERC4626)
- [Yearn V3 Vault Design](https://github.com/yearn/yearn-vaults-v3)
- [Trail of Bits: ERC4626 Security](https://blog.trailofbits.com/)

---

## Related Documents

- [vault-patterns.md](../patterns/vault-patterns.md)
- [erc4626-patterns.md](../patterns/erc4626-patterns.md)
- [reentrancy-patterns.md](../patterns/reentrancy-patterns.md)
- [math-precision-anti-patterns.md](math-precision-anti-patterns.md)
