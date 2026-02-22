# Attack Chain: Cross-Contract Interaction

## Overview

Attacker exploits trust assumptions between contracts, using one contract as a stepping stone to compromise another. Includes cross-contract reentrancy, callback exploits, and inter-protocol composability attacks.

**Complexity:** Medium-High
**Typical Severity:** CRITICAL
**Protocols At Risk:** DeFi protocols with external integrations, lending/borrowing, yield aggregators, any multi-contract system

---

## Attack Steps

```
IDENTIFY TRUST BOUNDARY → CRAFT MALICIOUS CONTRACT → EXPLOIT CALLBACK/INTERACTION → VIOLATE INVARIANTS → EXTRACT VALUE
```

### Step 1: Identify Trust Boundaries
```
- Find contracts that call external contracts
- Map which functions are called on external addresses
- Identify where return values are trusted without validation
- Find cross-contract state dependencies
```

### Step 2: Cross-Contract Reentrancy
```
Contract A updates a shared state variable
Contract A calls external contract (attacker)
Attacker re-enters Contract B (which reads the not-yet-updated shared state)
Contract B acts on stale/inconsistent state
```

### Step 3: Callback Exploitation
```
Protocol calls token.transfer() or hook
Token has callback (ERC777, ERC1155, ERC721)
Callback gives attacker execution control
Attacker interacts with protocol in inconsistent state
```

### Step 4: Extract Value
```
- Borrow at wrong collateral ratio
- Swap at wrong price
- Withdraw more than deposited
- Bypass access controls through delegatecall chains
```

---

## Code Signals

### Cross-Contract Reentrancy (Shared State)
```solidity
// [VULNERABLE] Contract A and B share state but only A has reentrancy guard
contract VaultA {
    mapping(address => uint256) public shares; // shared via cross-contract call

    function withdraw(uint256 amount) external nonReentrant {
        shares[msg.sender] -= amount;
        // Calls external - attacker re-enters VaultB which reads shares[]
        token.transfer(msg.sender, amount);
        // State updated in A, but B already read stale value
    }
}

contract VaultB {
    VaultA public vaultA;

    function getCollateral(address user) public view returns (uint256) {
        return vaultA.shares(user); // Reads stale state during A's transfer
    }

    function borrow(uint256 amount) external {
        require(getCollateral(msg.sender) >= amount); // Stale check!
        // Lend based on stale collateral value
    }
}
```

### Untrusted External Call
```solidity
// [VULNERABLE] Trusts return value from arbitrary contract
function getPrice(address token) internal returns (uint256) {
    // Attacker deploys contract at 'token' that returns fake price
    (bool success, bytes memory data) = token.call(
        abi.encodeWithSignature("getPrice()")
    );
    return abi.decode(data, (uint256)); // Trusted without validation!
}
```

### Delegatecall to User-Controlled Address
```solidity
// [VULNERABLE] Delegatecall preserves msg.sender and storage context
function execute(address target, bytes calldata data) external {
    // Attacker can make this contract execute arbitrary code
    // in its own storage context
    (bool success,) = target.delegatecall(data);
    require(success);
}
```

### Inter-Protocol Composability
```solidity
// [VULNERABLE] Assumes external protocol state is consistent
function liquidate(address user) external {
    uint256 collateralValue = externalOracle.getPrice(collateralToken) * collateralAmount;
    uint256 debtValue = externalOracle.getPrice(debtToken) * debtAmount;

    // If externalOracle is manipulable (e.g., spot price),
    // attacker can trigger false liquidations
    require(collateralValue < debtValue * liquidationThreshold / 100);
    _executeLiquidation(user);
}
```

### Callback During State Transition
```solidity
// [VULNERABLE] ERC721 safeTransferFrom triggers onERC721Received callback
function claimNFT(uint256 tokenId) external {
    require(claims[msg.sender][tokenId], "Not claimable");
    // Callback happens BEFORE state update
    nft.safeTransferFrom(address(this), msg.sender, tokenId);
    // Attacker's onERC721Received re-enters and claims again
    claims[msg.sender][tokenId] = false; // Too late!
}
```

---

## Attack Variants

| Variant | Mechanism | Example |
|---------|-----------|---------|
| Cross-contract reentrancy | Re-enter different contract sharing state | Curve/Vyper exploit |
| Read-only reentrancy | View function returns stale data during callback | Balancer pool reentrancy |
| Callback exploitation | ERC777/721/1155 callbacks give control | imBTC Uniswap drain |
| Delegatecall chain | Proxy + delegatecall to attacker | Parity wallet hack |
| Return value trust | Trust external return without validation | Custom token exploits |
| Flash loan composability | Borrow → manipulate protocol A → exploit protocol B | Cream Finance |

---

## Detection Checklist

Cross-contract state:
- [ ] Identify ALL contracts that share state (directly or via reads)
- [ ] Reentrancy guards applied consistently across ALL related contracts
- [ ] Global reentrancy lock for multi-contract systems
- [ ] State updates happen BEFORE external calls (CEI) in ALL contracts
- [ ] View functions account for mid-transaction state

External calls:
- [ ] Return values validated, not blindly trusted
- [ ] No delegatecall to user-controlled addresses
- [ ] External call targets are whitelisted/verified
- [ ] Callbacks from token transfers handled (ERC777, ERC721, ERC1155)
- [ ] Low-level calls check success AND validate return data

Composability:
- [ ] Price feeds resistant to single-tx manipulation
- [ ] Protocol doesn't assume external protocol state is atomic
- [ ] Flash loan interactions considered
- [ ] Reentrancy protection covers cross-protocol calls

---

## Real-World Examples

| Protocol | Loss | Method | Year |
|----------|------|--------|------|
| Curve/Vyper | $70M | Cross-contract reentrancy via Vyper bug | 2023 |
| Parity Wallet | $150M | Delegatecall to self-destructed library | 2017 |
| Cream Finance | $130M | Flash loan + cross-protocol manipulation | 2021 |
| Fei Protocol | $80M | Cross-contract reentrancy in Rari pools | 2022 |
| imBTC/Uniswap | $300K | ERC777 callback reentrancy | 2020 |

---

## Mitigations

| Mitigation | Effectiveness | Notes |
|-----------|---------------|-------|
| Global reentrancy lock | HIGH | Single lock across all related contracts |
| CEI pattern everywhere | HIGH | All contracts, not just entry point |
| No delegatecall to user input | HIGH | Whitelist targets only |
| Validate all return values | HIGH | Don't trust external contracts |
| Check-lock-interact pattern | HIGH | Lock before any external call |
| View function reentrancy guards | MEDIUM | Prevent read-only reentrancy |
| Interface validation | MEDIUM | Verify contract implements expected interface |

---

## Related Patterns

- [Reentrancy Patterns](../patterns/reentrancy-patterns.md)
- [Proxy Patterns](../patterns/proxy-patterns.md)
- [Composability Patterns](../patterns/composability-patterns.md)
- [Access Control Patterns](../patterns/access-control-patterns.md)
