# EIP Security Considerations

Security implications and common vulnerabilities associated with each major EIP/ERC standard.

---

## ERC20 Security Issues

### Issue: Missing Return Value Handling

**Severity**: High | **Frequency**: Common

```solidity
// ❌ VULNERABLE: Assumes transfer returns bool
function transferTokens(IERC20 token, address to, uint256 amount) {
    require(token.transfer(to, amount), "Transfer failed");  // Reverts for USDT
}

// ✅ SECURE: Use SafeERC20
using SafeERC20 for IERC20;
function transferTokens(IERC20 token, address to, uint256 amount) {
    token.safeTransfer(to, amount);
}
```

**Affected Tokens**: USDT, BNB, OMG, MKR (old)

---

### Issue: Allowance Race Condition (Front-Running)

**Severity**: Medium | **Frequency**: Common

```solidity
// Attack scenario:
// 1. Alice approves Bob for 100 tokens
// 2. Alice wants to change approval to 50
// 3. Bob front-runs the approve(50) tx
// 4. Bob calls transferFrom for 100
// 5. Alice's approve(50) executes
// 6. Bob calls transferFrom for 50
// 7. Bob got 150 instead of 100

// ❌ VULNERABLE: Direct approval change
token.approve(spender, newAmount);

// ✅ SAFER: Increase/decrease pattern
function increaseAllowance(address spender, uint256 addedValue) public returns (bool) {
    _approve(msg.sender, spender, _allowances[msg.sender][spender] + addedValue);
    return true;
}

// ✅ SAFER: Set to 0 first (still race possible but lower risk)
token.approve(spender, 0);
token.approve(spender, newAmount);
```

---

### Issue: Integer Overflow/Underflow (Pre-0.8.0)

**Severity**: Critical | **Frequency**: Legacy contracts

```solidity
// ❌ VULNERABLE (Solidity < 0.8.0)
function transfer(address to, uint256 amount) public returns (bool) {
    balances[msg.sender] -= amount;  // Underflow possible
    balances[to] += amount;          // Overflow possible
    return true;
}

// ✅ SECURE: Use SafeMath or Solidity 0.8+
function transfer(address to, uint256 amount) public returns (bool) {
    require(balances[msg.sender] >= amount, "Insufficient balance");
    unchecked {
        balances[msg.sender] -= amount;  // Underflow impossible due to require
    }
    balances[to] += amount;  // Checked by default in 0.8+
    return true;
}
```

---

## ERC721 Security Issues

### Issue: Reentrancy via onERC721Received

**Severity**: High | **Frequency**: Common

```solidity
// ❌ VULNERABLE: State updated after external call
function buyNFT(uint256 tokenId) external payable {
    require(msg.value >= price[tokenId]);
    
    // External call - receiver can reenter
    nft.safeTransferFrom(seller, msg.sender, tokenId);
    
    // State update AFTER external call
    sold[tokenId] = true;
}

// Attack: Receiver's onERC721Received reenters buyNFT before sold[tokenId] is set

// ✅ SECURE: CEI pattern + reentrancy guard
function buyNFT(uint256 tokenId) external payable nonReentrant {
    require(msg.value >= price[tokenId]);
    require(!sold[tokenId], "Already sold");
    
    // Effects BEFORE interactions
    sold[tokenId] = true;
    
    // Interaction last
    nft.safeTransferFrom(seller, msg.sender, tokenId);
}
```

---

### Issue: Approval Not Cleared on Transfer

**Severity**: Medium | **Frequency**: Implementation error

```solidity
// ❌ SPEC VIOLATION: Approval persists after transfer
function transferFrom(address from, address to, uint256 tokenId) public {
    require(_isApprovedOrOwner(msg.sender, tokenId));
    _transfer(from, to, tokenId);
    // Missing: _approve(address(0), tokenId);
}

// ✅ CORRECT: Clear approval on transfer
function _transfer(address from, address to, uint256 tokenId) internal {
    require(ownerOf(tokenId) == from);
    _approve(address(0), tokenId);  // Clear approval
    _owners[tokenId] = to;
    emit Transfer(from, to, tokenId);
}
```

---

### Issue: Missing onERC721Received Check

**Severity**: Medium | **Frequency**: Implementation error

```solidity
// ❌ SPEC VIOLATION: safeTransferFrom doesn't check receiver
function safeTransferFrom(address from, address to, uint256 tokenId) public {
    transferFrom(from, to, tokenId);
    // Missing receiver check!
}

// ✅ CORRECT: Check receiver
function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data) public {
    transferFrom(from, to, tokenId);
    require(_checkOnERC721Received(from, to, tokenId, data), "ERC721: non-receiver");
}

function _checkOnERC721Received(address from, address to, uint256 tokenId, bytes memory data) 
    private returns (bool) 
{
    if (to.code.length > 0) {
        try IERC721Receiver(to).onERC721Received(msg.sender, from, tokenId, data) returns (bytes4 retval) {
            return retval == IERC721Receiver.onERC721Received.selector;
        } catch {
            return false;
        }
    }
    return true;
}
```

---

## ERC777 Security Issues

### Issue: Reentrancy via Hooks (CRITICAL)

**Severity**: Critical | **Frequency**: By design

```solidity
// ERC777 ALWAYS calls hooks on every transfer:
// 1. tokensToSend (on sender)
// 2. tokensReceived (on recipient)

// ❌ EXTREMELY VULNERABLE: Any ERC777 integration without guards
contract VulnerablePool {
    function deposit(IERC777 token, uint256 amount) external {
        token.send(address(this), amount, "");
        // tokensReceived hook called on pool
        // Hook can reenter deposit() before balance updated
        
        balances[msg.sender] += amount;  // Updated AFTER hook
    }
}

// Real-world impact: imBTC/Uniswap hack - $25M lost

// ✅ SECURE: Reentrancy guard + CEI
contract SecurePool is ReentrancyGuard {
    function deposit(IERC777 token, uint256 amount) external nonReentrant {
        uint256 balanceBefore = token.balanceOf(address(this));
        token.send(address(this), amount, "");  // Hook called here
        uint256 received = token.balanceOf(address(this)) - balanceBefore;
        
        balances[msg.sender] += received;
    }
}

// ✅ BEST: Block ERC777 tokens entirely
function deposit(IERC20 token, uint256 amount) external {
    require(!isERC777(address(token)), "ERC777 not supported");
    // ...
}
```

---

## ERC4626 Security Issues

### Issue: Inflation Attack

**Severity**: Critical | **Frequency**: Common in naive implementations

```solidity
// Attack on empty vault:
// 1. Attacker deposits 1 wei → gets 1 share
// 2. Attacker donates 10000 tokens to vault (not via deposit)
// 3. Vault now has 10000 tokens, 1 share
// 4. Victim deposits 9999 tokens
// 5. Victim gets: 9999 * 1 / 10000 = 0 shares (rounds down!)
// 6. Attacker redeems 1 share → gets all ~20000 tokens

// ❌ VULNERABLE: No protection
function convertToShares(uint256 assets) public view returns (uint256) {
    uint256 supply = totalSupply();
    return supply == 0 ? assets : assets * supply / totalAssets();
}

// ✅ SECURE: Virtual offset (OpenZeppelin pattern)
uint256 constant OFFSET = 10 ** decimalsOffset;  // e.g., 1e3

function _convertToShares(uint256 assets, Math.Rounding rounding) internal view returns (uint256) {
    return assets.mulDiv(totalSupply() + OFFSET, totalAssets() + 1, rounding);
}

// ✅ SECURE: Dead shares (mint to dead address on first deposit)
function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
    if (totalSupply() == 0) {
        // Mint dead shares to prevent inflation attack
        _mint(address(0xdead), 1000);
    }
    // ... rest of deposit
}
```

---

### Issue: Rounding Direction Errors

**Severity**: High | **Frequency**: Common

```solidity
// ❌ WRONG: Always rounds down
function previewMint(uint256 shares) public view returns (uint256) {
    return shares * totalAssets() / totalSupply();  // Should round UP
}

// ✅ CORRECT: Round UP for user-pays scenarios
function previewMint(uint256 shares) public view returns (uint256) {
    return shares.mulDiv(totalAssets(), totalSupply(), Math.Rounding.Ceil);
}

// Rounding rules:
// - previewDeposit: DOWN (user gets fewer shares)
// - previewMint: UP (user pays more assets)
// - previewWithdraw: UP (user burns more shares)
// - previewRedeem: DOWN (user gets fewer assets)
```

---

## EIP712 Security Issues

### Issue: Cross-Chain Replay

**Severity**: High | **Frequency**: Common in forks

```solidity
// ❌ VULNERABLE: Cached domain separator doesn't update on fork
bytes32 public immutable DOMAIN_SEPARATOR;  // Set at deploy

constructor() {
    DOMAIN_SEPARATOR = computeDomainSeparator();  // Uses block.chainid
}

// After chain fork, DOMAIN_SEPARATOR is stale!
// Signatures valid on one chain can replay on fork

// ✅ SECURE: Recompute on chain change
bytes32 private immutable INITIAL_CHAIN_ID;
bytes32 private immutable INITIAL_DOMAIN_SEPARATOR;

constructor() {
    INITIAL_CHAIN_ID = block.chainid;
    INITIAL_DOMAIN_SEPARATOR = computeDomainSeparator();
}

function DOMAIN_SEPARATOR() public view returns (bytes32) {
    return block.chainid == INITIAL_CHAIN_ID 
        ? INITIAL_DOMAIN_SEPARATOR 
        : computeDomainSeparator();
}
```

---

### Issue: Wrong Type Hash Format

**Severity**: Medium | **Frequency**: Implementation error

```solidity
// ❌ WRONG: Extra spaces, wrong order
bytes32 constant PERMIT_TYPEHASH = keccak256(
    "Permit(address owner, address spender, uint256 value, uint256 nonce, uint256 deadline)"
    //                   ^ extra spaces - signature won't match!
);

// ❌ WRONG: Parameters in wrong order
bytes32 constant PERMIT_TYPEHASH = keccak256(
    "Permit(address spender,address owner,uint256 value,uint256 nonce,uint256 deadline)"
    //      ^ spender before owner - doesn't match spec!
);

// ✅ CORRECT: Exact format per spec
bytes32 constant PERMIT_TYPEHASH = keccak256(
    "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
);
```

---

## EIP2612 Permit Security Issues

### Issue: Missing Deadline Check

**Severity**: High | **Frequency**: Implementation error

```solidity
// ❌ VULNERABLE: Deadline checked after signature verification
function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
    address signer = ecrecover(digest, v, r, s);
    require(signer == owner, "Invalid signature");
    require(deadline >= block.timestamp, "Expired");  // Too late!
    // Attacker can reuse expired permit if they have valid signature
    
    _approve(owner, spender, value);
}

// ✅ SECURE: Check deadline first
function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
    require(deadline >= block.timestamp, "Expired");
    
    bytes32 digest = keccak256(abi.encodePacked(
        "\x19\x01",
        DOMAIN_SEPARATOR(),
        keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline))
    ));
    
    address signer = ecrecover(digest, v, r, s);
    require(signer != address(0) && signer == owner, "Invalid signature");
    
    _approve(owner, spender, value);
}
```

---

### Issue: ecrecover Returns Zero Address

**Severity**: High | **Frequency**: Common oversight

```solidity
// ❌ VULNERABLE: Zero address check missing
function permit(...) external {
    address signer = ecrecover(digest, v, r, s);
    require(signer == owner, "Invalid");  // Passes if owner == address(0)!
}

// ✅ SECURE: Check for zero address
function permit(...) external {
    address signer = ecrecover(digest, v, r, s);
    require(signer != address(0), "Invalid signature");
    require(signer == owner, "Wrong signer");
}
```

---

## EIP1967 Proxy Security Issues

### Issue: Uninitialized Implementation

**Severity**: Critical | **Frequency**: Common

```solidity
// ❌ VULNERABLE: Implementation can be initialized by attacker
contract Implementation {
    address public owner;
    
    function initialize(address _owner) external {
        owner = _owner;  // No initialization guard!
    }
}

// Attack:
// 1. Find uninitialized implementation contract
// 2. Call initialize(attacker) directly on implementation
// 3. In some cases, this can be leveraged to destroy proxy

// ✅ SECURE: Use initializer modifier
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract Implementation is Initializable {
    address public owner;
    
    function initialize(address _owner) external initializer {
        owner = _owner;
    }
}
```

---

### Issue: Storage Collision on Upgrade

**Severity**: Critical | **Frequency**: Common during upgrades

```solidity
// V1 Implementation
contract V1 {
    uint256 public value;     // Slot 0
    address public owner;     // Slot 1
}

// ❌ DANGEROUS V2: Changed storage layout
contract V2 {
    address public owner;     // Slot 0 - COLLISION with value!
    uint256 public value;     // Slot 1 - COLLISION with owner!
    uint256 public newValue;  // Slot 2 - OK
}

// ✅ SAFE V2: Append only
contract V2 {
    uint256 public value;     // Slot 0 - Same
    address public owner;     // Slot 1 - Same
    uint256 public newValue;  // Slot 2 - New, appended
}

// ✅ BEST: Use storage gap pattern
contract V1 {
    uint256 public value;
    address public owner;
    
    uint256[48] private __gap;  // Reserve 48 slots for future
}
```

---

## UUPS (EIP1822) Security Issues

### Issue: Missing Upgrade Authorization

**Severity**: Critical | **Frequency**: Implementation error

```solidity
// ❌ VULNERABLE: Anyone can upgrade
contract VulnerableUUPS is UUPSUpgradeable {
    function _authorizeUpgrade(address newImplementation) internal override {
        // No access control!
    }
}

// ✅ SECURE: Proper authorization
contract SecureUUPS is UUPSUpgradeable, OwnableUpgradeable {
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {
        // Only owner can upgrade
    }
}
```

---

### Issue: Implementation Without Upgrade Logic

**Severity**: Critical | **Frequency**: Can happen during upgrade

```solidity
// If V2 implementation doesn't include UUPS upgrade logic,
// the proxy becomes permanently locked!

// ❌ DANGEROUS: V2 removes upgrade capability
contract V2 {  // Not UUPSUpgradeable!
    // No upgradeTo function
    // Proxy is now BRICKED
}

// ✅ SAFE: Always inherit UUPS
contract V2 is UUPSUpgradeable, OwnableUpgradeable {
    function _authorizeUpgrade(address) internal override onlyOwner {}
}
```

---

## ERC4337 Account Abstraction Security

### Issue: Signature Replay Across Accounts

**Severity**: High | **Frequency**: Design consideration

```solidity
// ❌ VULNERABLE: Signature valid for multiple accounts
function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds) 
    external returns (uint256) 
{
    // Only validates signature, not that it's for THIS account
    require(ECDSA.recover(userOpHash, userOp.signature) == owner);
    return 0;
}

// ✅ SECURE: Include account address in validation
function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds) 
    external returns (uint256) 
{
    require(msg.sender == entryPoint, "Not from EntryPoint");
    require(userOp.sender == address(this), "Wrong account");
    
    bytes32 hash = keccak256(abi.encodePacked(userOpHash, address(this), block.chainid));
    require(ECDSA.recover(hash, userOp.signature) == owner);
    return 0;
}
```

---

## Quick Security Checklist by Standard

### ERC20
- [ ] Using SafeERC20?
- [ ] Approve race condition considered?
- [ ] Transfer event on mint/burn?

### ERC721
- [ ] Reentrancy guard on safeTransfer?
- [ ] Approval cleared on transfer?
- [ ] onERC721Received check implemented?

### ERC777
- [ ] **DO NOT USE** without extensive review
- [ ] Reentrancy guard on ALL functions?
- [ ] Consider blocking ERC777 tokens

### ERC4626
- [ ] Inflation attack mitigation?
- [ ] Rounding directions correct?
- [ ] Preview functions match actual?

### EIP712
- [ ] Domain separator includes chainId?
- [ ] Recomputed on chain fork?
- [ ] Type hash format exact?

### EIP2612
- [ ] Deadline checked before signature?
- [ ] Zero address check on ecrecover?
- [ ] Nonce incremented before use?

### EIP1967/UUPS
- [ ] Implementation initialized?
- [ ] Storage layout preserved?
- [ ] Upgrade authorization proper?
- [ ] UUPS logic in all versions?
