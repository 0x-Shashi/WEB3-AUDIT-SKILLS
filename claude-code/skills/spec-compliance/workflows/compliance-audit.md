# Compliance Audit Workflow

Systematic workflow for verifying smart contract compliance with EIP/ERC standards.

---

## Prerequisites

- [ ] Smart contract source code
- [ ] Declared standards the contract implements
- [ ] Contract documentation/specifications
- [ ] Access to EIP/ERC specifications

---

## Phase 1: Standard Identification

### 1.1 Identify Declared Standards

```bash
# Find ERC/EIP references in code
grep -rn "ERC20\|ERC721\|ERC1155\|ERC777\|ERC4626" contracts/
grep -rn "IERC20\|IERC721\|IERC1155\|IERC777\|IERC4626" contracts/

# Find interface inheritance
grep -rn "is.*IERC\|implements.*IERC" contracts/

# Find EIP references
grep -rn "EIP712\|EIP2612\|EIP1967\|EIP2535" contracts/
```

### 1.2 Document Claimed Compliance

```markdown
## Claimed Standards

| Contract | Standard | Location | Notes |
|----------|----------|----------|-------|
| Token.sol | ERC20 | Line 10 | inherits IERC20 |
| Token.sol | ERC2612 | Line 12 | permit function |
| NFT.sol | ERC721 | Line 8 | ERC721Enumerable |
| Vault.sol | ERC4626 | Line 15 | yield vault |
```

### 1.3 Check ERC165 Support

```solidity
// Query supported interfaces
function checkSupportsInterface(address target) external view {
    IERC165 erc165 = IERC165(target);
    
    console.log("ERC165:", erc165.supportsInterface(0x01ffc9a7));
    console.log("ERC721:", erc165.supportsInterface(0x80ac58cd));
    console.log("ERC721Metadata:", erc165.supportsInterface(0x5b5e139f));
    console.log("ERC1155:", erc165.supportsInterface(0xd9b67a26));
}
```

---

## Phase 2: ERC20 Compliance Check

### 2.1 Interface Completeness

```bash
# Check required functions
grep -n "function totalSupply" contracts/
grep -n "function balanceOf" contracts/
grep -n "function transfer" contracts/
grep -n "function allowance" contracts/
grep -n "function approve" contracts/
grep -n "function transferFrom" contracts/

# Check required events
grep -n "event Transfer" contracts/
grep -n "event Approval" contracts/
```

### 2.2 Function Signature Verification

```markdown
## ERC20 Function Signatures

| Function | Expected | Found | Status |
|----------|----------|-------|--------|
| totalSupply() | returns (uint256) |  | |
| balanceOf(address) | returns (uint256) |  | |
| transfer(address,uint256) | returns (bool) |  | |
| allowance(address,address) | returns (uint256) |  | |
| approve(address,uint256) | returns (bool) |  | |
| transferFrom(address,address,uint256) | returns (bool) |  | |
```

### 2.3 Event Compliance

```markdown
## ERC20 Event Compliance

### Transfer Event
- [ ] Emitted on transfer()
- [ ] Emitted on transferFrom()
- [ ] Emitted on mint (from = 0x0)
- [ ] Emitted on burn (to = 0x0)
- [ ] Parameters: (indexed from, indexed to, value)

### Approval Event
- [ ] Emitted on approve()
- [ ] Parameters: (indexed owner, indexed spender, value)
```

### 2.4 Behavior Compliance

```solidity
// Test: transfer(to, 0) should succeed
function testZeroTransfer() {
    uint256 balanceBefore = token.balanceOf(recipient);
    token.transfer(recipient, 0);
    assertEq(token.balanceOf(recipient), balanceBefore);
}

// Test: transferFrom should decrease allowance
function testTransferFromDecrementsAllowance() {
    token.approve(spender, 100);
    vm.prank(spender);
    token.transferFrom(owner, recipient, 50);
    assertEq(token.allowance(owner, spender), 50);
}

// Test: transfer returns true
function testTransferReturnsTrue() {
    bool success = token.transfer(recipient, 100);
    assertTrue(success);
}
```

---

## Phase 3: ERC721 Compliance Check

### 3.1 Interface Completeness

```bash
# Check required functions
grep -n "function balanceOf\|function ownerOf" contracts/
grep -n "function safeTransferFrom\|function transferFrom" contracts/
grep -n "function approve\|function setApprovalForAll" contracts/
grep -n "function getApproved\|function isApprovedForAll" contracts/

# Check required events
grep -n "event Transfer\|event Approval\|event ApprovalForAll" contracts/
```

### 3.2 Safe Transfer Verification

```markdown
## ERC721 Safe Transfer Check

### safeTransferFrom Requirements
- [ ] Checks if recipient is contract
- [ ] Calls onERC721Received if contract
- [ ] Reverts if return value incorrect
- [ ] Reverts if receiver doesn't implement interface
- [ ] Passes correct parameters (operator, from, tokenId, data)
```

### 3.3 Approval Behavior

```solidity
// Test: Approval cleared on transfer
function testApprovalClearedOnTransfer() {
    nft.approve(approved, tokenId);
    assertEq(nft.getApproved(tokenId), approved);
    
    nft.transferFrom(owner, recipient, tokenId);
    assertEq(nft.getApproved(tokenId), address(0));  // Should be cleared
}

// Test: ownerOf reverts for non-existent token
function testOwnerOfRevertsForNonExistent() {
    vm.expectRevert();
    nft.ownerOf(999999);  // Non-existent
}

// Test: balanceOf reverts for zero address
function testBalanceOfRevertsForZeroAddress() {
    vm.expectRevert();
    nft.balanceOf(address(0));
}
```

---

## Phase 4: ERC4626 Compliance Check

### 4.1 Interface Completeness

```bash
# Check all required functions
grep -n "function asset\|function totalAssets" contracts/
grep -n "function convertToShares\|function convertToAssets" contracts/
grep -n "function maxDeposit\|function previewDeposit\|function deposit" contracts/
grep -n "function maxMint\|function previewMint\|function mint" contracts/
grep -n "function maxWithdraw\|function previewWithdraw\|function withdraw" contracts/
grep -n "function maxRedeem\|function previewRedeem\|function redeem" contracts/
```

### 4.2 Rounding Direction Verification

```solidity
// Test: convertToShares rounds DOWN
function testConvertToSharesRoundsDown() {
    // Setup: 100 shares, 101 assets
    // convertToShares(1) should return 0, not 1
    uint256 shares = vault.convertToShares(1);
    assertEq(shares, 0);  // Rounded down
}

// Test: previewMint rounds UP
function testPreviewMintRoundsUp() {
    // Setup: 100 shares, 99 assets
    // previewMint(1) should return 1, not 0
    uint256 assets = vault.previewMint(1);
    assertGe(assets, 1);  // Rounded up
}

// Test: previewWithdraw rounds UP
function testPreviewWithdrawRoundsUp() {
    // User burns MORE shares than minimum needed
    uint256 shares = vault.previewWithdraw(1);
    uint256 actual = vault.withdraw(1, user, user);
    assertLe(actual, shares);  // Actually burned <= preview
}
```

### 4.3 Invariant Testing

```solidity
// Invariant: convertToShares(convertToAssets(x))  x
function testSharesAssetsRoundTrip(uint256 shares) {
    vm.assume(shares > 0 && shares <= vault.totalSupply());
    uint256 assets = vault.convertToAssets(shares);
    uint256 sharesBack = vault.convertToShares(assets);
    // Should be approximately equal (within rounding)
    assertApproxEqAbs(sharesBack, shares, 1);
}

// Invariant: deposit gives at least previewDeposit shares
function testDepositGivesAtLeastPreview(uint256 assets) {
    vm.assume(assets > 0 && assets <= vault.maxDeposit(user));
    uint256 preview = vault.previewDeposit(assets);
    uint256 actual = vault.deposit(assets, user);
    assertGe(actual, preview);  // May get MORE shares
}
```

### 4.4 Inflation Attack Check

```solidity
// Test: First depositor inflation attack
function testInflationAttack() {
    // Attacker is first depositor with 1 wei
    vm.prank(attacker);
    vault.deposit(1, attacker);
    
    // Attacker donates tokens directly (not via deposit)
    asset.transfer(address(vault), 10000e18);
    
    // Victim deposits large amount
    vm.prank(victim);
    uint256 shares = vault.deposit(9999e18, victim);
    
    // Victim should get meaningful shares, not 0
    assertGt(shares, 0, "Inflation attack: victim got 0 shares");
}
```

---

## Phase 5: EIP712 Compliance Check

### 5.1 Domain Separator Verification

```bash
# Find domain separator
grep -n "DOMAIN_SEPARATOR\|EIP712Domain\|domainSeparator" contracts/

# Find type hashes
grep -n "TYPEHASH\|keccak256.*\".*(" contracts/
```

### 5.2 Type Hash Format Check

```markdown
## EIP712 Type Hash Verification

### Domain Type Hash
Expected: `EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)`
Found: 

### Struct Type Hashes
| Struct | Expected Format | Found | Status |
|--------|-----------------|-------|--------|
| Permit | `Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)` |  | |

### Common Issues
- [ ] No extra spaces in type strings
- [ ] Parameters in correct order
- [ ] Nested types in alphabetical order
```

### 5.3 Chain Fork Handling

```solidity
// Test: DOMAIN_SEPARATOR updates on chain fork
function testDomainSeparatorUpdatesOnFork() {
    bytes32 original = token.DOMAIN_SEPARATOR();
    
    // Simulate chain fork
    vm.chainId(999);
    
    bytes32 afterFork = token.DOMAIN_SEPARATOR();
    assertNotEq(original, afterFork, "DOMAIN_SEPARATOR should change on fork");
}
```

---

## Phase 6: EIP2612 Permit Compliance

### 6.1 Function Verification

```bash
# Check permit function
grep -n "function permit" contracts/
grep -n "function nonces" contracts/
grep -n "DOMAIN_SEPARATOR" contracts/
```

### 6.2 Permit Behavior Testing

```solidity
// Test: permit sets allowance correctly
function testPermitSetsAllowance() {
    bytes32 digest = getPermitDigest(owner, spender, value, nonce, deadline);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);
    
    token.permit(owner, spender, value, deadline, v, r, s);
    
    assertEq(token.allowance(owner, spender), value);
}

// Test: permit reverts after deadline
function testPermitRevertsAfterDeadline() {
    uint256 deadline = block.timestamp - 1;  // Expired
    bytes32 digest = getPermitDigest(owner, spender, value, nonce, deadline);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, digest);
    
    vm.expectRevert();
    token.permit(owner, spender, value, deadline, v, r, s);
}

// Test: permit increments nonce
function testPermitIncrementsNonce() {
    uint256 nonceBefore = token.nonces(owner);
    
    // Valid permit
    token.permit(owner, spender, value, deadline, v, r, s);
    
    assertEq(token.nonces(owner), nonceBefore + 1);
}

// Test: permit reverts for wrong signer
function testPermitRevertsForWrongSigner() {
    bytes32 digest = getPermitDigest(owner, spender, value, nonce, deadline);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(attackerPrivateKey, digest);  // Wrong signer
    
    vm.expectRevert();
    token.permit(owner, spender, value, deadline, v, r, s);
}
```

---

## Phase 7: Proxy Compliance Check

### 7.1 Storage Slot Verification

```solidity
// Verify EIP1967 storage slots
function testEIP1967Slots() {
    // Implementation slot
    bytes32 implSlot = bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
    assertEq(implSlot, 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc);
    
    // Admin slot
    bytes32 adminSlot = bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1);
    assertEq(adminSlot, 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103);
    
    // Verify actual values
    address impl = address(uint160(uint256(vm.load(address(proxy), implSlot))));
    assertEq(impl, expectedImplementation);
}
```

### 7.2 Upgrade Event Verification

```markdown
## Proxy Event Compliance

### Required Events
- [ ] Upgraded(address indexed implementation) - on upgrade
- [ ] AdminChanged(address previousAdmin, address newAdmin) - on admin change
- [ ] BeaconUpgraded(address indexed beacon) - for beacon proxies
```

### 7.3 UUPS Specific Checks

```solidity
// Test: Only authorized can upgrade
function testOnlyAuthorizedCanUpgrade() {
    vm.prank(attacker);
    vm.expectRevert();
    uupsProxy.upgradeTo(newImplementation);
}

// Test: proxiableUUID returns correct slot
function testProxiableUUID() {
    bytes32 uuid = implementation.proxiableUUID();
    assertEq(uuid, 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc);
}
```

---

## Phase 8: Generate Compliance Report

### 8.1 Summary Template

```markdown
# Compliance Audit Report

## Summary

| Standard | Compliance | Issues |
|----------|------------|--------|
| ERC20 |  Compliant | 0 |
| ERC721 |  Partial | 2 |
| ERC4626 |  Non-compliant | 3 |
| EIP712 |  Compliant | 0 |

## Detailed Findings

### [C-01] ERC4626 Inflation Attack Possible

**Severity**: Critical
**Standard**: ERC4626
**Location**: Vault.sol

**Description**: The vault is vulnerable to the first depositor inflation attack. An attacker can manipulate the share/asset ratio to steal deposits from subsequent users.

**Recommendation**: Implement virtual shares/assets offset or mint dead shares on first deposit.

---

### [M-01] ERC721 Approval Not Cleared on Transfer

**Severity**: Medium
**Standard**: ERC721
**Location**: NFT.sol:transferFrom()

**Description**: Token approvals are not cleared when tokens are transferred, violating ERC721 specification.

**Recommendation**: Call `_approve(address(0), tokenId)` in `_transfer()`.
```

### 8.2 Compliance Matrix

```markdown
## Compliance Matrix

### ERC20 Compliance

| Requirement | Section | Status | Notes |
|-------------|---------|--------|-------|
| totalSupply() | 3.1 |  | |
| balanceOf(address) | 3.1 |  | |
| transfer(address,uint256) | 3.1 |  | |
| transfer returns bool | 3.1 |  | Returns void |
| Transfer event on transfer | 3.2 |  | |
| Transfer event on mint | 3.2 |  | Missing |

### ERC721 Compliance

| Requirement | Section | Status | Notes |
|-------------|---------|--------|-------|
| ownerOf reverts for non-existent | 4.1 |  | |
| safeTransferFrom checks receiver | 4.2 |  | Not checking |
| Approval cleared on transfer | 4.3 |  | Persists |
```

---

## Quick Compliance Checklist

```markdown
## Final Compliance Checklist

### ERC20
- [ ] All 6 functions present with correct signatures
- [ ] Transfer and Approval events emitted correctly
- [ ] Returns bool on transfer/approve (or uses no return)
- [ ] Zero address handling

### ERC721
- [ ] All functions present with correct signatures
- [ ] Events with indexed parameters
- [ ] safeTransferFrom calls onERC721Received
- [ ] Approval cleared on transfer
- [ ] ownerOf reverts for non-existent

### ERC4626
- [ ] All preview functions implemented
- [ ] Rounding directions correct
- [ ] Inflation attack mitigated
- [ ] max* functions accurate

### EIP712
- [ ] Domain separator includes chainId
- [ ] Updates on chain fork
- [ ] Type hashes correctly formatted

### Proxy
- [ ] Correct storage slots (EIP1967)
- [ ] Events on upgrade/admin change
- [ ] Initialization protected
- [ ] Storage layout preserved
```

