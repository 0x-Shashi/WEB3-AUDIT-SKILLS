---
name: Spec Compliance Checker
description: Verify smart contract compliance with EIP/ERC standards and specifications
version: 1.0.0
author: Web3 Security Plugin
tags: [eip, erc, compliance, standards, specification, audit]
---

# Spec Compliance Checker Skill

Comprehensive checker for verifying smart contract compliance with Ethereum Improvement Proposals (EIPs), ERC standards, and protocol specifications.

## Capabilities

- **ERC Token Standards**: ERC20, ERC721, ERC1155, ERC4626 compliance
- **Signature Standards**: EIP712, EIP2612 (Permit), EIP1271
- **Account Standards**: ERC4337 (Account Abstraction), ERC6900
- **DeFi Standards**: ERC4626 (Vault), EIP2535 (Diamond)
- **Upgrade Standards**: EIP1967 (Proxy), UUPS, Transparent Proxy
- **Custom Specifications**: Protocol-specific spec validation

---

## ERC20 Compliance Checker

### Required Interface

```solidity
interface IERC20 {
    // Core functions
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    
    // Events (MUST emit)
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

// Optional metadata interface
interface IERC20Metadata is IERC20 {
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function decimals() external view returns (uint8);
}
```

### ERC20 Compliance Checklist

```markdown
## ERC20 Core Requirements

### Functions
- [ ] totalSupply() returns total token supply
- [ ] balanceOf(address) returns balance of account
- [ ] transfer(to, amount) transfers tokens, returns bool
- [ ] allowance(owner, spender) returns current allowance
- [ ] approve(spender, amount) sets allowance, returns bool
- [ ] transferFrom(from, to, amount) transfers with allowance, returns bool

### Events
- [ ] Transfer(from, to, value) emitted on ALL transfers including mint/burn
- [ ] Transfer with from=0x0 for mints
- [ ] Transfer with to=0x0 for burns
- [ ] Approval(owner, spender, value) emitted on ALL approve calls

### Return Values
- [ ] transfer() returns true on success (not revert)
- [ ] approve() returns true on success
- [ ] transferFrom() returns true on success

### Behavior
- [ ] transfer(0) should succeed (not revert)
- [ ] transferFrom decrements allowance (or infinite approval)
- [ ] Zero address checks on transfer/approve
- [ ] Underflow protection on balances

### Common Violations
- ❌ No return value (USDT-style)
- ❌ Returns false instead of reverting
- ❌ Missing Transfer event on mint/burn
- ❌ Missing Approval event
- ❌ Reverts on zero transfer
- ❌ Non-indexed event parameters
```

### ERC20 Grep Patterns

```bash
# Check for Transfer event (must have indexed from, to)
grep -n "event Transfer" contracts/
grep -n "indexed.*from.*indexed.*to" contracts/

# Check for Approval event
grep -n "event Approval" contracts/

# Check return values
grep -n "function transfer.*returns.*bool" contracts/
grep -n "function approve.*returns.*bool" contracts/

# Check emit statements
grep -n "emit Transfer" contracts/
grep -n "emit Approval" contracts/
```

---

## ERC721 Compliance Checker

### Required Interface

```solidity
interface IERC721 {
    // Events (MUST emit)
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);
    
    // Core functions
    function balanceOf(address owner) external view returns (uint256);
    function ownerOf(uint256 tokenId) external view returns (address);
    function safeTransferFrom(address from, address to, uint256 tokenId, bytes data) external;
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
    function transferFrom(address from, address to, uint256 tokenId) external;
    function approve(address to, uint256 tokenId) external;
    function setApprovalForAll(address operator, bool approved) external;
    function getApproved(uint256 tokenId) external view returns (address);
    function isApprovedForAll(address owner, address operator) external view returns (bool);
}

interface IERC721Receiver {
    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4);
}
```

### ERC721 Compliance Checklist

```markdown
## ERC721 Requirements

### Events
- [ ] Transfer emitted with indexed from, to, tokenId
- [ ] Approval emitted with indexed owner, approved, tokenId
- [ ] ApprovalForAll emitted with indexed owner, operator

### Functions
- [ ] balanceOf reverts for zero address
- [ ] ownerOf reverts for non-existent tokens
- [ ] safeTransferFrom calls onERC721Received on contracts
- [ ] safeTransferFrom reverts if receiver rejects
- [ ] transferFrom clears approval after transfer
- [ ] approve clears on transfer
- [ ] approve reverts if caller is not owner/operator
- [ ] setApprovalForAll allows operator for all tokens

### Safe Transfer Requirements
- [ ] Checks if recipient is contract
- [ ] Calls onERC721Received with correct parameters
- [ ] Reverts if return value != IERC721Receiver.onERC721Received.selector
- [ ] Reverts if recipient is contract that doesn't implement receiver

### Common Violations
- ❌ safeTransferFrom doesn't check receiver
- ❌ Missing indexed on event parameters
- ❌ Approval not cleared on transfer
- ❌ Non-existent token doesn't revert
- ❌ Zero address check missing
```

### ERC721 Extensions

```markdown
## ERC721 Optional Extensions

### ERC721Metadata
- [ ] name() returns collection name
- [ ] symbol() returns collection symbol  
- [ ] tokenURI(tokenId) returns metadata URI

### ERC721Enumerable
- [ ] totalSupply() returns total tokens
- [ ] tokenOfOwnerByIndex(owner, index) returns tokenId
- [ ] tokenByIndex(index) returns tokenId
- [ ] All three functions remain consistent

### Common Metadata Issues
- ❌ tokenURI doesn't revert for non-existent tokens
- ❌ baseURI not properly concatenated
- ❌ tokenURI returns empty string instead of reverting
```

---

## ERC1155 Compliance Checker

### Required Interface

```solidity
interface IERC1155 {
    event TransferSingle(address indexed operator, address indexed from, address indexed to, uint256 id, uint256 value);
    event TransferBatch(address indexed operator, address indexed from, address indexed to, uint256[] ids, uint256[] values);
    event ApprovalForAll(address indexed account, address indexed operator, bool approved);
    event URI(string value, uint256 indexed id);
    
    function balanceOf(address account, uint256 id) external view returns (uint256);
    function balanceOfBatch(address[] calldata accounts, uint256[] calldata ids) external view returns (uint256[] memory);
    function setApprovalForAll(address operator, bool approved) external;
    function isApprovedForAll(address account, address operator) external view returns (bool);
    function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes calldata data) external;
    function safeBatchTransferFrom(address from, address to, uint256[] calldata ids, uint256[] calldata amounts, bytes calldata data) external;
}
```

### ERC1155 Compliance Checklist

```markdown
## ERC1155 Requirements

### Events
- [ ] TransferSingle for single transfers
- [ ] TransferBatch for batch transfers
- [ ] Both events for mint/burn operations
- [ ] ApprovalForAll when operators change

### Safe Transfer
- [ ] Calls onERC1155Received for single transfers
- [ ] Calls onERC1155BatchReceived for batch transfers
- [ ] Reverts if receiver rejects
- [ ] Correct selector verification

### Batch Operations
- [ ] balanceOfBatch accepts arrays
- [ ] safeBatchTransferFrom atomic (all or nothing)
- [ ] Array length validation

### Common Violations
- ❌ Missing receiver check on transfers
- ❌ Non-atomic batch transfers
- ❌ Missing URI event on metadata changes
- ❌ Inconsistent batch behavior
```

---

## ERC4626 Vault Compliance

### Required Interface

```solidity
interface IERC4626 is IERC20 {
    // Asset
    function asset() external view returns (address);
    
    // Deposit/Withdraw
    function deposit(uint256 assets, address receiver) external returns (uint256 shares);
    function mint(uint256 shares, address receiver) external returns (uint256 assets);
    function withdraw(uint256 assets, address receiver, address owner) external returns (uint256 shares);
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets);
    
    // Accounting Views
    function totalAssets() external view returns (uint256);
    function convertToShares(uint256 assets) external view returns (uint256);
    function convertToAssets(uint256 shares) external view returns (uint256);
    function previewDeposit(uint256 assets) external view returns (uint256);
    function previewMint(uint256 shares) external view returns (uint256);
    function previewWithdraw(uint256 assets) external view returns (uint256);
    function previewRedeem(uint256 shares) external view returns (uint256);
    function maxDeposit(address receiver) external view returns (uint256);
    function maxMint(address receiver) external view returns (uint256);
    function maxWithdraw(address owner) external view returns (uint256);
    function maxRedeem(address owner) external view returns (uint256);
    
    // Events
    event Deposit(address indexed sender, address indexed owner, uint256 assets, uint256 shares);
    event Withdraw(address indexed sender, address indexed receiver, address indexed owner, uint256 assets, uint256 shares);
}
```

### ERC4626 Compliance Checklist

```markdown
## ERC4626 Requirements

### Core Invariants
- [ ] convertToShares(convertToAssets(shares)) ≈ shares
- [ ] convertToAssets(convertToShares(assets)) ≈ assets
- [ ] deposit(assets) ≤ previewDeposit(assets) (may get more shares)
- [ ] mint(shares) ≥ previewMint(shares) (may need more assets)
- [ ] withdraw(assets) ≤ previewWithdraw(assets) (may burn fewer shares)
- [ ] redeem(shares) ≥ previewRedeem(shares) (may get more assets)

### Preview Functions
- [ ] previewDeposit MUST NOT revert
- [ ] previewMint MUST NOT revert
- [ ] previewWithdraw MAY revert only if withdraw would revert
- [ ] previewRedeem MAY revert only if redeem would revert
- [ ] Previews inclusive of fees

### Max Functions
- [ ] maxDeposit returns max depositable by receiver
- [ ] maxMint returns max mintable for receiver
- [ ] maxWithdraw returns max withdrawable by owner
- [ ] maxRedeem returns max redeemable by owner
- [ ] Return 0 if operation not possible

### Rounding
- [ ] convertToShares rounds DOWN (favor vault)
- [ ] convertToAssets rounds DOWN (favor vault)
- [ ] previewDeposit rounds DOWN (get fewer shares)
- [ ] previewMint rounds UP (need more assets)
- [ ] previewWithdraw rounds UP (burn more shares)
- [ ] previewRedeem rounds DOWN (get fewer assets)

### Common Violations
- ❌ Rounding direction incorrect
- ❌ Preview functions revert unexpectedly
- ❌ convertTo functions don't round trip
- ❌ Max functions return wrong values
- ❌ Missing or incorrect events
- ❌ Inflation attack vulnerability
```

### ERC4626 Security Issues

```markdown
## Known ERC4626 Vulnerabilities

### Inflation Attack
- [ ] Empty vault vulnerability (first depositor attack)
- [ ] Attacker donates assets before first deposit
- [ ] First real depositor gets fewer shares than expected
- [ ] Mitigation: virtual shares/assets, minimum deposit

### Rounding Exploitation
- [ ] Deposit 0 assets → get shares?
- [ ] Small withdrawals lose value to rounding?
- [ ] Repeated deposit/withdraw drains vault?

### Oracle Manipulation
- [ ] convertTo* uses spot prices?
- [ ] Flashloan manipulation possible?
- [ ] TWAP or time-delay protection?
```

---

## EIP712 Typed Data Signing

### Required Implementation

```solidity
// EIP712 Domain Separator
bytes32 constant DOMAIN_TYPEHASH = keccak256(
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
);

function DOMAIN_SEPARATOR() public view returns (bytes32) {
    return keccak256(abi.encode(
        DOMAIN_TYPEHASH,
        keccak256(bytes(name)),
        keccak256(bytes(version)),
        block.chainid,
        address(this)
    ));
}

// Struct hash
bytes32 constant PERMIT_TYPEHASH = keccak256(
    "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
);

function hashStruct(Permit memory permit) internal pure returns (bytes32) {
    return keccak256(abi.encode(
        PERMIT_TYPEHASH,
        permit.owner,
        permit.spender,
        permit.value,
        permit.nonce,
        permit.deadline
    ));
}
```

### EIP712 Compliance Checklist

```markdown
## EIP712 Requirements

### Domain Separator
- [ ] Includes name (string)
- [ ] Includes version (string)
- [ ] Includes chainId (uint256)
- [ ] Includes verifyingContract (address)
- [ ] Recalculated on chain fork (if chainId changes)

### Type Hashes
- [ ] Correctly formatted type strings
- [ ] Types in alphabetical order for nested structs
- [ ] No trailing spaces or formatting issues

### Signature Verification
- [ ] Uses ecrecover correctly
- [ ] Checks for zero address result
- [ ] Validates signer matches expected
- [ ] Deadline checked before signature verification

### Common Violations
- ❌ DOMAIN_SEPARATOR cached at deploy (chain fork issue)
- ❌ Wrong type string format
- ❌ Missing chain ID check
- ❌ Signature replay across contracts
- ❌ Missing deadline validation
```

---

## EIP2612 Permit

### Required Implementation

```solidity
interface IERC2612 {
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;
    
    function nonces(address owner) external view returns (uint256);
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}
```

### Permit Compliance Checklist

```markdown
## EIP2612 Requirements

### Function Behavior
- [ ] Sets allowance to value for owner→spender
- [ ] Reverts if deadline < block.timestamp
- [ ] Reverts if signature invalid
- [ ] Reverts if recovered signer ≠ owner
- [ ] Increments nonce after use
- [ ] Emits Approval event

### Nonce Management
- [ ] Nonce unique per owner
- [ ] Nonce increments monotonically
- [ ] Cannot reuse nonces
- [ ] No gaps in nonces

### Common Violations
- ❌ Deadline checked after ecrecover
- ❌ Zero address allowed as owner
- ❌ Nonce not incremented
- ❌ Missing Approval event
- ❌ Front-runnable (though inherent to design)
```

---

## EIP1967 Proxy Storage Slots

### Required Slots

```solidity
// Implementation slot
bytes32 constant IMPLEMENTATION_SLOT = 
    bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
// = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc

// Admin slot
bytes32 constant ADMIN_SLOT = 
    bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1);
// = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103

// Beacon slot
bytes32 constant BEACON_SLOT = 
    bytes32(uint256(keccak256("eip1967.proxy.beacon")) - 1);
// = 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50
```

### EIP1967 Compliance Checklist

```markdown
## EIP1967 Requirements

### Storage Slots
- [ ] Implementation at correct slot
- [ ] Admin at correct slot (if used)
- [ ] Beacon at correct slot (if beacon proxy)
- [ ] No collisions with other storage

### Events
- [ ] Upgraded(address indexed implementation)
- [ ] AdminChanged(address previousAdmin, address newAdmin)
- [ ] BeaconUpgraded(address indexed beacon)

### Security
- [ ] Only admin can upgrade
- [ ] Implementation is valid contract
- [ ] Initialization cannot be re-run
- [ ] Storage layout compatible between versions

### Common Violations
- ❌ Wrong storage slot calculation
- ❌ Missing upgrade events
- ❌ Uninitialized implementation
- ❌ Storage collision on upgrade
```

---

## Resources

- [erc-standards.md](resources/erc-standards.md) - Complete ERC reference
- [eip-security.md](resources/eip-security.md) - EIP security considerations

## Workflows

- [compliance-audit.md](workflows/compliance-audit.md) - Compliance audit workflow

---

## Integration with Cyfrin Solodit

```markdown
## Search Queries for Compliance Issues

- "ERC20 compliance" - ERC20 standard violations
- "ERC721 safeTransfer" - NFT transfer issues
- "ERC4626" - Vault standard issues
- "EIP712" - Signature issues
- "permit" - Permit implementation bugs
- "proxy" - Upgrade proxy issues
```
