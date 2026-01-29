# Complete ERC Standards Reference

Comprehensive reference for all major ERC/EIP standards relevant to smart contract security auditing.

---

## Token Standards

### ERC20 - Fungible Token Standard

**Status**: Final | **Category**: Token

```solidity
// Core Interface
interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}
```

**Security Considerations**:
- Allowance race condition (approve from A to B can be front-run)
- Missing return value handling (USDT)
- Integer overflow (pre-0.8.0)
- Fee-on-transfer tokens break assumptions

**Grep Patterns**:
```bash
grep -n "function transfer\|function approve\|function transferFrom" contracts/
grep -n "event Transfer\|event Approval" contracts/
```

---

### ERC721 - Non-Fungible Token Standard

**Status**: Final | **Category**: Token

```solidity
interface IERC721 {
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);
    
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

**Security Considerations**:
- Reentrancy via onERC721Received callback
- Approval not cleared on transfer (spec violation)
- Non-existent token handling
- safeTransferFrom to contracts without receiver interface

**Expected Return Value**:
```solidity
bytes4 constant ERC721_RECEIVED = bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"));
// = 0x150b7a02
```

---

### ERC1155 - Multi Token Standard

**Status**: Final | **Category**: Token

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

interface IERC1155Receiver {
    function onERC1155Received(
        address operator,
        address from,
        uint256 id,
        uint256 value,
        bytes calldata data
    ) external returns (bytes4);
    
    function onERC1155BatchReceived(
        address operator,
        address from,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    ) external returns (bytes4);
}
```

**Security Considerations**:
- Reentrancy via receiver callbacks
- Array length mismatch in batch operations
- Atomicity requirements for batches
- URI event for metadata changes

---

### ERC777 - Advanced Token Standard

**Status**: Final | **Category**: Token

```solidity
interface IERC777 {
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function granularity() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function balanceOf(address owner) external view returns (uint256);
    function send(address recipient, uint256 amount, bytes calldata data) external;
    function burn(uint256 amount, bytes calldata data) external;
    function isOperatorFor(address operator, address tokenHolder) external view returns (bool);
    function authorizeOperator(address operator) external;
    function revokeOperator(address operator) external;
    function defaultOperators() external view returns (address[] memory);
    function operatorSend(address sender, address recipient, uint256 amount, bytes calldata data, bytes calldata operatorData) external;
    function operatorBurn(address account, uint256 amount, bytes calldata data, bytes calldata operatorData) external;
    
    event Sent(address indexed operator, address indexed from, address indexed to, uint256 amount, bytes data, bytes operatorData);
    event Minted(address indexed operator, address indexed to, uint256 amount, bytes data, bytes operatorData);
    event Burned(address indexed operator, address indexed from, uint256 amount, bytes data, bytes operatorData);
    event AuthorizedOperator(address indexed operator, address indexed tokenHolder);
    event RevokedOperator(address indexed operator, address indexed tokenHolder);
}

interface IERC777Sender {
    function tokensToSend(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external;
}

interface IERC777Recipient {
    function tokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external;
}
```

**Security Considerations**:
- **CRITICAL**: Reentrancy via tokensToSend and tokensReceived hooks
- ERC1820 registry registration required
- Hooks called on every transfer
- imBTC hack: $25M lost to reentrancy

---

## Vault & DeFi Standards

### ERC4626 - Tokenized Vault Standard

**Status**: Final | **Category**: DeFi

```solidity
interface IERC4626 is IERC20 {
    function asset() external view returns (address);
    function totalAssets() external view returns (uint256);
    
    function convertToShares(uint256 assets) external view returns (uint256);
    function convertToAssets(uint256 shares) external view returns (uint256);
    
    function maxDeposit(address receiver) external view returns (uint256);
    function previewDeposit(uint256 assets) external view returns (uint256);
    function deposit(uint256 assets, address receiver) external returns (uint256);
    
    function maxMint(address receiver) external view returns (uint256);
    function previewMint(uint256 shares) external view returns (uint256);
    function mint(uint256 shares, address receiver) external returns (uint256);
    
    function maxWithdraw(address owner) external view returns (uint256);
    function previewWithdraw(uint256 assets) external view returns (uint256);
    function withdraw(uint256 assets, address receiver, address owner) external returns (uint256);
    
    function maxRedeem(address owner) external view returns (uint256);
    function previewRedeem(uint256 shares) external view returns (uint256);
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256);
    
    event Deposit(address indexed sender, address indexed owner, uint256 assets, uint256 shares);
    event Withdraw(address indexed sender, address indexed receiver, address indexed owner, uint256 assets, uint256 shares);
}
```

**Rounding Rules**:
| Function | Direction | Reason |
|----------|-----------|--------|
| convertToShares | DOWN | Favor vault |
| convertToAssets | DOWN | Favor vault |
| previewDeposit | DOWN | User gets fewer shares |
| previewMint | UP | User pays more assets |
| previewWithdraw | UP | User burns more shares |
| previewRedeem | DOWN | User gets fewer assets |

**Security Considerations**:
- Inflation attack on empty vault
- Rounding exploitation
- Fee integration complexity
- Preview function revert conditions

---

## Signature Standards

### EIP712 - Typed Data Signing

**Status**: Final | **Category**: Signature

```solidity
// Domain Separator
bytes32 constant DOMAIN_TYPEHASH = keccak256(
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
);

// Example: Permit
bytes32 constant PERMIT_TYPEHASH = keccak256(
    "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
);

function domainSeparator() public view returns (bytes32) {
    return keccak256(abi.encode(
        DOMAIN_TYPEHASH,
        keccak256(bytes(name)),
        keccak256(bytes("1")),
        block.chainid,
        address(this)
    ));
}

function hashTypedData(bytes32 structHash) public view returns (bytes32) {
    return keccak256(abi.encodePacked(
        "\x19\x01",
        domainSeparator(),
        structHash
    ));
}
```

**Security Considerations**:
- Domain separator must include chainId
- Recalculate on chain fork
- Type string formatting exact
- Nested struct ordering

---

### EIP2612 - Permit Extension

**Status**: Final | **Category**: Signature

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

**Security Considerations**:
- Deadline validation before signature check
- Nonce management
- Front-running inherent risk
- Phishing attack surface

---

### EIP1271 - Contract Signature Validation

**Status**: Final | **Category**: Signature

```solidity
interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes memory signature) 
        external view returns (bytes4 magicValue);
}

// Magic value for valid signature
bytes4 constant EIP1271_MAGIC_VALUE = 0x1626ba7e;
```

**Security Considerations**:
- Must return exact magic value
- Hash vs message handling
- Gas limit considerations
- Upgradeable contract implications

---

## Proxy Standards

### EIP1967 - Standard Proxy Storage Slots

**Status**: Final | **Category**: Upgrade

```solidity
// Storage Slots
bytes32 constant IMPLEMENTATION_SLOT = 
    bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
    // 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc

bytes32 constant ADMIN_SLOT = 
    bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1);
    // 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103

bytes32 constant BEACON_SLOT = 
    bytes32(uint256(keccak256("eip1967.proxy.beacon")) - 1);
    // 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50

// Events
event Upgraded(address indexed implementation);
event AdminChanged(address previousAdmin, address newAdmin);
event BeaconUpgraded(address indexed beacon);
```

---

### EIP1822 - UUPS Proxy

**Status**: Draft | **Category**: Upgrade

```solidity
abstract contract UUPSUpgradeable {
    bytes32 constant _IMPLEMENTATION_SLOT = 
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    
    function proxiableUUID() external view returns (bytes32) {
        return _IMPLEMENTATION_SLOT;
    }
    
    function upgradeTo(address newImplementation) external virtual;
    
    function _authorizeUpgrade(address newImplementation) internal virtual;
}
```

**Security Considerations**:
- Implementation must include upgrade logic
- Bricked if upgrade logic removed
- Storage layout must match
- Initializer protection

---

### EIP2535 - Diamond Standard (Multi-Facet Proxy)

**Status**: Final | **Category**: Upgrade

```solidity
interface IDiamond {
    enum FacetCutAction { Add, Replace, Remove }
    
    struct FacetCut {
        address facetAddress;
        FacetCutAction action;
        bytes4[] functionSelectors;
    }
    
    event DiamondCut(FacetCut[] _diamondCut, address _init, bytes _calldata);
    
    function diamondCut(
        FacetCut[] calldata _diamondCut,
        address _init,
        bytes calldata _calldata
    ) external;
}

interface IDiamondLoupe {
    struct Facet {
        address facetAddress;
        bytes4[] functionSelectors;
    }
    
    function facets() external view returns (Facet[] memory);
    function facetFunctionSelectors(address _facet) external view returns (bytes4[] memory);
    function facetAddresses() external view returns (address[] memory);
    function facetAddress(bytes4 _functionSelector) external view returns (address);
}
```

**Security Considerations**:
- Function selector collision
- Storage slot collision across facets
- Initialization complexity
- Upgrade atomicity

---

## Account Abstraction

### ERC4337 - Account Abstraction

**Status**: Draft | **Category**: Account

```solidity
interface IAccount {
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData);
}

struct UserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    uint256 callGasLimit;
    uint256 verificationGasLimit;
    uint256 preVerificationGas;
    uint256 maxFeePerGas;
    uint256 maxPriorityFeePerGas;
    bytes paymasterAndData;
    bytes signature;
}

interface IEntryPoint {
    function handleOps(UserOperation[] calldata ops, address payable beneficiary) external;
    function handleAggregatedOps(UserOpsPerAggregator[] calldata opsPerAggregator, address payable beneficiary) external;
    function simulateValidation(UserOperation calldata userOp) external;
}
```

**Security Considerations**:
- Signature validation
- Gas estimation attacks
- Paymaster abuse
- Nonce management
- Storage access restrictions

---

## Metadata Standards

### ERC721 Metadata

```solidity
interface IERC721Metadata {
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function tokenURI(uint256 tokenId) external view returns (string memory);
}
```

### ERC1155 Metadata

```solidity
interface IERC1155MetadataURI {
    function uri(uint256 id) external view returns (string memory);
}
```

### On-chain vs Off-chain

```solidity
// Off-chain (IPFS)
function tokenURI(uint256 tokenId) external view returns (string memory) {
    return string(abi.encodePacked(baseURI, tokenId.toString()));
}

// On-chain (Base64 encoded JSON)
function tokenURI(uint256 tokenId) external view returns (string memory) {
    string memory json = Base64.encode(bytes(string(abi.encodePacked(
        '{"name":"Token #', tokenId.toString(), '",',
        '"description":"An NFT",',
        '"image":"', imageURI, '"}'
    ))));
    return string(abi.encodePacked("data:application/json;base64,", json));
}
```

---

## Access Control Standards

### ERC173 - Ownership

```solidity
interface IERC173 {
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    
    function owner() external view returns (address);
    function transferOwnership(address newOwner) external;
}
```

### AccessControl (OpenZeppelin Pattern)

```solidity
interface IAccessControl {
    event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole);
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);
    
    function hasRole(bytes32 role, address account) external view returns (bool);
    function getRoleAdmin(bytes32 role) external view returns (bytes32);
    function grantRole(bytes32 role, address account) external;
    function revokeRole(bytes32 role, address account) external;
    function renounceRole(bytes32 role, address account) external;
}
```

---

## Introspection

### ERC165 - Standard Interface Detection

```solidity
interface IERC165 {
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

// Interface IDs
bytes4 constant IERC165_ID = 0x01ffc9a7;
bytes4 constant IERC721_ID = 0x80ac58cd;
bytes4 constant IERC721_METADATA_ID = 0x5b5e139f;
bytes4 constant IERC721_ENUMERABLE_ID = 0x780e9d63;
bytes4 constant IERC1155_ID = 0xd9b67a26;
bytes4 constant IERC1155_METADATA_ID = 0x0e89341c;
```

### ERC1820 - Universal Registry

```solidity
interface IERC1820Registry {
    function setInterfaceImplementer(address account, bytes32 interfaceHash, address implementer) external;
    function getInterfaceImplementer(address account, bytes32 interfaceHash) external view returns (address);
    function setManager(address account, address newManager) external;
    function getManager(address account) external view returns (address);
}

// Registry Address (same on all chains)
address constant ERC1820_REGISTRY = 0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24;
```

---

## Quick Reference Table

| Standard | Category | Security Risk Level |
|----------|----------|---------------------|
| ERC20 | Token | Medium |
| ERC721 | Token | Medium |
| ERC777 | Token | **Critical** |
| ERC1155 | Token | Medium |
| ERC4626 | DeFi | High |
| EIP712 | Signature | Medium |
| EIP2612 | Signature | Medium |
| EIP1271 | Signature | Medium |
| EIP1967 | Proxy | High |
| EIP1822 | Proxy | **Critical** |
| EIP2535 | Proxy | High |
| ERC4337 | Account | High |
