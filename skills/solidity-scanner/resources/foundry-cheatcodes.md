---
id: foundry-cheatcodes
title: Foundry Cheatcodes — Complete Reference for Security Auditors
category: solidity-scanner
difficulty: intermediate
triggers:
  - foundry cheatcodes
  - forge cheatcodes
  - vm.prank
  - vm.warp
  - vm.deal
  - vm.store
  - forge-std API
related_skills:
  - solidity-scanner/SKILL.md
  - solidity-scanner/resources/foundry-testing.md
  - solidity-scanner/resources/foundry-security.md
tags:
  - foundry
  - cheatcodes
  - forge-std
  - testing
last_updated: 2026-02-26
description: >-
  Complete Foundry cheatcode reference organized for security auditors.
  150+ cheatcodes covering state manipulation, caller context, time/block
  control, expectations, cryptography, storage inspection, gas metering,
  and the full forge-std API (StdAssertions, StdCheats, StdStorage,
  StdUtils, StdInvariant, StdError). Sourced from claude-plugins foundry-solidity.
---

# Foundry Cheatcodes — Complete Reference

> **For Auditors**: These cheatcodes are the tools you use to construct exploit PoCs, manipulate protocol state, impersonate accounts, time-travel, and verify security properties.

---

## State Manipulation

```solidity
// ETH balance
vm.deal(address, uint256);

// ERC20 balance (from StdCheats)
deal(address token, address to, uint256 amount);
deal(address token, address to, uint256 amount, bool adjustTotalSupply);

// ERC721 / ERC1155
dealERC721(address token, address to, uint256 tokenId);
dealERC1155(address token, address to, uint256 id, uint256 amount);

// Code at address (inject bytecode)
vm.etch(address, bytes memory code);

// Direct storage read/write (critical for PoC construction)
vm.store(address, bytes32 slot, bytes32 value);
bytes32 value = vm.load(address, bytes32 slot);

// Copy storage between addresses
vm.copyStorage(address from, address to);

// Nonce
vm.setNonce(address, uint64 nonce);
vm.resetNonce(address);
uint64 nonce = vm.getNonce(address);

// Destroy account (post-Dencun selfdestruct testing)
destroyAccount(address target, address beneficiary);
```

---

## Caller Context (Impersonation)

```solidity
// Single call as sender
vm.prank(address sender);
vm.prank(address sender, address origin); // Also sets tx.origin

// Multiple calls
vm.startPrank(address sender);
vm.startPrank(address sender, address origin);
// ... calls ...
vm.stopPrank();

// Prank with ETH (from StdCheats)
hoax(address sender);
hoax(address sender, uint256 give);
hoax(address sender, address origin);

// Multiple calls with ETH
startHoax(address sender);
startHoax(address sender, uint256 give);
// ... calls ...
vm.stopPrank();
```

---

## Time & Block

```solidity
vm.warp(uint256 timestamp);          // block.timestamp
vm.roll(uint256 blockNumber);        // block.number
vm.fee(uint256 gasPrice);            // tx.gasprice
vm.difficulty(uint256 difficulty);   // block.difficulty
vm.coinbase(address miner);          // block.coinbase
vm.chainId(uint256 chainId);        // block.chainid
vm.prevrandao(bytes32 prevrandao);  // block.prevrandao

// StdCheats helpers
skip(uint256 seconds);   // Move timestamp forward
rewind(uint256 seconds); // Move timestamp backward

// Examples
skip(1 days);
skip(1 hours);
rewind(30 minutes);
```

---

## Expectations (Assertions on Behavior)

### Revert Expectations

```solidity
vm.expectRevert();
vm.expectRevert(bytes memory message);
vm.expectRevert(bytes4 selector);
vm.expectPartialRevert(bytes4 selector);
```

### Event Expectations

```solidity
vm.expectEmit(bool topic1, bool topic2, bool topic3, bool data);
vm.expectEmit(bool topic1, bool topic2, bool topic3, bool data, address emitter);
```

### Call Expectations

```solidity
vm.expectCall(address target, bytes memory data);
vm.expectCall(address target, uint256 value, bytes memory data);
vm.expectCall(address target, bytes memory data, uint64 count);
```

---

## Snapshots (State Isolation)

```solidity
uint256 snapshot = vm.snapshot();
vm.revertTo(snapshot);
vm.revertToAndDelete(snapshot);
```

---

## Environment Variables

```solidity
string memory value = vm.envString("KEY");
uint256 value = vm.envUint("KEY");
address value = vm.envAddress("KEY");
bool value = vm.envBool("KEY");
bytes32 value = vm.envBytes32("KEY");

// With default
uint256 value = vm.envOr("KEY", uint256(100));

// Check existence
bool exists = vm.envExists("KEY");
```

---

## Cryptography

```solidity
// Sign message
(uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
(bytes32 r, bytes32 vs) = vm.signCompact(privateKey, digest);

// Get address from private key
address addr = vm.addr(privateKey);

// Derive key from mnemonic
uint256 key = vm.deriveKey(mnemonic, index);
uint256 key = vm.deriveKey(mnemonic, path, index);

// Create wallet
Vm.Wallet memory wallet = vm.createWallet("label");
Vm.Wallet memory wallet = vm.createWallet(privateKey);
```

---

## Labels & Debugging

```solidity
// Address labels (appear in traces)
vm.label(address, "name");
string memory name = vm.getLabel(address);

// Breakpoints for interactive debugger
vm.breakpoint();
vm.breakpoint("name");

// Console logging
console.log("value:", value);
console.log("address:", addr);
```

---

## Gas Metering

```solidity
vm.pauseGasMetering();
// ... expensive setup operations ...
vm.resumeGasMetering();

// Last call gas data
Vm.Gas memory gas = vm.lastCallGas();

// Section snapshots
vm.startSnapshotGas("operation");
// ... code to profile ...
uint256 gasUsed = vm.stopSnapshotGas();
```

---

## File I/O

```solidity
string memory content = vm.readFile("path/to/file");
vm.writeFile("path/to/file", "content");
bool exists = vm.exists("path/to/file");
vm.removeFile("path/to/file");
```

---

## Address Creation (StdCheats)

```solidity
// Create labeled address
address alice = makeAddr("alice");

// Create address with private key
(address bob, uint256 bobKey) = makeAddrAndKey("bob");

// Create account struct
Account memory account = makeAccount("charlie");
// account.addr, account.key
```

---

## Fuzz Assumptions (StdCheats)

```solidity
// Address type checks
assumeNotZeroAddress(address addr);
assumeNotPrecompile(address addr);
assumeNotPrecompile(address addr, uint256 chainId);
assumeNotForgeAddress(address addr);
assumePayable(address addr);
assumeNotPayable(address addr);

// Token blacklists (USDC/USDT aware)
assumeNotBlacklisted(address token, address addr);

// Combined checks
assumeAddressIsNot(address addr, AddressType t);
assumeAddressIsNot(address addr, AddressType t1, AddressType t2);

// Private key bounding
uint256 pk = boundPrivateKey(rawPk); // Constrains to valid secp256k1 range
```

---

## StdStorage — Dynamic Slot Discovery

Find and manipulate storage slots without knowing the layout:

```solidity
using stdstore for StdStorage;

// Find slot for a simple variable
uint256 slot = stdstore
    .target(address(token))
    .sig("totalSupply()")
    .find();

// Find slot for mapping value
uint256 slot = stdstore
    .target(address(token))
    .sig("balanceOf(address)")
    .with_key(alice)
    .find();

// Find slot for nested mapping
uint256 slot = stdstore
    .target(address(token))
    .sig("allowance(address,address)")
    .with_key(alice)
    .with_key(bob)
    .find();

// Write directly to storage slot
stdstore
    .target(address(token))
    .sig("balanceOf(address)")
    .with_key(alice)
    .checked_write(1000e18);
```

---

## StdInvariant — Targeting API

```solidity
// Target specific contracts for invariant fuzzing
targetContract(address);
excludeContract(address);

// Target specific senders
targetSender(address);
excludeSender(address);

// Target specific function selectors
targetSelector(FuzzSelector memory sel);

// Target artifacts (for complex factory patterns)
targetArtifact(string memory artifactPath);

// Query targets
address[] memory targets = targetContracts();
address[] memory senders = targetSenders();
```

---

## StdError — Revert Selectors

Named selectors for common Solidity errors:

```solidity
stdError.assertionError     // assert() failure
stdError.arithmeticError    // overflow/underflow
stdError.divisionError      // division by zero
stdError.enumCastError      // invalid enum conversion
stdError.encodeStorageError  // encoding error
stdError.popEmptyArrayError // pop on empty array
stdError.indexOOBError      // array out of bounds
stdError.memOverflowError   // memory overflow
stdError.zeroVarError       // zero-initialized function pointer

// Usage
vm.expectRevert(stdError.arithmeticError);
vault.withdraw(type(uint256).max);
```

---

## StdUtils

```solidity
// Bound value to range (PREFERRED over vm.assume)
uint256 bounded = bound(value, min, max);

// Compute CREATE/CREATE2 addresses
address predicted = computeCreateAddress(deployer, nonce);
address predicted = computeCreate2Address(salt, initCodeHash, deployer);

// Hash init code
bytes32 hash = hashInitCode(type(MyContract).creationCode, abi.encode(arg1));

// Get token balances via Multicall3
uint256[] memory balances = getTokenBalances(token, addresses);
```

---

## Code Deployment Helpers

```solidity
// Deploy from artifacts
address deployed = deployCode("ContractName.sol");
address deployed = deployCode("ContractName.sol:ContractName");
address deployed = deployCode("ContractName.sol", constructorArgs);

// Deploy to specific address
deployCodeTo("ContractName.sol", targetAddress);
deployCodeTo("ContractName.sol", constructorArgs, targetAddress);
```

---

## Constants

```solidity
// Well-known addresses
address CREATE2_FACTORY  = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
address MULTICALL3       = 0xcA11bde05977b3631167028862bE2a173976CA11;
address CONSOLE          = 0x000000000000000000636F6e736F6c652e6c6f67;
address DEFAULT_SENDER   = 0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38;
address DEFAULT_TEST     = 0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f;
address HEVM_ADDRESS     = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D;
uint256 UINT256_MAX      = type(uint256).max;
```

---

## Anvil-Specific Cheatcodes (for PoC Testing)

When using Anvil as a local testnet for exploit PoCs:

```bash
# Auto-impersonate any address
anvil --auto-impersonate

# Manual mining (MEV/ordering simulation)
anvil --no-mining
cast rpc evm_mine  # Mine manually

# Mine multiple blocks at once
cast rpc anvil_mine 10

# Set exact next block timestamp
cast rpc evm_setNextBlockTimestamp <timestamp>

# State dump/load (persist exploit environment)
anvil --dump-state state.json
anvil --load-state state.json

# Fork at specific block
anvil --fork-url $RPC_URL --fork-block-number 18000000

# Hardfork selection
anvil --hardfork cancun
```

---

## Cast — On-Chain Investigation

```bash
# Decode unknown function selector
cast 4byte 0xa9059cbb  # → transfer(address,uint256)

# Decode full calldata
cast 4byte-decode <calldata>

# Read storage slot
cast storage $CONTRACT 0

# Compute mapping slot
cast index address $KEY $SLOT

# Query events
cast logs --from-block 18000000 --to-block 18000100 --address $CONTRACT

# Debug on-chain transaction (opcode-level replay)
cast run --debug $TX_HASH

# Sign message for testing
cast wallet sign "message" --private-key $PK

# Compute CREATE/CREATE2 address
cast compute-address $DEPLOYER --nonce 5
cast create2 --starts-with 0x1234
```

---

## Chisel — Interactive Solidity REPL

```bash
# Fork REPL for live investigation
chisel --fork-url $RPC_URL --fork-block-number 18000000

# Inside chisel:
# - Define interfaces, call contracts, test math
# - !export to save session as script
# - !source to inspect generated wrapper
```

---

## Related Files

- [Foundry Security Testing](foundry-security.md) — Vulnerability PoCs
- [Foundry Testing Guide](foundry-testing.md) — Fuzz, invariant, fork patterns
- [Gas & Security](gas-security.md) — Gas optimization implications
- [Foundry CI/CD](foundry-ci-cd.md) — Automated testing pipelines

---

*Source: claude-plugins foundry-solidity testing.md, forge-std-api.md, anvil-advanced.md, cast-advanced.md, chisel.md (February 2026)*
