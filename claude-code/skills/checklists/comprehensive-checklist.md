# Comprehensive Audit Checklist - AI Reference

> **For AI Assistants:** Use this systematic checklist when auditing smart contracts.
> Source: Consolidated from SmartContracts-audit-checklist and industry best practices.

---

## Pre-Audit Scoping

### Code Metrics
```bash
# Count lines of code
cloc */

# Count Solidity files
find . -name '*.sol' | wc -l

# Lines per file
find . -name '*.sol' | xargs wc -l

# SHA256 hashes for integrity
shasum -a 256 contracts/*.sol
```

### Tools to Run First
- [ ] Slither: `slither .`
- [ ] Mythril: `myth analyze contracts/*.sol`
- [ ] Solhint: `solhint 'contracts/**/*.sol'`
- [ ] solidity-metrics (VS Code extension)

---

## Variables Checklist

| ID | Check | SWC |
|----|-------|-----|
| V1 | Can it be `internal` instead of `public`? | - |
| V2 | Can it be `constant`? | - |
| V3 | Can it be `immutable`? | - |
| V4 | Is visibility explicitly set? | SWC-108 |
| V5 | Is purpose documented with NatSpec? | - |
| V6 | Can it be packed with adjacent storage variable? | - |
| V7 | Can it be packed in a struct? | - |
| V8 | Use full 256 bit types unless packing | - |
| V9 | If public array, is there getter for full array? | - |
| V10 | Only use `private` to prevent child access, prefer `internal` | - |

---

## Structs Checklist

| ID | Check |
|----|-------|
| S1 | Is a struct necessary? Can variables be packed raw? |
| S2 | Are fields packed together (if possible)? |
| S3 | Is purpose documented with NatSpec? |

---

## Functions Checklist

| ID | Check | SWC |
|----|-------|-----|
| F1 | Can it be `external` instead of `public`? | - |
| F2 | Should it be `internal`? | - |
| F3 | Should it be `payable`? | - |
| F4 | Can it be combined with similar function? | - |
| F5 | Are all parameters validated (even for trusted callers)? | - |
| F6 | Is checks-effects-interactions pattern followed? | SWC-107 |
| F7 | Check for front-running (especially approve) | SWC-114 |
| F8 | Is insufficient gas griefing possible? | SWC-126 |
| F9 | Are correct modifiers applied (onlyOwner, etc.)? | - |
| F10 | Are return values always assigned? | - |
| F11 | Are precondition invariants tested? | - |
| F12 | Are postcondition invariants tested? | - |
| F13 | Is naming clear and descriptive? | - |
| F14 | If intentionally unsafe, use warning name | - |
| F15 | Are args, returns, side effects documented? | - |
| F16 | Don't assume msg.sender is the operated user | - |
| F17 | Check explicit initialized variable, not owner == 0 | - |
| F18 | Only use `private` to prevent child calls | - |
| F19 | Use `virtual` if child may override | - |

---

## Modifiers Checklist

| ID | Check |
|----|-------|
| M1 | No storage updates (except reentrancy lock)? |
| M2 | Are external calls avoided? |
| M3 | Is purpose documented with NatSpec? |

---

## Code Checklist

| ID | Check | SWC |
|----|-------|-----|
| C1 | Using SafeMath or 0.8+ checked math? | SWC-101 |
| C2 | Are storage slots read multiple times? (cache them) | - |
| C3 | Unbounded loops that can cause DoS? | SWC-128 |
| C4 | Use block.timestamp only for long intervals | SWC-116 |
| C5 | Don't use block.number for elapsed time | SWC-116 |
| C7 | Avoid delegatecall, especially to external | SWC-112 |
| C8 | Don't update array length while iterating | - |
| C9 | Don't use blockhash for randomness | SWC-120 |
| C10 | Signatures protected with nonce + chainid? | SWC-121 |
| C11 | All signatures use EIP-712? | SWC-117, SWC-122 |
| C12 | Don't hash abi.encodePacked with >2 dynamic types | SWC-133 |
| C13 | Careful with assembly, no arbitrary data | SWC-127 |
| C14 | Don't assume specific ETH balance | SWC-132 |
| C15 | Avoid insufficient gas griefing | SWC-126 |
| C16 | Private data isn't private on-chain | SWC-136 |
| C17 | Updating memory struct doesn't update storage | - |
| C18 | Never shadow state variables | SWC-119 |
| C19 | Don't mutate function parameters | - |
| C20 | Is calculating on-the-fly cheaper than storing? | - |
| C21 | Reading from correct contract (master vs clone)? | - |
| C22 | Comparison operators correct (>, <, >=, <=)? | - |
| C23 | Logical operators correct (&&, \|\|, ==, !=)? | - |
| C24 | Multiply before dividing (unless overflow risk) | - |
| C25 | Magic numbers replaced with named constants? | - |
| C26 | Fallback revert causing DoS? | SWC-113 |
| C27 | Use SafeERC20 or check return values | - |
| C28 | Don't use msg.value in a loop | - |
| C29 | Don't use msg.value with recursive delegatecall | - |
| C30 | Don't assume msg.sender is always relevant user | - |
| C31 | Only use assert() for fuzzing/formal verification | SWC-110 |
| C32 | Don't use tx.origin for authorization | SWC-115 |
| C33 | Don't use transfer()/send(), use call() | SWC-134 |
| C34 | Check contract exists before low-level call | - |
| C35 | Use named arguments for many parameters | - |
| C36 | Don't use assembly for CREATE2 | - |
| C37 | Don't use assembly for chainid/code | - |
| C38 | Use `delete` for zeroing variables | - |
| C39 | Comment the "why" | - |
| C40 | Comment unconventional code | - |
| C41 | Comment complex math with examples | - |
| C42 | Comment gas optimizations with estimates | - |
| C43 | Comment avoided optimizations with reasoning | - |
| C44 | Comment unchecked blocks with reasoning | - |
| C45 | Use parentheses for operator precedence | - |
| C46 | No side-effects in comparison expressions | - |
| C47 | Document precision loss direction | - |
| C48 | Document why reentrancy lock is needed | - |
| C49 | Use modulo to bound fuzzer inputs | - |
| C50 | Use ternary for simple branching | - |
| C51 | Consider same-address edge case | - |

---

## External Calls Checklist

| ID | Check | SWC |
|----|-------|-----|
| X1 | Is external call actually needed? | - |
| X2 | Can error cause DoS (balanceOf reverting)? | SWC-113 |
| X3 | Harmful if call reenters current function? | SWC-107 |
| X4 | Harmful if call reenters another function? | SWC-107 |
| X5 | Is result checked and errors handled? | SWC-104 |
| X6 | What if it uses all provided gas? | - |
| X7 | Can massive return data cause OOG? | - |
| X8 | Don't assume success means function exists | - |

---

## Static Calls Checklist

| ID | Check | SWC |
|----|-------|-----|
| S1 | Is external call actually needed? | - |
| S2 | Is it marked as view in interface? | - |
| S3 | Can error cause DoS? | SWC-113 |
| S4 | Can infinite loop cause DoS? | - |

---

## Events Checklist

| ID | Check |
|----|-------|
| E1 | Should any fields be indexed? |
| E2 | Is action creator included as indexed field? |
| E3 | Don't index dynamic types (strings, bytes) |
| E4 | Is emission documented with NatSpec? |
| E5 | Are all affected users/ids indexed? |

---

## Contract Checklist

| ID | Check | SWC |
|----|-------|-----|
| T1 | SPDX license identifier present? | - |
| T2 | Events emitted for all storage mutations? | - |
| T3 | Correct inheritance, simple and linear? | SWC-125 |
| T4 | receive() function if accepting ETH? | - |
| T5 | Invariants about stored state tested? | - |
| T6 | Purpose documented with NatSpec? | - |
| T7 | Use `abstract` if must be inherited? | - |
| T8 | Constructor emits events for non-immutables? | - |
| T9 | Avoid over-inheritance? | - |
| T10 | Use named imports? | - |
| T11 | Group imports by folder/package? | - |
| T12 | @notice and @dev NatSpec comments? | - |

---

## Project Checklist

| ID | Check |
|----|-------|
| P1 | Correct license (GPL if depending on GPL)? |
| P2 | Unit tests for everything? |
| P3 | Fuzz testing? |
| P4 | Symbolic execution where possible? |
| P5 | Slither/Solhint run and findings reviewed? |

---

## DeFi-Specific Checklist

| ID | Check |
|----|-------|
| D1 | Check assumptions about external contracts |
| D2 | Don't mix internal accounting with actual balances |
| D3 | Don't use AMM spot price as oracle |
| D4 | Get price target off-chain or via oracle for AMM trades |
| D5 | Sanity checks to prevent oracle manipulation |
| D6 | Handle rebasing tokens or document unsupported |
| D7 | Handle ERC-777 reentrancy risk |
| D8 | Handle fee-on-transfer tokens or document |
| D9 | Handle tokens with unusual decimals |
| D10 | Don't rely on raw balance for earnings calculation |
| D11 | No arbitrary calls from token approval targets |

---

## Quick Security Checks

### Access Control
- [ ] All admin functions have proper modifiers
- [ ] Ownership transfer is two-step
- [ ] No unprotected initialize functions
- [ ] Pause mechanism exists for emergencies

### Reentrancy
- [ ] CEI pattern followed
- [ ] ReentrancyGuard used where needed
- [ ] External calls are last operation
- [ ] No state reads after external calls

### Math
- [ ] No unchecked blocks with user input
- [ ] Division by zero prevented
- [ ] Rounding favors protocol (not user)
- [ ] Precision loss documented

### Tokens
- [ ] SafeERC20 used for transfers
- [ ] Approval race condition handled
- [ ] Fee-on-transfer considered
- [ ] Zero address checks

### Oracle
- [ ] Staleness check on price feeds
- [ ] Min/max price bounds
- [ ] Multi-oracle fallback
- [ ] Decimal normalization

---

## Audit Report Platforms

| Platform | URL |
|----------|-----|
| Code4rena | https://code4rena.com/reports |
| Sherlock | https://app.sherlock.xyz/audits/contests |
| Consensys | https://consensys.net/diligence/audits |
| OpenZeppelin | https://blog.openzeppelin.com/security-audits |
| Trail of Bits | https://github.com/trailofbits/publications |
| Peckshield | https://peckshield.com/#report |
| Hacken | https://hacken.io/audits |
| Oak Security | https://github.com/oak-security/audit-reports |

---

## Bug Bounty Platforms

| Platform | URL |
|----------|-----|
| Immunefi | https://immunefi.com |
| Code4rena | https://code4rena.com |
| Sherlock | https://app.sherlock.xyz |
| Codehawks | https://www.codehawks.com |
| Hats Finance | https://hats.finance |
| HackenProof | https://hackenproof.com |

---

## SWC Registry Quick Reference

| SWC | Name | Category |
|-----|------|----------|
| SWC-100 | Function Default Visibility | Access Control |
| SWC-101 | Integer Overflow/Underflow | Arithmetic |
| SWC-104 | Unchecked Call Return Value | External Calls |
| SWC-107 | Reentrancy | Reentrancy |
| SWC-108 | State Variable Visibility | Access Control |
| SWC-110 | Assert Violation | Logic |
| SWC-112 | Delegatecall to Untrusted | Access Control |
| SWC-113 | DoS with Failed Call | DoS |
| SWC-114 | Transaction Order Dependence | Front-running |
| SWC-115 | tx.origin Authorization | Access Control |
| SWC-116 | Block Timestamp Dependence | Logic |
| SWC-117 | Signature Malleability | Signature |
| SWC-119 | Shadowing State Variables | Logic |
| SWC-120 | Weak Randomness | Randomness |
| SWC-121 | Missing Signature Replay Protection | Signature |
| SWC-126 | Insufficient Gas Griefing | DoS |
| SWC-128 | DoS With Block Gas Limit | DoS |
| SWC-133 | Hash Collisions | Signature |
| SWC-136 | Unencrypted Private Data | Privacy |
