# Initializer Security Patterns

## Overview

**Frequency**: 4 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 2 | 0 | 0 |

**Common Sources**: Code4rena, ConsenSys

---

## Detection Checklist

- [ ] Check for initializer vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: [H-03]  Wrong implementation of EIP712MetaTransaction

**Source**: Code4rena
**Protocol**: Rolla
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-03-rolla/blob/efe4a3c1af8d77c5dfb5ba110c3507e67a061bdd/quant-protocol/contracts/utils/EIP712MetaTransaction.sol#L102-L114


## Vulnerability details

1. `EIP712MetaTransaction` is a utils contract that intended to be inherited by concrete (actual) contracts, therefore. it's initializer function should not use the `initializer` modifier, instead, it should use `onlyInitializing` modifier. See the implementation of [openzeppelin `EIP712Upgradeable` initializer function](https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/v4.5.1/contracts/utils/cryptography/draft-EIP712Upgradeable.sol#L48-L57).

https://github.com/code-423n4/2022-03-rolla/blob/efe4a3c1af8d77c5dfb5ba110c3507e67a061bdd/quant-protocol/contracts/utils/EIP712MetaTransaction.sol#L102-L114

```solidity
    /// @notice initialize method for EIP712Upgradeable
    /// @dev called once after initial deployment and every upgrade.
    /// @param _name the user readable name of the signing domain for EIP712
    /// @param _version the current major version of the signing domain for EIP712
    function initializeEIP712(string memory _name, string memory _version)
        public
        initializer
    {
        name = _name;
        version = _version;

        __EIP712_init(_name, _version);
    }
```

Otherwise, when the concrete contract's initializer function (with a `initializer` modifier) is calling EIP712MetaTransaction's initializer function, it w

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-03-rolla)

---

### Example 2: [H-04] The Constructor Caveat leads to bricking of Configurator contract.

**Source**: Code4rena
**Protocol**: Lybra Finance
**Impact**: HIGH

**Details**:

In Solidity, code that is inside a constructor or part of a global variable declaration is not part of a deployed contract's runtime bytecode. This code is executed only once, when the contract instance is deployed. As a consequence of this, the code within a logic contract's constructor will never be executed in the context of the proxy's state. This means that any state changes made in the constructor of a logic contract will not be reflected in the proxy's state.
1.  This will lead to governance timelocks contract and the `curvePool` contract contain default values of zero values.
2.  As a result, all the functions that rely on governance will be broken, since the governance address is set to zero address.

### Proof of Concept

```
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {LybraProxy} from "@lybra/Proxy/LybraProxy.sol";
import {LybraProxyAdmin} from "@lybra/Proxy/LybraProxyAdmin.sol";
import {GovernanceTimelock} from "@lybra/governance/GovernanceTimelock.sol";
import {PeUSDMainnet} from "@lybra/token/PeUSDMainnetStableVision.sol";
import {Configurator} from "@lybra/configuration/LybraConfigurator.sol";
import {EUSDMock} from "@mocks/mockEUSD.sol";
import {mockCurve} from "@mocks/mockCurve.sol";
import {mockUSDC} from "@mocks/mockUSDC.sol";

/* remappings used
@lybra=contracts/lybra/
@mocks=cont

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-06-lybra)

---

### Example 3: [M-01] Initialize function in L2GraphToken.sol, BridgeEscrow.sol, L2GraphTokenGateway.sol, L1GraphTokenGateway.sol can be invoked multiple times from the implementation contract

**Source**: Code4rena
**Protocol**: The Graph
**Impact**: MEDIUM

**Details**:

## Lines of code

https://github.com/code-423n4/2022-10-thegraph/blob/309a188f7215fa42c745b136357702400f91b4ff/contracts/l2/gateway/L2GraphTokenGateway.sol#L87
https://github.com/code-423n4/2022-10-thegraph/blob/309a188f7215fa42c745b136357702400f91b4ff/contracts/l2/token/L2GraphToken.sol#L48
https://github.com/code-423n4/2022-10-thegraph/blob/309a188f7215fa42c745b136357702400f91b4ff/contracts/gateway/L1GraphTokenGateway.sol#L99
https://github.com/code-423n4/2022-10-thegraph/blob/309a188f7215fa42c745b136357702400f91b4ff/contracts/gateway/BridgeEscrow.sol#L20


## Vulnerability details

## Impact

initialize function in L2GraphToken.sol, BridgeEscrow.sol, L2GraphTokenGateway.sol, L1GraphTokenGateway.sol 

can be invoked multiple times from the implementation contract.

this means a compromised implementation can reinitialize the contract above and 

become the owner to complete the privilege escalation then drain the user's fund.

Usually in Upgradeable contract, a initialize function is protected by the modifier

```solidity
 initializer
```

to make sure the contract can only be initialized once.

## Proof of Concept
Provide direct links to all referenced code in GitHub. Add screenshots, logs, or any other relevant proof that illustrates the concept.

1. The implementation contract is compromised,

2. The attacker reinitialize the BridgeEscrow contract

```
    function initialize(address _controller) external onlyImpl {
        Managed._initialize(_controller);
    }
```

th

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-thegraph)

---

### Example 4: No Protection of Uninitialized Implementation Contracts From Attacker

**Source**: ConsenSys
**Protocol**: LEEQUID - Staking
**Impact**: MEDIUM

**Details**:

#### Description


In the contracts implement Openzeppelin’s UUPS model, uninitialized implementation contract can be taken over by an attacker with `initialize` function, it’s recommended to invoke the `_disableInitializers` function in the constructor to prevent the implementation contract from being used by the attacker. However all the contracts which implements `OwnablePausableUpgradeable` do not call `_disableInitializers` in the constructors


#### Examples


**contracts/tokens/Rewards.sol:L25**



```
contract Rewards is IRewards, OwnablePausableUpgradeable, ReentrancyGuardUpgradeable {

```
**contracts/pool/Pool.sol:L20**



```
contract Pool is IPool, OwnablePausableUpgradeable, ReentrancyGuardUpgradeable {

```
**contracts/tokens/StakedLyxToken.sol:L46**



```
contract StakedLyxToken is OwnablePausableUpgradeable, LSP4DigitalAssetMetadataInitAbstract, IStakedLyxToken, ReentrancyGuardUpgradeable {

```
etc.


#### Recommendation


Invoke `_disableInitializers` in the constructors of contracts which implement `OwnablePausableUpgradeable` including following:



```
Pool
PoolValidators
FeeEscrow
Reward
StakeLyxTokem
Oracles 
MerkleDistributor

```

**Reference**: [View Original Finding](https://consensys.net/diligence/audits/2023/09/leequid-staking/)

---

## Statistics

- Total findings analyzed: 4
- Examples shown: 4
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

