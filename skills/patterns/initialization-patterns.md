# Initialization Security Patterns

## Overview

**Frequency**: 15 occurrences (0.03% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 5 | 10 | 0 | 0 |

**Common Sources**: Code4rena, Sherlock, Spearbit, Codehawks, ConsenSys

---

## Detection Checklist

- [ ] Check for initialization vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Unauthorized access to change acceptanceDelay

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Vulnerability Report

## Severity
**High Risk**

## Context
**File:** DiamondInit.sol  
**Lines:** 35-L40

## Description
The `acceptanceDelay` along with `supportedInterfaces[]` can be set by any user without the need of any Authorization once the init function of `DiamondInit` has been called and set. This is happening since caller checks (`LibDiamond.enforceIsContractOwner();`) are missing for these fields. 

Since `acceptanceDelay` defines the time post which certain action could be executed, setting a very large value could cause a Denial of Service (DOS) to the system (the new owner cannot be set) and setting a very low value could allow changes to be made without consideration time (such as Setting/Renouncing Admin, Disabling whitelisting etc. at `ProposedOwnableFacet.sol`).

## Recommendation
Change the function implementation as shown below:

```solidity
LibDiamond.DiamondStorage storage ds = LibDiamond.diamondStorage();
// Current implementation
- ds.supportedInterfaces[type(IERC165).interfaceId] = true;
- ds.supportedInterfaces[type(IDiamondCut).interfaceId] = true;
- ds.supportedInterfaces[type(IDiamondLoupe).interfaceId] = true;
- ds.supportedInterfaces[type(IProposedOwnable).interfaceId] = true;
- ds.acceptanceDelay = _acceptanceDelay;

if (!s.initialized) {
    ...
    // Proposed implementation
    + ds.supportedInterfaces[type(IERC165).interfaceId] = true;
    + ds.supportedInterfaces[type(IDiamondCut).interfaceId] = true;
    + ds.supportedInterfaces[type

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/ConnextNxtp-Spearbit-Security-Review.pdf)

---

### Example 2: [H-01] Minter.sol#startInflation() can be bypassed.

**Source**: Code4rena
**Protocol**: Backd
**Impact**: HIGH

**Details**:

## Lines of code

https://github.com/code-423n4/2022-05-backd/blob/2a5664d35cde5b036074edef3c1369b984d10010/protocol/contracts/tokenomics/Minter.sol#L104-L108


## Vulnerability details

https://github.com/code-423n4/2022-05-backd/blob/2a5664d35cde5b036074edef3c1369b984d10010/protocol/contracts/tokenomics/Minter.sol#L104-L108

```solidity
    function startInflation() external override onlyGovernance {
        require(lastEvent == 0, "Inflation has already started.");
        lastEvent = block.timestamp;
        lastInflationDecay = block.timestamp;
    }
```

As `lastEvent` and `lastInflationDecay` are not initialized in the `constructor()`, they will remain to the default value of `0`.

However, the permissionless `executeInflationRateUpdate()` method does not check the value of `lastEvent` and `lastInflationDecay` and used them directly.

As a result, if `executeInflationRateUpdate()` is called before `startInflation()`:

1. L190, the check of if `_INFLATION_DECAY_PERIOD` has passed since `lastInflationDecay` will be `true`, and `initialPeriodEnded` will be set to `true` right away;
2. L188, since the `lastEvent` in `totalAvailableToNow += (currentTotalInflation * (block.timestamp - lastEvent));` is `0`, the `totalAvailableToNow` will be set to `totalAvailableToNow ≈ currentTotalInflation * 52 years`, which renders the constrains of `totalAvailableToNow` incorrect and useless.

https://github.com/code-423n4/2022-05-backd/blob/2a5664d35cde5b036074edef3c1369b984d10010/protoc

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-backd)

---

### Example 3: [H-04] Initial pool deposit can be stolen

**Source**: Code4rena
**Protocol**: InsureDAO
**Impact**: HIGH

**Details**:

_Submitted by cmichel, also found by WatchPug_

Note that the `PoolTemplate.initialize` function, called when creating a market with `Factory.createMarket`, calls a vault function to transfer an initial deposit amount (`conditions[1]`) *from* the initial depositor (`_references[4]`):

```solidity
// PoolTemplate
function initialize(
     string calldata _metaData,
     uint256[] calldata _conditions,
     address[] calldata _references
) external override {
     // ...

     if (_conditions[1] > 0) {
          // @audit vault calls asset.transferFrom(_references[4], vault, _conditions[1])
          _depositFrom(_conditions[1], _references[4]);
     }
}

function _depositFrom(uint256 _amount, address _from)
     internal
     returns (uint256 _mintAmount)
{
     require(
          marketStatus == MarketStatus.Trading && paused == false,
          "ERROR: DEPOSIT_DISABLED"
     );
     require(_amount > 0, "ERROR: DEPOSIT_ZERO");

     _mintAmount = worth(_amount);
     // @audit vault calls asset.transferFrom(_from, vault, _amount)
     vault.addValue(_amount, _from, address(this));

     emit Deposit(_from, _amount, _mintAmount);

     //mint iToken
     _mint(_from, _mintAmount);
}
```

The initial depositor needs to first approve the vault contract for the `transferFrom` to succeed.

An attacker can then frontrun the `Factory.createMarket` transaction with their own market creation (it does not have access restrictions) and create a market *with different parameters* but st

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-01-insure)

---

### Example 4: [H-04] The Constructor Caveat leads to bricking of Configurator contract.

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

### Example 5: Initialization functions can be front-run

**Source**: TrailOfBits
**Protocol**: Advanced Blockchain
**Impact**: HIGH

**Details**:

## Type: Timing

## Difficulty: Medium

### Target: Throughout the contracts

### Description
The `CrosslayerPortal` contracts have initializer functions that can be front-run, allowing an attacker to incorrectly initialize the contracts. Due to the use of the `delegatecall` proxy pattern, these contracts cannot be initialized with their own constructors, and they have initializer functions:

```solidity
function initialize() public initializer {
    __Ownable_init();
    __Pausable_init();
    __ReentrancyGuard_init();
}
```

*Figure 1.1: The `initialize` function in `MsgSender:126-130`*

An attacker could front-run these functions and initialize the contracts with malicious values. This issue affects the following system contracts:

- `contracts/core/BridgeAggregator`
- `contracts/core/InvestmentStrategyBase`
- `contracts/core/MosaicHolding`
- `contracts/core/MosaicVault`
- `contracts/core/MosaicVaultConfig`
- `contracts/core/functionCalls/MsgReceiverFactory`
- `contracts/core/functionCalls/MsgSender`
- `contracts/nfts/Summoner`
- `contracts/protocols/aave/AaveInvestmentStrategy`
- `contracts/protocols/balancer/BalancerV1Wrapper`
- `contracts/protocols/balancer/BalancerVaultV2Wrapper`
- `contracts/protocols/bancor/BancorWrapper`
- `contracts/protocols/compound/CompoundInvestmentStrategy`
- `contracts/protocols/curve/CurveWrapper`
- `contracts/protocols/gmx/GmxWrapper`
- `contracts/protocols/sushiswap/SushiswapLiquidityProvider`
- `contracts/protocols/synapse/ISynapseSwap`
-

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/trailofbits/publications/blob/master/reviews/AdvancedBlockchain.pdf)

---

### Example 6: [M-01] `PirexGmx.initiateMigration` can be blocked

**Source**: Code4rena
**Protocol**: Redacted Cartel
**Impact**: MEDIUM

**Details**:

`PirexGmx.initiateMigration` can be blocked so contract will not be able to migrate his funds to another contract using gmx.

### Proof of Concept

PirexGmx was designed with the thought that the current contract can be changed with another during migration.

`PirexGmx.initiateMigration` is the first point in this long process.

<https://github.com/code-423n4/2022-11-redactedcartel/blob/main/src/PirexGmx.sol#L921-L935>

```solidity
    function initiateMigration(address newContract)
        external
        whenPaused
        onlyOwner
    {
        if (newContract == address(0)) revert ZeroAddress();


        // Notify the reward router that the current/old contract is going to perform
        // full account transfer to the specified new contract
        gmxRewardRouterV2.signalTransfer(newContract);


        migratedTo = newContract;


        emit InitiateMigration(newContract);
    }
```

As you can see `gmxRewardRouterV2.signalTransfer(newContract);` is called to start migration.

This is the code of signalTransfer function
<https://arbiscan.io/address/0xA906F338CB21815cBc4Bc87ace9e68c87eF8d8F1#code#F1#L282>

```solidity
    function signalTransfer(address _receiver) external nonReentrant {
        require(IERC20(gmxVester).balanceOf(msg.sender) == 0, "RewardRouter: sender has vested tokens");
        require(IERC20(glpVester).balanceOf(msg.sender) == 0, "RewardRouter: sender has vested tokens");

        _validateReceiver(_receiver);
        pendingReceivers[msg.send

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-11-redactedcartel)

---

### Example 7: [M-10] Wrong DOMAIN_SEPARATOR

**Source**: Code4rena
**Protocol**: Rubicon
**Impact**: MEDIUM

**Details**:

_Submitted by 0x1f8b, also found by rotcivegaf, unforgiven, CertoraInc, eccentricexit, and IllIllI_

The `DOMAIN_SEPARATOR` is wrongly calculated.

### Proof of Concept

In the `initialize` method of the `BathToken` contract, the `name` of the contract is used to calculate the `DOMAIN_SEPARATOR`, however said name is set later, so it will use an incorrect `name`, making it impossible to calculate the `DOMAIN_SEPARATOR` correctly.

```javascript
DOMAIN_SEPARATOR = keccak256(
    abi.encode(
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        ),
        keccak256(bytes(name)),
        keccak256(bytes("1")),
        chainId,
        address(this)
    )
);
name = string(abi.encodePacked(_symbol, (" v1")));
```

Affected source code:

*   [BathToken.sol#L199-L210](https://github.com/code-423n4/2022-05-rubicon/blob/521d50b22b41b1f52ff9a67ea68ed8012c618da9/contracts/rubiconPools/BathToken.sol#L199-L210)

### Recommended Mitigation Steps

*   Set the `name` before using it.

**[bghughes (Rubicon) confirmed](https://github.com/code-423n4/2022-05-rubicon-findings/issues/38)**



***

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-05-rubicon)

---

### Example 8: [M-01] Multiples initializations of `JBTiered721Delegate`

**Source**: Code4rena
**Protocol**: Juicebox
**Impact**: MEDIUM

**Details**:

The `initialize` method of the `JBTiered721Delegate` contract has as a flag that the `_store` argument is different from `address(0)`, however, it can be initialized by anyone with this value to allow the project to continue with its usual initialization, the attacker could have interfered and modified the corresponding values to carry out an attack.

### Proof of Concept

Looking at the method below, we highlight in green the parts that need to be initialized to prevent a call to `store=address(0)` from failing.

```diff
  function initialize(
    uint256 _projectId,
    IJBDirectory _directory,
    string memory _name,
    string memory _symbol,
    IJBFundingCycleStore _fundingCycleStore,
    string memory _baseUri,
    IJBTokenUriResolver _tokenUriResolver,
    string memory _contractUri,
    JB721PricingParams memory _pricing,
    IJBTiered721DelegateStore _store,
    JBTiered721Flags memory _flags
  ) public override {
    // Make the original un-initializable.
    require(address(this) != codeOrigin);
    // Stop re-initialization.
    require(address(store) == address(0));

    // Initialize the sub class.
    JB721Delegate._initialize(_projectId, _directory, _name, _symbol);

    fundingCycleStore = _fundingCycleStore;
    store = _store;
    pricingCurrency = _pricing.currency;
    pricingDecimals = _pricing.decimals;
    prices = _pricing.prices;

    // Store the base URI if provided.
+   if (bytes(_baseUri).length != 0) _store.recordSetBaseUri(_baseUri);

    // 

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-juicebox)

---

### Example 9: No Protection of Uninitialized Implementation Contracts From Attacker

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

### Example 10: M-13: BondBaseSDA.setDefaults doesn't validate inputs

**Source**: Sherlock
**Protocol**: Bond Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-bond-judging/issues/11 

## Found by 
rvierdiiev

## Summary
BondBaseSDA.setDefaults doesn't validate inputs which can lead to initializing new markets incorrectly
## Vulnerability Detail
https://github.com/sherlock-audit/2022-11-bond/blob/main/src/bases/BondBaseSDA.sol#L348-L356
```solidity
    function setDefaults(uint32[6] memory defaults_) external override requiresAuth {
        // Restricted to authorized addresses
        defaultTuneInterval = defaults_[0];
        defaultTuneAdjustment = defaults_[1];
        minDebtDecayInterval = defaults_[2];
        minDepositInterval = defaults_[3];
        minMarketDuration = defaults_[4];
        minDebtBuffer = defaults_[5];
    }
```

Function BondBaseSDA.setDefaults doesn't do any checkings, as you can see. Because of that it's possible to provide values that will break market functionality.

For example you can set `minDepositInterval` to be bigger than `minMarketDuration` and it will be [not possible](https://github.com/sherlock-audit/2022-11-bond/blob/main/src/bases/BondBaseSDA.sol#L174-L178) to create new market.

Or you can provide `minDebtBuffer` to be 100% ot 0% that will break logic of market closing.
## Impact
Can't create new market or market logic will be not working as designed.
## Code Snippet
Provided above
## Tool used

Manual Review

## Recommendation
Add input validation.

## Discussion

**Evert0x**

Message from sponsor

----

Agree. We added the following v

*[Content truncated...]*

---

### Example 11: M-2: Loan is rollable by default

**Source**: Sherlock
**Protocol**: Cooler
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-01-cooler-judging/issues/265 

## Found by 
hansfriese, Nyx, enckrish, wagmi, yixxas, HollaDieWaldfee, HonorLt, Tricko, Zarf, libratus, simon135, usmannk, Trumpero

## Summary
Making the loan rollable by default gives an unfair early advantage to the borrowers.

## Vulnerability Detail
When clearing a new loan, the flag of ```rollable``` is set to true by default:
```solidity
    loans.push(
        Loan(req, req.amount + interest, collat, expiration, true, msg.sender)
    );
```
This means a borrower can extend the loan anytime before the expiry:
```solidity
    function roll (uint256 loanID) external {
        Loan storage loan = loans[loanID];
        Request memory req = loan.request;

        if (block.timestamp > loan.expiry) 
            revert Default();

        if (!loan.rollable)
            revert NotRollable();
```
If the lenders do not intend to allow rollable loans, they should separately toggle the status to prevent that:
```solidity
    function toggleRoll(uint256 loanID) external returns (bool) {
        ...
        loan.rollable = !loan.rollable;
        ...
    }
```

I believe it gives an unfair advantage to the borrower because they can re-roll the loan before the lender's transaction forbids this action.

## Impact
Lenders who do not want the loans to be used more than once, have to bundle their transactions. Otherwise, it is possible that someone might roll their loan, especially if the capital requirement

*[Content truncated...]*

---

### Example 12: An Uninitialized Variable In The `MarketConfiguration::update` Function Causes The `PrepMarket::getIndexPrice` Function To Revert

**Source**: Codehawks
**Protocol**: Zaros
**Impact**: MEDIUM

**Details**:

## Summary:

The `update` function within the `MarketConfiguration` library fails to update the `priceFeedHeartbeatSeconds` variable, which is essential for the `getIndexPrice` function to operate correctly. This oversight causes the `getIndexPrice` function to always revert due to an uninitialized heartbeat check.

## Vulnerability Detail:

In the `MarketConfiguration` library, the `update` function is designed to update various market configuration parameters. However, it neglects to update the `priceFeedHeartbeatSeconds` variable. Consequently, this variable remains uninitialized, defaulting to zero.

The `getIndexPrice` function relies on the `priceFeedHeartbeatSeconds` variable to validate the timeliness of the price feed data from Chainlink oracles. When it checks `if (block.timestamp - updatedAt > priceFeedHeartbeatSeconds)`, the comparison always results in `true` (since `priceFeedHeartbeatSeconds` is zero), causing the function to revert every time it is called.

## Impact:

This vulnerability significantly impacts the functionality of the protocol by making the price checking mechanism always revert. As a result, it effectively halts the correct operation of any process relying on the `getIndexPrice` function. Specifically, it renders the entire price validation mechanism inoperative, potentially disrupting market operations.

These are the list of functions that got affected by this vulnerability includes:

1. `PerpMarket::getIndexPrice`
2. `TradingAccountBranch::g

*[Content truncated...]*

---

### Example 13: [M-10] Holographable tokens can be reinitialized

**Source**: Code4rena
**Protocol**: Holograph
**Impact**: MEDIUM

**Details**:

When new holographable tokens are created, they typically set a state variable that holds the address of the holograph contract. When creation is done through the `HolographFactory`, the holograph contract is [passed in as a parameter](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/HolographFactory.sol#L252) to the holographable contract's initializer function. Under normal circumstances, this would ensure that the hologrpahable asset stores a trusted holograph contract address in its `_holographSlot`.

However, the initializer is vulnerable to reentrancy and the `_holographSlot` can be set to an untrusted contract address. This occurs because before the initialization is complete, the Holographer makes a [delegate call](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/enforcer/Holographer.sol#L162-L164) to a corresponding enforcer contract. From here, the enforcer contract makes an [optional call](https://github.com/code-423n4/2022-10-holograph/blob/f8c2eae866280a1acfdc8a8352401ed031be1373/contracts/enforcer/HolographERC20.sol#L241) to the source contract in an attempt to intialize it. This call can be used to reenter into the Holographer contract's initialize function before the first one has been completed and overwrite key variables such as the `_adminslot`, the `_holographSlot` and the `_sourceContractSlot`.

One way in which this becomes problematic is because

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2022-10-holograph)

---

### Example 14: Add missing input validation on constructor/initializer/setters

**Source**: Spearbit
**Protocol**: Liquid Collective
**Impact**: MEDIUM

**Details**:

## Severity: Medium Risk

## Description: Allowlist.1.sol

- `initAllowlistV1` should require the `_admin` parameter to be not equal to `address(0)`. This check is not needed if the issue with `LibOwnable._setAdmin` allows setting `address(0)` as the admin of the contract is implemented directly at `LibOwnable._setAdmin` level.
- `allow` should check that `_accounts[i]` is not equal to `address(0)`.

## Firewall.sol

- Constructor should check that: `governor_ != address(0)`, `executor_ != address(0)`, `destination_ != address(0)`.
- `setGovernor` should check that `newGovernor` is not equal to `address(0)`.
- `setExecutor` should check that `newExecutor` is not equal to `address(0)`.

## OperatorsRegistry.1.sol

- `initOperatorsRegistryV1` should require the `_admin` parameter to be not equal to `address(0)`. This check is not needed if the issue with `LibOwnable._setAdmin` allows setting `address(0)` as the admin of the contract is implemented directly at `LibOwnable._setAdmin` level.
- `addOperator` should check: `_name` is not an empty string, `_operator` is not equal to `address(0)`, and `_feeRecipient` is not equal to `address(0)`.
- `setOperatorAddress` should check that `_newOperatorAddress` is not equal to `address(0)`.
- `setOperatorFeeRecipientAddress` should check that `_newOperatorFeeRecipientAddress` is not equal to `address(0)`.
- `setOperatorName` should check that `_newName` is not an empty string.

## Oracle.1.sol

- `initOracleV1` should require the `_admin

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LiquidCollective-Spearbit-Security-Review.pdf)

---

### Example 15: M-4: WithdrawPeriphery uses incorrect value for MAX_BPS which will allow much higher slippage than intended

**Source**: Sherlock
**Protocol**: Rage Trade
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-10-rage-trade-judging/issues/39 

## Found by 
0x52

## Summary

WithdrawPeriphery accidentally uses an incorrect value for MAX_BPS which will allow for much higher slippage than intended. 

## Vulnerability Detail

    uint256 internal constant MAX_BPS = 1000;

BPS is typically 10,000 and using 1000 is inconsistent with the rest of the ecosystem contracts and tests. The result is that slippage values will be 10x higher than intended.

## Impact

Unexpected slippage resulting in loss of user funds, likely due to MEV

## Code Snippet

https://github.com/sherlock-audit/2022-10-rage-trade/blob/main/dn-gmx-vaults/contracts/periphery/WithdrawPeriphery.sol#L47

## Tool used

Manual Review

## Recommendation

Correct MAX_BPS:

    -   uint256 internal constant MAX_BPS = 1000;
    +   uint256 internal constant MAX_BPS = 10_000;

---

## Statistics

- Total findings analyzed: 15
- Examples shown: 15
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29
