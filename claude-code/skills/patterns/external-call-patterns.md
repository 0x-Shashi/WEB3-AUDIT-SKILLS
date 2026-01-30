# External Call Security Patterns

## Overview

**Frequency**: 8 occurrences (0.02% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 5 | 3 | 0 | 0 |

**Common Sources**: Spearbit, Sherlock, Halborn, Code4rena

---

## Detection Checklist

- [ ] Check for external call vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: Too generic calls in GenericBridgeFacet allow stealing of tokens

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: HIGH

**Details**:

## Security Report

## Severity
**High Risk**

## Context
- `GenericBridgeFacet.sol#L69-L120`
- `LibSwap.sol#L30-L68`

## Description
With the contract `GenericBridgeFacet`, the functions `swapAndStartBridgeTokensGeneric()` (via `LibSwap.swap()`) and `_startBridge()` allow arbitrary function calls, which enable anyone to call `transferFrom()` and steal tokens from users who have provided a large allowance to the LiFi protocol. This vulnerability has been exploited in the past.

### Additional Risks
- Ability to call the LiFi Diamond itself via functions that dont have `nonReentrant`.
- Potential cancellation of transfers for other users.
- Calling functions protected by checks on `this`, such as `completeBridgeTokensViaStargate`.

```solidity
contract GenericBridgeFacet is ILiFi, ReentrancyGuard {
    function swapAndStartBridgeTokensGeneric(
        ...
        LibSwap.swap(_lifiData.transactionId, _swapData[i]);
        ...
    )
    
    function _startBridge(BridgeData memory _bridgeData) internal {
        ...
        (bool success, bytes memory res) = _bridgeData.callTo.call{ value: value }(_bridgeData.callData);
        ...
    }
}

library LibSwap {
    function swap(bytes32 transactionId, SwapData calldata _swapData) internal {
        ...
        (bool success, bytes memory res) = _swapData.callTo.call{ value: nativeValue }(_swapData.callData);
        ...
    }
}
```

## Recommendation
Whitelist the external call addresses and function signatures for both the dece

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 2: LACK OF EXTERNAL CALLS VALIDATION

**Source**: Halborn
**Protocol**: Account Abstraction Schnorr Signatures SDK
**Impact**: HIGH

**Details**:

##### Description

Non-validated external calls occur when a function invokes an external contract without verifying the return value or handling potential errors.

Several external calls were detected without proper validation.

### Impact

This can lead to reentrancy attacks or unexpected side effects if the external call fails or returns an unexpected result, directly causing a potential impact in the availability or integrity of the environment.

##### Proof of Concept

Listed below, there are some examples of unvalidated calls that may fail or cause an unconsistent or unexpected behavior of the application execution flow.

* `examples/account-address/account_address.ts`

```
async function getAddressAlchemyAASDK(combinedAddresses: Address[], salt: string) {
  const rpcUrl = process.env.ALCHEMY_RPC_URL
  const transport = http(rpcUrl)
  const multiSigSmartAccount = await createMultiSigSmartAccount({
    transport,
    chain: CHAIN,
    combinedAddress: combinedAddresses,
    salt: saltToHex(salt),
    entryPoint: getEntryPoint(CHAIN),
  })

  return multiSigSmartAccount.address
}


```

* `src/helpers/create2.ts`

```
export async function getAccountImplementationAddress(factoryAddress: string, ethersSignerOrProvider: Signer | Provider): Promise<string> {
  const smartAccountFactory = new ethers.Contract(factoryAddress, MultiSigSmartAccountFactory_abi, ethersSignerOrProvider)
  const accountImplementation = await smartAccountFactory.accountImplementation()
  return accoun

*[Content truncated...]*

**Reference**: [View Original Finding](https://www.halborn.com/audits/influx-technologies/account-abstraction-schnorr-signatures-sdk)

---

### Example 3: Bridge with Axelar can be stolen with malicious external call

**Source**: Spearbit
**Protocol**: LI.FI
**Impact**: HIGH

**Details**:

## Severity: High Risk

## Context
- `Executor.sol#L272-L288`
- `Executor.sol#L323-L333`
- `Executor.sol#L269-L288`

## Description
The Executor contract allows users to build an arbitrary payload external call to any address except `address(erc20Proxy)`. `erc20Proxy` is not the only dangerous address to call. By building a malicious external call to the Axelar gateway, exploiters can steal users funds.

The Executor performs swaps at the destination chain. By setting the receiver address to the Executor contract at the destination chain, Li-Fi can help users to get the best price. The Executor inherits `IAxelarExecutable`. The `execute` and `executeWithToken` functions validate the payload and execute the external call.

### IAxelarExecutable.sol#L27-L40
```solidity
function executeWithToken(
    bytes32 commandId,
    string calldata sourceChain,
    string calldata sourceAddress,
    bytes calldata payload,
    string calldata tokenSymbol,
    uint256 amount
) external {
    bytes32 payloadHash = keccak256(payload);
    if (!gateway.validateContractCallAndMint(commandId, sourceChain, sourceAddress, payloadHash, tokenSymbol, amount)) 
        revert NotApprovedByGateway();
    _executeWithToken(sourceChain, sourceAddress, payload, tokenSymbol, amount);
}
```

The nuance lies in the Axelar gateway `AxelarGateway.sol#L133-L148`. Once the receiver calls `validateContractCallAndMint` with a valid payload, the gateway mints the tokens to the receiver and marks it as executed. I

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/LIFI-Spearbit-Security-Review.pdf)

---

### Example 4: Malicious call data can steal unclaimed tokens in the Executor contract

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Vulnerability Report

## Severity: High Risk

### Context
`Executor.sol#L211`

### Description
Users can provide a destination contract `args.to` and arbitrary data `_args.callData` when doing a cross-chain transfer. The protocol will provide the allowance to the callee contract and triggers the function call through `ExcessivelySafeCall.excessivelySafeCall`.

```solidity
contract Executor is IExecutor {
    function execute(ExecutorArgs memory _args) external payable override onlyConnext returns (bool, bytes memory) {
        ...
        SafeERC20.safeIncreaseAllowance(IERC20(_args.assetId), _args.to, _args.amount);
        ...
        // Try to execute the callData
        // the low level call will return `false` if its execution reverts
        (success, returnData) = ExcessivelySafeCall.excessivelySafeCall(
            _args.to,
            gas,
            isNative ? _args.amount : 0,
            MAX_COPY,
            _args.callData
        );
        ...
    }
}
```

Since there arent restrictions on the destination contract and calldata, exploiters can steal the tokens from the executor.

**Note:** The executor does have excess tokens, see: Kovan executor.

**Note:** See issue "Tokens can get stuck in Executor contract."

Tokens can be stolen by granting an allowance. Setting 
```solidity
calldata = abi.encodeWithSelector(ERC20.approve.selector, exploiter, type(uint256).max);
args.to = tokenAddress;
```
allows the exploiter to get an infinite allowance of any toke

*[Content truncated...]*

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 5: Add checks to xcall()

**Source**: Spearbit
**Protocol**: Connext
**Impact**: HIGH

**Details**:

## Security Vulnerability Report

**Severity**: High Risk  
**Context**: 
- BridgeFacet.sol#L240-L339
- BridgeFacet.sol#L400-L419
- Executor.sol#L142-L280

**Description**:  
The function `xcall()` does some sanity checks; nevertheless, more checks should be added to prevent issues later on in the use of the protocol. 

- If `args.recovery == 0`, then `sendToRecovery()` will send funds to the 0 address, effectively losing them.
- If `params.agent == 0`, then `forceReceiveLocal` cant be used, and funds might be locked forever.
- The `args.params.destinationDomain` should never be `s.domain`, although this is also implicitly checked via `_mustHaveRemote()` assuming a correct configuration.
- If `args.params.slippageTol` is set to something greater than `s.LIQUIDITY_FEE_DENOMINATOR`, then funds can be locked as `xcall()` allows for the user to provide the local asset, avoiding any swap while `_handleExecuteLiquidity()` in `execute()` may attempt to perform a swap on the destination chain.

```solidity
function xcall(XCallArgs calldata _args) external payable nonReentrant whenNotPaused returns (bytes32) {
    // Sanity checks.
    ...
}
```

**Recommendation**:  
Consider adding the following checks:
- `recovery != 0`
- `agent != 0`
- `_args.params.destinationDomain != s.domain`
- `_args.params.slippageTol <= s.LIQUIDITY_FEE_DENOMINATOR`

Also, double-check if any additional checks are useful.

**Connext**: Solved in PR 1536.  
**Spearbit**: Verified.

**Reference**: [View Original Finding](https://github.com/spearbit/portfolio/blob/master/pdfs/Connext-Spearbit-Security-Review.pdf)

---

### Example 6: M-2: Depositing `stETH` to puffer finance will revert due to wrong implementation of `PufETHAdapter._stake` call

**Source**: Sherlock
**Protocol**: Napier Finance - LST/LRT Integrations
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2024-05-napier-update-judging/issues/21 

## Found by 
Bauer, Drynooo, Ironsidesec, KupiaSec, PNS, blackhole, blutorque, karsar, merlin, no, yamato, zzykxx
## Summary
Reason: `PufETHAdapter._stake` will always revert due to wrong external call implementation.
Impact: Can't deposit to Puffer.
Likelihood: always.


## Vulnerability Detail

https://github.com/sherlock-audit/2024-05-napier-update/blob/c31af59c6399182fd04b40530d79d98632d2bfa7/napier-uups-adapters/src/adapters/puffer/PufETHAdapter.sol#L82

```solidity
File: 2024-05-napier-update\napier-uups-adapters\src\adapters\puffer\PufETHAdapter.sol

66:   function _stake(uint256 stakeAmount) internal override returns (uint256) {
...
74: 
75:     IWETH9(Constants.WETH).withdraw(stakeAmount);
76:     uint256 _stETHAmt = STETH.balanceOf(address(this));
77:     STETH.submit{value: stakeAmount}(address(this));
78:     _stETHAmt = STETH.balanceOf(address(this)) - _stETHAmt;
79:     if (_stETHAmt == 0) revert InvariantViolation();
80: 
81:     // Stake stETH to PufferDepositor
82:  >>> uint256 _pufETHAmt = PUFFER_DEPOSITOR.depositStETH(Permit(block.timestamp, _stETHAmt, 0, 0, 0));
84: 
...
88:   }

```

**Issue flow**:
1. When depositing by calling `PUFFER_DEPOSITOR.depositStETH(Permit)`, `PufETHAdapter` passes only one parameter `Permit` look at line 82 above.
2. But the current `PUFFER_DEPOSITOR.depositStETH` has 2 parameters (Permit, address recipient). Chec

*[Content truncated...]*

---

### Example 7: M-5: `getPositionRisk()` will return a wrong value of risk

**Source**: Sherlock
**Protocol**: Blueberry Update
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-04-blueberry-judging/issues/97 

## Found by 
Ch\_301
## Summary
In order to interact with SPELL the users need to `lend()` some collateral which is known as **Isolated Collateral** and the SoftVault will deposit them into Compound protocol to generate some lending interest (to earn passive yield)  

## Vulnerability Detail
to [liquidate](https://github.com/sherlock-audit/2023-04-blueberry/blob/main/blueberry-core/contracts/BlueBerryBank.sol#L487-L548) a position this function `isLiquidatable()` should return `true`
```solidity
    function isLiquidatable(uint256 positionId) public view returns (bool) {
        return
            getPositionRisk(positionId) >=
            banks[positions[positionId].underlyingToken].liqThreshold;
    }
```
and it is subcall to `getPositionRisk()`
```solidity
    function getPositionRisk(
        uint256 positionId
    ) public view returns (uint256 risk) {
        uint256 pv = getPositionValue(positionId);          
        uint256 ov = getDebtValue(positionId);             
        uint256 cv = getIsolatedCollateralValue(positionId);

        if (
            (cv == 0 && pv == 0 && ov == 0) || pv >= ov // Closed position or Overcollateralized position
        ) {
            risk = 0;
        } else if (cv == 0) {
            // Sth bad happened to isolated underlying token
            risk = Constants.DENOMINATOR;
        } else {
            risk = ((ov - pv) * Constants.DENOMINATOR) / cv;
   

*[Content truncated...]*

---

### Example 8: [M-25] Vault can be created for not-yet-existing ERC20 tokens, which allows attackers to set traps to steal NFTs from Borrowers

**Source**: Code4rena
**Protocol**: Astaria
**Impact**: MEDIUM

**Details**:

There is a subtle difference between the implementation of solmates SafeTransferLib and OZs SafeERC20: OZs SafeERC20 checks if the token is a contract or not, solmates SafeTransferLib does not.<br>
See: <https://github.com/Rari-Capital/solmate/blob/main/src/utils/SafeTransferLib.sol#L9><br>
Note that none of the functions in this library check that a token has code at all! That responsibility is delegated to the caller.<br>
As a result, when the tokens address has no code, the transaction will just succeed with no error.<br>
This attack vector was made well-known by the qBridge hack back in Jan 2022.

In AstariaRouter, Vault, PublicVault, VaultImplementation, ClearingHouse, TransferProxy, and WithdrawProxy, the `safetransfer` and `safetransferfrom` don't check the existence of code at the token address. This is a known issue while using solmates libraries.

Hence this can lead to miscalculation of funds and also loss of funds , because if safetransfer() and safetransferfrom() are called on a token address that doesnt have contract in it, it will always return success. Due to this protocol will think that funds has been transferred and successful , and records will be accordingly calculated, but in reality funds were never transferred.

So this will lead to miscalculation and loss of funds.

### Attack scenario (example):

Its becoming popular for protocols to deploy their token across multiple networks and when they do so, a common practice is to deploy the token cont

*[Content truncated...]*

**Reference**: [View Original Finding](https://code4rena.com/reports/2023-01-astaria)

---

## Statistics

- Total findings analyzed: 8
- Examples shown: 8
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

