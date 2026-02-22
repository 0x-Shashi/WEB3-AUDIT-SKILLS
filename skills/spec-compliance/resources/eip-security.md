# EIP Security Implications

## EIP-712 (Typed Structured Data)
- Domain separator MUST include chainId
- Replay protection via nonces
- Signature malleability: use OpenZeppelin ECDSA
- Domain separator caching on deployment (recalculate if chain changes)

## EIP-1967 (Proxy Storage Slots)
- Standard slots prevent storage collision
- Implementation slot: `bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)`
- Admin slot: `bytes32(uint256(keccak256('eip1967.proxy.admin')) - 1)`
- Security: slots must be used correctly

## EIP-2535 (Diamond Standard)
- Multi-facet proxy pattern
- Risk: function selector collision across facets
- Risk: storage collision between facets
- Must validate facet additions carefully

## EIP-4337 (Account Abstraction)
- UserOperation validation: signature checking in validateUserOp
- Paymaster trust: paying gas for others
- EntryPoint trust: single entry point contract
- Storage access rules during validation phase

## EIP-1153 (Transient Storage)
- TSTORE/TLOAD: storage that resets after transaction
- Useful for reentrancy locks without permanent storage cost
- Risk: transient storage still accessible within same transaction
