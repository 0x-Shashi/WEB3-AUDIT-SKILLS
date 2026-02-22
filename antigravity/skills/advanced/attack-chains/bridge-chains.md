# Bridge Attack Chains

## Chain 1: Fake Message Verification
```
Step 1: Craft fake cross-chain message
Step 2: Bypass signature/proof verification
Step 3: Execute message on destination chain
Step 4: Mint/unlock tokens without real deposit
```

### Detection Points
- [ ] Message verification uses proper threshold (not 1-of-n)
- [ ] Guardian/validator set cannot be manipulated
- [ ] Signatures verified against correct message hash
- [ ] Replay protection (nonce or message ID)
- [ ] Chain ID included in signed data

### Real Example: Wormhole ($326M)
- Attacker called `complete_transfer` with crafted VAA
- Signature verification bypassed via deprecated `verify_signatures` instruction
- Fake guardian set injected through unvalidated sysvar
- 120,000 wETH minted without deposit

## Chain 2: Deposit-Without-Lock
```
Step 1: Call bridge deposit on source chain
Step 2: Transaction reverts/fails after event emission
Step 3: Relayer picks up deposit event
Step 4: Tokens minted on destination without source lock
```

### Detection Points
- [ ] Deposit events only emitted after successful state change
- [ ] Relayer verifies transaction success (not just event)
- [ ] Finality requirements enforced (wait for confirmations)
- [ ] Source chain state verified before destination mint

## Chain 3: Validator Compromise
```
Step 1: Compromise sufficient validators/guardians
Step 2: Sign fraudulent messages
Step 3: Execute arbitrary cross-chain calls
Step 4: Drain bridge reserves
```

### Detection Points
- [ ] Validator set size (not too small)
- [ ] Key management practices (HSM, MPC)
- [ ] Threshold requirements (not majority, prefer 2/3+1)
- [ ] Validator rotation mechanism
- [ ] Detection of validator compromise

### Real Example: Ronin Bridge ($624M)
- 5 of 9 validators compromised
- 4 Sky Mavis validators + 1 Axie DAO validator
- Attackers signed withdrawal messages
- Went undetected for 6 days

## Chain 4: Token Mapping Exploit
```
Step 1: Register malicious token mapping
Step 2: Deposit worthless tokens on source chain
Step 3: Bridge maps to valuable token on destination
Step 4: Withdraw valuable tokens
```

### Detection Points
- [ ] Token mapping is admin-controlled or verified
- [ ] Cannot map arbitrary token pairs
- [ ] Mapping updates have timelock
- [ ] Token contract verification on both chains

## Chain 5: Reorg Attack
```
Step 1: Deposit tokens on source chain
Step 2: Wait for bridge to process (low confirmation count)
Step 3: Receive tokens on destination chain
Step 4: Reorg source chain to revert deposit
Step 5: Keep tokens on both chains
```

### Detection Points
- [ ] Sufficient confirmation requirements per chain
- [ ] Polygon: 150+ blocks (known reorg risk)
- [ ] Ethereum: 12+ blocks (post-merge)
- [ ] L2s: Finality depends on L1 confirmation

## Audit Approach for Bridges
1. Map ALL message verification paths
2. Trace fund flow: deposit → lock → verify → mint → withdraw → burn → unlock
3. Check every verification step for bypass
4. Verify accounting reconciliation between chains
5. Test with adversarial message crafting
6. Check admin key management and rotation
