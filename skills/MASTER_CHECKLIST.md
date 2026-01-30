#  Smart Contract Security Master Checklist

*Based on 50,530 real audit findings from Code4rena, Sherlock, Cyfrin, and 20+ audit platforms*

---

##  CRITICAL PRIORITY (Top 20 Most Common)

### 1. Business Logic (234 occurrences - 0.46%)

- [ ] Review all instances for business logic vulnerabilities
- [ ] Check edge cases and boundary conditions
- [ ] Verify proper validation and access controls

 **Pattern Reference**: [patterns/business-logic-patterns.md](patterns/business-logic-patterns.md)

---

### 2. Validation (127 occurrences - 0.25%)

- [ ] Review all instances for validation vulnerabilities
- [ ] Check edge cases and boundary conditions
- [ ] Verify proper validation and access controls

 **Pattern Reference**: [patterns/validation-patterns.md](patterns/validation-patterns.md)

---

### 3. Wrong Math (107 occurrences - 0.21%)

- [ ] Review all instances for wrong math vulnerabilities
- [ ] Check edge cases and boundary conditions
- [ ] Verify proper validation and access controls

 **Pattern Reference**: [patterns/wrong-math-patterns.md](patterns/wrong-math-patterns.md)

---

### 4. Front-Running (106 occurrences - 0.21%)

- [ ] Review all instances for front-running vulnerabilities
- [ ] Check edge cases and boundary conditions
- [ ] Verify proper validation and access controls

 **Pattern Reference**: [patterns/front-running-patterns.md](patterns/front-running-patterns.md)

---

### 5. Fee On Transfer (66 occurrences - 0.13%)

- [ ] Review all instances for fee on transfer vulnerabilities
- [ ] Check edge cases and boundary conditions
- [ ] Verify proper validation and access controls

 **Pattern Reference**: [patterns/fee-on-transfer-patterns.md](patterns/fee-on-transfer-patterns.md)

---

### 6. DOS (66 occurrences - 0.13%)

- [ ] Review all instances for dos vulnerabilities
- [ ] Check edge cases and boundary conditions
- [ ] Verify proper validation and access controls

 **Pattern Reference**: [patterns/dos-patterns.md](patterns/dos-patterns.md)

---

### 7. Oracle (59 occurrences - 0.12%)

- [ ] Review all instances for oracle vulnerabilities
- [ ] Check edge cases and boundary conditions
- [ ] Verify proper validation and access controls

 **Pattern Reference**: [patterns/oracle-patterns.md](patterns/oracle-patterns.md)

---

### 8. Reentrancy (59 occurrences - 0.12%)

- [ ] Review all instances for reentrancy vulnerabilities
- [ ] Check edge cases and boundary conditions
- [ ] Verify proper validation and access controls

 **Pattern Reference**: [patterns/reentrancy-patterns.md](patterns/reentrancy-patterns.md)

---

### 9. Access Control (48 occurrences - 0.09%)

- [ ] Review all instances for access control vulnerabilities
- [ ] Check edge cases and boundary conditions
- [ ] Verify proper validation and access controls

 **Pattern Reference**: [patterns/access-control-patterns.md](patterns/access-control-patterns.md)

---

### 10. Don't update state (47 occurrences - 0.09%)

- [ ] Review all instances for don't update state vulnerabilities
- [ ] Check edge cases and boundary conditions
- [ ] Verify proper validation and access controls

 **Pattern Reference**: [patterns/don-t-update-state-patterns.md](patterns/don-t-update-state-patterns.md)

---

### 11. Decimals (45 occurrences - 0.09%)

- [ ] Review all instances for decimals vulnerabilities
- [ ] Check edge cases and boundary conditions
- [ ] Verify proper validation and access controls

 **Pattern Reference**: [patterns/decimals-patterns.md](patterns/decimals-patterns.md)

---

### 12. Overflow/Underflow (43 occurrences - 0.09%)

- [ ] Review all instances for overflow/underflow vulnerabilities
- [ ] Check edge cases and boundary conditions
- [ ] Verify proper validation and access controls

 **Pattern Reference**: [patterns/overflow-underflow-patterns.md](patterns/overflow-underflow-patterns.md)

---

### 13. Liquidation (42 occurrences - 0.08%)

- [ ] Review all instances for liquidation vulnerabilities
- [ ] Check edge cases and boundary conditions
- [ ] Verify proper validation and access controls

 **Pattern Reference**: [patterns/liquidation-patterns.md](patterns/liquidation-patterns.md)

---

### 14. Slippage (36 occurrences - 0.07%)

- [ ] Review all instances for slippage vulnerabilities
- [ ] Check edge cases and boundary conditions
- [ ] Verify proper validation and access controls

 **Pattern Reference**: [patterns/slippage-patterns.md](patterns/slippage-patterns.md)

---

### 15. Denial-Of-Service (36 occurrences - 0.07%)

- [ ] Review all instances for denial-of-service vulnerabilities
- [ ] Check edge cases and boundary conditions
- [ ] Verify proper validation and access controls

 **Pattern Reference**: [patterns/denial-of-service-patterns.md](patterns/denial-of-service-patterns.md)

---

### 16. Admin (36 occurrences - 0.07%)

- [ ] Review all instances for admin vulnerabilities
- [ ] Check edge cases and boundary conditions
- [ ] Verify proper validation and access controls

 **Pattern Reference**: [patterns/admin-patterns.md](patterns/admin-patterns.md)

---

### 17. Missing-Logic (33 occurrences - 0.07%)

- [ ] Review all instances for missing-logic vulnerabilities
- [ ] Check edge cases and boundary conditions
- [ ] Verify proper validation and access controls

 **Pattern Reference**: [patterns/missing-logic-patterns.md](patterns/missing-logic-patterns.md)

---

### 18. Rounding (32 occurrences - 0.06%)

- [ ] Review all instances for rounding vulnerabilities
- [ ] Check edge cases and boundary conditions
- [ ] Verify proper validation and access controls

 **Pattern Reference**: [patterns/rounding-patterns.md](patterns/rounding-patterns.md)

---

### 19. Stale Price (31 occurrences - 0.06%)

- [ ] Review all instances for stale price vulnerabilities
- [ ] Check edge cases and boundary conditions
- [ ] Verify proper validation and access controls

 **Pattern Reference**: [patterns/stale-price-patterns.md](patterns/stale-price-patterns.md)

---

### 20. ERC4626 (28 occurrences - 0.06%)

- [ ] Review all instances for erc4626 vulnerabilities
- [ ] Check edge cases and boundary conditions
- [ ] Verify proper validation and access controls

 **Pattern Reference**: [patterns/erc4626-patterns.md](patterns/erc4626-patterns.md)

---

##  HIGH PRIORITY (Ranks 21-50)

| Rank | Vulnerability Type | Count | % of Total |
|------|-------------------|-------|------------|
| 21 | ERC20 | 27 | 0.053% |
| 22 | First Depositor Issue | 26 | 0.051% |
| 23 | Weird ERC20 | 26 | 0.051% |
| 24 | Flash Loan | 25 | 0.049% |
| 25 | Chainlink | 25 | 0.049% |
| 26 | Configuration | 24 | 0.047% |
| 27 | Missing Check | 23 | 0.046% |
| 28 | Vote | 22 | 0.044% |
| 29 | Uniswap | 22 | 0.044% |
| 30 | Fund Lock | 22 | 0.044% |
| 31 | ERC721 | 21 | 0.042% |
| 32 | Coding-Bug | 20 | 0.040% |
| 33 | Sandwich Attack | 19 | 0.038% |
| 34 | NFT | 19 | 0.038% |
| 35 | Deposit/Reward tokens | 18 | 0.036% |
| 36 | Gas Limit | 18 | 0.036% |
| 37 | Chain Reorganization Attack | 18 | 0.036% |
| 38 | Approve | 18 | 0.036% |
| 39 | Swap | 18 | 0.036% |
| 40 | Lending Pool | 17 | 0.034% |
| 41 | ERC1155 | 17 | 0.034% |
| 42 | Blacklisted | 16 | 0.032% |
| 43 | Auction | 15 | 0.030% |
| 44 | Initialization | 15 | 0.030% |
| 45 | Allowance | 15 | 0.030% |
| 46 | call vs transfer | 15 | 0.030% |
| 47 | Bypass limit | 15 | 0.030% |
| 48 | Precision Loss | 14 | 0.028% |
| 49 | Replay Attack | 14 | 0.028% |
| 50 | transferFrom vs safeTransferFrom | 14 | 0.028% |


##  MEDIUM PRIORITY (Ranks 51-100)

| Rank | Vulnerability Type | Count |
|------|-------------------|-------|
| 51 | Type casting | 14 |
| 52 | SafeTransfer | 14 |
| 53 | Ownership | 13 |
| 54 | Grief Attack | 12 |
| 55 | Share Inflation | 12 |
| 56 | Refund Ether | 12 |
| 57 | ERC777 | 11 |
| 58 | Upgradable | 10 |
| 59 | Code Quality | 10 |
| 60 | Pause | 10 |
| 61 | TWAP | 10 |
| 62 | Initial Deposit | 9 |
| 63 | Timing | 9 |
| 64 | Vault | 9 |
| 65 | Payable | 9 |
| 66 | EIP-4626 | 9 |
| 67 | Min/Max Cap Validation | 9 |
| 68 | External Call | 8 |
| 69 | Cross Chain | 8 |
| 70 | Delegate | 8 |
| 71 | Pre/Post Balance | 7 |
| 72 | 0x | 7 |
| 73 | Check Return Value | 7 |
| 74 | Whitelist/Blacklist Match | 7 |
| 75 | LayerZero | 7 |
| 76 | Data Validation | 7 |
| 77 | External Contract | 7 |
| 78 | Broken Loop | 7 |
| 79 | Revert By Sending Dust | 7 |
| 80 | Bridge | 7 |
| 81 | 1/64 Rule | 6 |
| 82 | Account Abstraction | 6 |
| 83 | L2 Sequencer | 6 |
| 84 | from=to | 6 |
| 85 | Typo / CopyPaste | 6 |
| 86 | Change Validation | 6 |
| 87 | EIP-712 | 6 |
| 88 | Deadline | 6 |
| 89 | USDC | 6 |
| 90 | USDT | 6 |
| 91 | Event | 6 |
| 92 | Withdraw Pattern | 6 |
| 93 | Array | 6 |
| 94 | Read-only Reentrancy | 6 |
| 95 | Royalty | 6 |
| 96 | ERC2981 | 6 |
| 97 | Hardcoded Address | 6 |
| 98 | Arbitrum | 5 |
| 99 | EIP-165 | 5 |
| 100 | supportsInterface | 5 |


---

##  Statistics

- **Total Vulnerabilities Analyzed**: 50,530
- **Unique Vulnerability Types**: 207
- **Checklist Coverage**: Top 100 vulnerability types
- **Last Updated**: 2026-01-29

##  Quick Links

- [All Pattern Files](patterns/)
- [Severity Analysis](severity/)
- [Audit Source Analysis](sources/)
- [Full Statistics](STATISTICS.md)
- [Searchable Index](INDEX.md)

