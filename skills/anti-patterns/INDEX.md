# Anti-Patterns Index

**What NOT to do** - Bad code examples that lead to exploits.

---

## What Are Anti-Patterns?

Anti-patterns show **explicitly BAD code** that you should never write. Each anti-pattern includes:

- **Real vulnerable code** - Actual patterns found in production
- **Why it's bad** - Explanation of the vulnerability
- **Exploited in** - Real hacks that used this pattern
- **Attack PoC** - Working exploit code
- **Correct pattern** - How to fix it

---

## Philosophy

**Learn from others' mistakes.** These patterns have all led to real exploits costing millions. By seeing exactly what went wrong, you can avoid repeating these mistakes.

---

## Available Anti-Patterns

### [Oracle Anti-Patterns](oracle-anti-patterns.md)

**7 common oracle mistakes:**

1. **Using Spot Price Directly** ($24M+ losses)
   - Harvest Finance, Warp Finance, Cream Finance
   - Flash loan manipulation of DEX reserves
   - Fix: Use TWAP, not spot price

2. **No Staleness Check** ($1.2M+ losses)
   - Venus Protocol, Inverse Finance
   - Using outdated oracle prices
   - Fix: Check updatedAt timestamp

3. **No Zero/Negative Price Handling** (Critical)
   - Division by zero, int underflow
   - Infinite borrow power
   - Fix: Validate price > 0, handle int casting

4. **Single Oracle, No Fallback** (DoS risk)
   - Synthetix, bZx
   - Single point of failure
   - Fix: Multiple oracles with fallback

5. **Using balanceOf for LP Price** ($7.7M loss)
   - Warp Finance
   - Donation attack inflates LP value
   - Fix: Use getReserves(), not balanceOf

6. **Trusting tx.origin for Oracle** (Phishing)
   - Bypass via intermediate contracts
   - Fix: Use msg.sender, not tx.origin

7. **No Deviation Check (Multi-Oracle)** (High risk)
   - Average of manipulated + real = still exploitable
   - Fix: Check max deviation before averaging

**Use for:** Any protocol using price oracles

---

### [Access Control Anti-Patterns](access-control-anti-patterns.md)

**7 common access control mistakes:**

1. **Unprotected Initialize** ($150M+ losses)
   - Parity Wallet, bridge exploits
   - Front-run initialize() to become owner
   - Fix: Use constructor or initializer modifier

2. **Missing Function Modifiers** ($610M loss)
   - Poly Network, bZx
   - Anyone can call admin functions
   - Fix: Add onlyOwner/onlyRole consistently

3. **Using tx.origin for Auth** ($8M loss)
   - THORChain
   - Phishing attack to trick owner
   - Fix: Use msg.sender, never tx.origin

4. **Inconsistent Access Control** (Audit nightmare)
   - Admin vs owner vs operator confusion
   - Some functions lack any check
   - Fix: Use OpenZeppelin AccessControl consistently

5. **Hardcoded Addresses** ($625M loss)
   - Ronin Bridge
   - Cannot rotate if compromised
   - Fix: Configurable with governance

6. **Centralized Admin with No Timelock** (Rug pull risk)
   - Instant parameter changes
   - Users cannot react
   - Fix: Add 2-day timelock to critical changes

7. **Modifier Only Checks One Condition** (Logic error)
   - Multisig that only checks isSigner
   - Doesn't verify enough signatures
   - Fix: Complete validation in modifier

**Use for:** All protocols

---

### [Reentrancy Anti-Patterns](reentrancy-anti-patterns.md)

**7 common reentrancy mistakes:**

1. **State Update After External Call** ($60M+ losses)
   - The DAO, Lendf.Me, Grim Finance
   - Classic reentrancy vulnerability
   - Fix: Checks-Effects-Interactions pattern

2. **Missing nonReentrant on Critical Functions** (Critical)
   - Cross-function reentrancy
   - Withdraw → reenter → borrow
   - Fix: Add ReentrancyGuard globally

3. **Read-Only Reentrancy** ($1M+ losses)
   - Sentiment, CREAM
   - View functions return stale data during state transition
   - Fix: Guard state transitions, snapshot pattern

4. **ERC777 Callback Reentrancy** ($25M loss)
   - Lendf.Me imBTC
   - Hidden tokensReceived() callback
   - Fix: Block ERC777 or add reentrancy guard

5. **Reentrancy via Callback Parameter** (High risk)
   - User-controlled callback address
   - Arbitrary reentrancy
   - Fix: Validate callback, use nonReentrant

6. **Delegatecall Reentrancy** (Critical)
   - Complex storage, hidden reentrancy
   - Storage collision risks
   - Fix: Guard both proxy and implementation

7. **Ignoring Token Transfer Return Value** (Silent failure)
   - Some tokens return false instead of reverting
   - State corrupted if transfer fails
   - Fix: Use SafeERC20

**Use for:** All protocols with external calls

---

## Coming Soon

Additional anti-pattern guides:

- **Token Anti-Patterns** (fee-on-transfer, rebasing, ERC777)
- **DEX Anti-Patterns** (AMM-specific mistakes)
- **Bridge Anti-Patterns** (cross-chain vulnerabilities)
- **Vault Anti-Patterns** (share price manipulation)
- **Flash Loan Anti-Patterns** (governance, price manipulation)

---

## How to Use Anti-Patterns

### During Code Review

```bash
1. Read the vulnerable code
2. Understand WHY it's bad
3. Look for similar patterns in the codebase
4. Verify the fix is properly implemented
```

### During Audit

```bash
1. Load relevant anti-pattern file
2. Search codebase for similar code
3. Write PoC to confirm vulnerability
4. Recommend the "Correct Pattern" from the file
```

### During Development

```bash
1. Check anti-patterns before implementing
2. Avoid all patterns marked ❌ VULNERABLE
3. Use patterns marked ✅ GOOD
4. Test with the attack PoCs to verify security
```

---

## Format

Each anti-pattern follows this structure:

```markdown
## Anti-Pattern #X: Name

### BAD CODE
❌ VULNERABLE: Code that should never be written

### Why It's Bad
- Explanation of vulnerability
- What goes wrong
- Why it's exploitable

### Exploited In
- Real protocol names
- Year and loss amount
- Type of attack

### Attack PoC
Working exploit code showing how to attack the bad pattern

### Correct Pattern
✅ GOOD: How to fix it properly
```

---

## Statistics

**Total losses from anti-patterns:** $1B+

| Category | Total Loss | Most Common |
|----------|------------|-------------|
| Oracle | $200M+ | Spot price manipulation |
| Access Control | $1.4B+ | Unprotected init, missing modifiers |
| Reentrancy | $115M+ | State after external call |

---

## Integration with Other Skills

Anti-patterns work best when combined with:

1. **Pattern Files** - See the correct way
   - `patterns/oracle-patterns.md` - ✅ GOOD oracle usage
   - `patterns/access-control-patterns.md` - ✅ GOOD access control
   - `patterns/reentrancy-patterns.md` - ✅ GOOD reentrancy protection

2. **Attack Trees** - Understand attack context
   - `attack-trees/lending-attack-tree.md` - Where these fit in attack paths
   - `attack-trees/bridge-attack-tree.md` - Bridge-specific vulnerabilities

3. **Exploit Forensics** - Full incident analysis
   - `exploit-forensics/dao-2016.md` - The DAO reentrancy
   - `exploit-forensics/poly-network-2021.md` - Access control
   - `exploit-forensics/cream-2021.md` - Oracle manipulation

4. **Checklists** - Verify absence of anti-patterns
   - `checklists/comprehensive-checklist.md`
   - `checklists/roles/developer-pre-deployment.md`

---

## Contributing

When adding new anti-patterns:

1. **Must be real** - From actual exploits or audits
2. **Include PoC** - Working attack code
3. **Show fix** - Correct pattern comparison
4. **Reference exploits** - Name real incidents
5. **Test the code** - Verify both vulnerable and fixed versions

---

## Quick Reference

**Most Critical Anti-Patterns (Learn These First):**

1. **Unprotected Initialize** - $150M+ losses, easy to exploit
2. **State After External Call** - $60M+ losses, classic reentrancy
3. **Using Spot Price** - $200M+ losses, flash loan attacks
4. **Missing nonReentrant** - Cross-function reentrancy
5. **tx.origin Auth** - Phishing attacks
6. **No Zero Price Check** - Division by zero, infinite borrow

---

## See Also

- **ROUTE-MAP.md** - Overall audit methodology
- **patterns/** - Correct implementation patterns
- **attack-trees/** - Where vulnerabilities fit in attack paths
- **exploit-forensics/** - Full incident reports

---

**Remember:** Every anti-pattern here has caused real losses. Learn from them.

---

**Last Updated:** 2024
**Version:** 1.0
