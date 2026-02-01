---
id: METHOD-ECONOMIC-MODELING
title: Economic Attack Modeling
category: methodology
difficulty: expert
tags: [economics, game-theory, tokenomics, mev, incentives]
last_updated: 2026-01-31
---

# Economic Attack Modeling

## Overview

Economic attacks exploit flawed incentive structures rather than code bugs. Understanding game theory and tokenomics is critical for auditing DeFi protocols.

```
┌─────────────────────────────────────────────────────────────────┐
│                   ECONOMIC ATTACK SURFACE                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │  Incentive  │  │  Market     │  │   MEV       │             │
│  │  Misalign   │  │  Manipulate │  │   Exploits  │             │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘             │
│         │                │                │                     │
│         └────────────────┼────────────────┘                     │
│                          ▼                                      │
│              ┌───────────────────────┐                          │
│              │   Rational Attacker   │                          │
│              │   Profit > Cost?      │                          │
│              └───────────────────────┘                          │
│                          │                                      │
│              ┌───────────▼───────────┐                          │
│              │  If YES: Attack       │                          │
│              │  Extract value from   │                          │
│              │  protocol/users       │                          │
│              └───────────────────────┘                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Attack Profitability Framework

### Basic Calculation

```python
# Attack is rational if:
# Expected_Profit > Expected_Cost

Expected_Profit = (
    P(success) * Profit_if_success
    - P(failure) * Loss_if_failure
    - Opportunity_cost
    - Gas_costs
)

# Example: Oracle manipulation attack
P_success = 0.9  # High success rate
Profit = $1,000,000  # Protocol TVL extractable
P_failure = 0.1
Loss = $50,000  # Collateral lost on failure
Gas = $500
Opportunity = $1,000  # Capital locked during attack

Expected_Profit = 0.9 * 1_000_000 - 0.1 * 50_000 - 500 - 1_000
# = $900,000 - $5,000 - $1,500
# = $893,500 → ATTACK IS PROFITABLE
```

### Cost-Benefit Matrix

| Attack Type | Capital Required | Success Rate | Typical Profit | Risk |
|-------------|-----------------|--------------|----------------|------|
| Flash Loan Oracle | $0 (borrowed) | High | Variable | Low |
| Governance Takeover | High (voting power) | Medium | Very High | Medium |
| Sandwich MEV | Medium | Very High | Low per tx | Low |
| Liquidation Manipulation | High | Medium | High | Medium |
| Rug Pull (malicious) | Protocol control | Certain | 100% TVL | High |

---

## Common Economic Attack Vectors

### 1. Flash Loan Price Manipulation

```solidity
// Attack pattern:
// 1. Flash loan large amount
// 2. Manipulate price (swap in DEX)
// 3. Exploit protocol using manipulated price
// 4. Repay flash loan + profit

contract FlashLoanAttack {
    function attack() external {
        // 1. Borrow $100M
        flashLender.flashLoan(100_000_000e18, address(this), "");
    }
    
    function onFlashLoan(uint256 amount) external {
        // 2. Dump into DEX to crash price
        // USDC → ETH (crashes ETH price on this DEX)
        dex.swap(usdc, eth, amount);
        
        // 3. Protocol uses this DEX for pricing
        // Liquidate positions at wrong price
        lendingProtocol.liquidate(victim);  // Gets collateral cheap
        
        // 4. Swap back and repay
        dex.swap(eth, usdc, ethBalance);
        flashLender.repay(amount + fee);
        
        // Profit: Cheap collateral - flash loan fee
    }
}
```

**Defense Analysis:**
```python
# Cost to attacker:
flash_loan_fee = 0.09%  # ~$90,000 on $100M
slippage_cost = variable  # Depends on DEX liquidity
gas_cost = ~$500

# For attack to be unprofitable:
# Profit < flash_loan_fee + slippage + gas

# Defense: Use TWAP oracle
# Attack cost increases (must hold position for TWAP window)
# Opportunity cost = capital_locked * time * interest_rate
```

### 2. Governance Attacks

```solidity
// Attack pattern:
// 1. Acquire voting power (buy/borrow tokens)
// 2. Submit malicious proposal
// 3. Vote it through
// 4. Extract value

// Cost analysis:
struct GovernanceAttack {
    uint256 votingPowerNeeded;    // e.g., 4% to propose, 51% to pass
    uint256 tokenPrice;           // Current governance token price
    uint256 borrowCost;           // If borrowing tokens
    uint256 timelockDelay;        // Must hold through timelock
    uint256 protocolTVL;          // Max extractable value
}

// Example: Beanstalk attack
// Cost: Flash loan fee (~$0)
// Profit: $182M
// Defense failure: No time delay between proposal and execution
```

**Defense Checklist:**
```python
governance_defenses = [
    "Timelock delay (24-72 hours)",
    "Voting escrow (lock tokens to vote)",
    "Proposal threshold (min tokens to propose)",
    "Quorum requirement",
    "Snapshot voting (block-specific)",
    "Guardian/veto power",
]
```

### 3. Liquidation Manipulation

```solidity
// Attack: Make healthy position liquidatable, then liquidate

contract LiquidationManipulation {
    function attack(address victim) external {
        // 1. Check victim's position
        (uint256 collateral, uint256 debt, uint256 healthFactor) = 
            lending.getPosition(victim);
        
        // 2. If healthFactor > 1 but close, manipulate price
        if (healthFactor < 1.1e18) {
            // Crash collateral price or pump debt price
            manipulateOracle();
            
            // 3. Liquidate at profit
            lending.liquidate(victim, debtToCover);
            
            // 4. Profit = liquidation bonus - manipulation cost
        }
    }
}
```

**Economic Analysis:**
```python
# Profitable if:
liquidation_bonus = 5%  # Protocol gives 5% bonus
collateral_value = $100,000
manipulation_cost = calculate_manipulation_cost()  # Slippage + fees

profit = collateral_value * liquidation_bonus - manipulation_cost

# Defense: Liquidation bonus < cost to manipulate
# Use manipulation-resistant oracles
```

### 4. Sandwich Attacks (MEV)

```solidity
// Attack: Front-run and back-run user trades

// User submits: Buy 100 ETH with 1% slippage
// Attacker sees in mempool:
// 1. Front-run: Buy ETH (price goes up)
// 2. User trade executes at higher price
// 3. Back-run: Sell ETH (take profit)

contract SandwichBot {
    function sandwich(
        address victim,
        address tokenIn,
        address tokenOut,
        uint256 victimAmount
    ) external {
        // 1. Calculate optimal front-run amount
        uint256 frontRunAmount = calculateOptimal(victimAmount);
        
        // 2. Buy before victim
        dex.swap(tokenIn, tokenOut, frontRunAmount);
        
        // 3. Victim's tx executes (price moved against them)
        
        // 4. Sell after victim
        dex.swap(tokenOut, tokenIn, frontRunAmount + profit);
    }
}
```

**Economics:**
```python
# Sandwich profit formula (Uniswap V2):
def sandwich_profit(victim_amount, reserves, front_run_amount):
    # Price impact from front-run
    price_impact_1 = front_run_amount / reserves
    
    # Victim pays higher price
    victim_extra_cost = victim_amount * price_impact_1
    
    # Attacker profit ≈ victim_extra_cost - 2*gas - 2*swap_fee
    return victim_extra_cost - gas_costs - fees

# Users can defend with:
# - Low slippage tolerance (but risks failed tx)
# - Private mempools (Flashbots Protect)
# - MEV-resistant DEXs (CoW Protocol)
```

---

## Tokenomics Vulnerability Analysis

### Inflation Attack

```solidity
// Problem: Uncontrolled token minting

// BAD: No supply cap
function mint(address to, uint256 amount) external onlyMinter {
    _mint(to, amount);  // Can mint unlimited
}

// Attack:
// 1. Become minter (exploit access control)
// 2. Mint billions of tokens
// 3. Dump on market
// 4. Protocol value → 0

// Example: PlayDapp ($290M loss)
```

### Deflationary Death Spiral

```solidity
// Problem: Fee-on-transfer creates death spiral

// Each transfer burns 2%
function transfer(address to, uint256 amount) public {
    uint256 fee = amount * 2 / 100;
    _burn(msg.sender, fee);
    _transfer(msg.sender, to, amount - fee);
}

// Economics:
// - High trading activity = faster deflation
// - Deflation increases scarcity → price up
// - BUT: Transaction costs discourage use
// - Usage drops → utility drops → price drops
// - Spiral accelerates as speculators leave
```

### Ponzi Detection

```python
# Signs of unsustainable tokenomics:

ponzi_indicators = {
    "yield_source": {
        "red_flag": "New deposits pay old depositors",
        "green_flag": "Yield from external revenue (fees, lending)"
    },
    "sustainability": {
        "red_flag": "APY requires constant growth",
        "green_flag": "APY sustainable at stable TVL"
    },
    "token_utility": {
        "red_flag": "Token only for speculation",
        "green_flag": "Token has real utility (governance, fees)"
    }
}

def calculate_sustainability(protocol):
    # Revenue must cover yield payments
    daily_yield_paid = tvl * apy / 365
    daily_revenue = trading_fees + borrow_interest + other
    
    if daily_revenue < daily_yield_paid:
        return "UNSUSTAINABLE - Ponzi characteristics"
    return "Potentially sustainable"
```

---

## Game Theory Analysis

### Nash Equilibrium in DeFi

```python
# Players act in self-interest
# Equilibrium: No player can improve by changing strategy

# Example: Staking game
# Players: Stakers, Protocol
# Strategies: Stake/Unstake, Set rewards

def find_equilibrium(staking_apy, unstaking_penalty, market_rate):
    """
    Staker's decision:
    - Stake if: staking_apy > market_rate + risk_premium
    - Unstake if: better opportunity exists
    
    Protocol's decision:
    - High APY attracts stakers but costs more
    - Low APY loses stakers
    """
    
    # Equilibrium APY ≈ market_rate + risk_premium
    # If protocol offers less, stakers leave
    # If protocol offers more, it's overpaying
    
    equilibrium_apy = market_rate + estimate_risk_premium()
    return equilibrium_apy
```

### Griefing Analysis

```python
# Griefing: Attacking to harm others, not for direct profit

def griefing_viable(attack_cost, victim_loss):
    """
    Griefing is viable if attacker considers victim loss as 'profit'
    
    Examples:
    - Competitor attacks rival protocol
    - Short seller attacks to profit from price drop
    - Disgruntled user attacks out of spite
    """
    
    # Defense: Make attack cost > victim loss
    # Attacker spends more than victim loses
    
    if attack_cost > victim_loss:
        return "Griefing not viable"
    else:
        return f"Griefing viable: {victim_loss - attack_cost} net damage"
```

---

## Audit Framework

### Economic Security Checklist

```markdown
## Incentive Alignment
- [ ] Are all actors incentivized to behave honestly?
- [ ] What's the cost to attack vs. profit?
- [ ] Can flash loans be used to amplify attacks?
- [ ] Are there MEV opportunities that harm users?

## Oracle Security
- [ ] What's the cost to manipulate the oracle?
- [ ] Does manipulation cost exceed profit?
- [ ] Is TWAP window sufficient?
- [ ] Are there multiple oracle sources?

## Tokenomics
- [ ] Is token supply capped or controlled?
- [ ] Are emissions sustainable?
- [ ] Can minting be exploited?
- [ ] Is yield source legitimate?

## Governance
- [ ] Is there a timelock on proposals?
- [ ] Can flash loans affect voting?
- [ ] Is voting power properly distributed?
- [ ] Can malicious proposals be vetoed?

## Liquidation
- [ ] Is liquidation bonus < manipulation cost?
- [ ] Are positions safe from artificial liquidation?
- [ ] Is there a liquidation delay/auction?

## Market Impact
- [ ] What's the slippage on max possible trade?
- [ ] Can large trades cause cascading liquidations?
- [ ] Are circuit breakers in place?
```

### Quantitative Analysis Template

```python
def analyze_protocol_economics(protocol):
    report = {}
    
    # 1. Flash loan attack cost
    report['flash_loan_attack'] = {
        'max_borrowable': get_flash_loan_capacity(),
        'manipulation_impact': calculate_price_impact(),
        'attack_profit': calculate_attack_profit(),
        'recommendation': 'SAFE' if attack_profit < 0 else 'VULNERABLE'
    }
    
    # 2. Governance attack cost
    report['governance_attack'] = {
        'voting_power_needed': protocol.quorum,
        'token_cost': voting_power_needed * token_price,
        'borrow_cost': calculate_borrow_cost(voting_power_needed),
        'protocol_tvl': protocol.tvl,
        'roi': protocol.tvl / min(token_cost, borrow_cost),
        'recommendation': 'SAFE' if roi < 1.5 else 'VULNERABLE'
    }
    
    # 3. Oracle manipulation cost
    report['oracle_manipulation'] = {
        'liquidity_to_move_1%': calculate_liquidity_depth(1),
        'liquidity_to_move_10%': calculate_liquidity_depth(10),
        'twap_window': protocol.oracle_twap_window,
        'capital_lockup_cost': calculate_lockup_cost(),
        'recommendation': assess_oracle_security()
    }
    
    return report
```

---

## Case Studies

### Beanstalk ($182M)

```python
attack_analysis = {
    'attack_type': 'Governance',
    'capital_required': '$0 (flash loan)',
    'profit': '$182M',
    
    'vulnerability': [
        'No voting escrow (could vote with borrowed tokens)',
        'No timelock (proposal executed immediately)',
        'Flash loan in same tx as vote'
    ],
    
    'attack_steps': [
        '1. Flash loan $1B worth of tokens',
        '2. Deposit into governance',
        '3. Submit + vote on malicious proposal',
        '4. Execute proposal (drain funds)',
        '5. Repay flash loan'
    ],
    
    'cost': 'Flash loan fee only (~$10K)',
    'fix': 'Add timelock + snapshot voting'
}
```

### Mango Markets ($114M)

```python
attack_analysis = {
    'attack_type': 'Market Manipulation',
    'capital_required': '$5M',
    'profit': '$114M',
    
    'vulnerability': [
        'Low liquidity on MNGO perpetual',
        'Collateral value based on manipulatable price',
        'No circuit breakers'
    ],
    
    'attack_steps': [
        '1. Deposit $5M collateral',
        '2. Open huge long MNGO-PERP position',
        '3. Buy MNGO spot to pump price',
        '4. Perp position now shows massive profit',
        '5. Borrow against "profit" as collateral',
        '6. Withdraw borrowed funds',
        '7. Let position liquidate (already withdrew profit)'
    ],
    
    'fix': 'Use reliable oracles, limit position sizes'
}
```

---

## Tools for Economic Analysis

| Tool | Purpose |
|------|---------|
| DeFiLlama | TVL, protocol metrics |
| Dune Analytics | On-chain data analysis |
| MEV-Explore | MEV activity tracking |
| Gauntlet | Economic modeling |
| Token Terminal | Revenue/earnings data |
| DeBank | Wallet tracking |

---

## Related Resources

- [Paradigm - MEV Research](https://www.paradigm.xyz/mev)
- [Flashbots - MEV Documentation](https://docs.flashbots.net/)
- [Gauntlet - DeFi Risk](https://gauntlet.network/)
- [SoK: DeFi Attacks](https://arxiv.org/abs/2208.13035)
