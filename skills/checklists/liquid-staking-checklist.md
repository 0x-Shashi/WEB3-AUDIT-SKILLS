# Liquid Staking Protocol Audit Checklist

## 1. Deposit and Minting
- [ ] **CRITICAL** LST minting: tokens issued at correct exchange rate (totalETH / totalShares)
- [ ] **CRITICAL** Deposit accounting: staked ETH tracked accurately across beacon chain deposits
- [ ] **CRITICAL** First depositor attack mitigated — exchange rate cannot be manipulated from 0
- [ ] **HIGH** Deposit buffer: ETH held in contract until batched to validators
- [ ] **HIGH** Minimum deposit enforced (32 ETH increments for direct validator, or pooled)
- [ ] **HIGH** Deposit router: ETH directed to correct validator/operator without interception
- [ ] **MEDIUM** Fee-on-deposit: if applicable, correctly deducted before share calculation
- [ ] **MEDIUM** Deposit cap: maximum protocol TVL enforced during growth phases

## 2. Withdrawal and Redemption
- [ ] **CRITICAL** Withdrawal: user receives correct ETH for shares burned at current rate
- [ ] **CRITICAL** Withdrawal queue: FIFO ordering fair, no front-running or priority bypass
- [ ] **CRITICAL** Withdrawal request cannot be cancelled or modified by protocol admin
- [ ] **HIGH** Validator exit: beacon chain withdrawal processed within expected timeframe
- [ ] **HIGH** Withdrawal finalization: oracle confirms beacon chain exit before ETH release
- [ ] **HIGH** Partial withdrawal supported — no requirement to redeem entire balance
- [ ] **MEDIUM** Withdrawal delay bounded — maximum wait time documented and enforced
- [ ] **MEDIUM** Emergency withdrawal: available with longer delay during unusual conditions
- [ ] **LOW** Failed withdrawal (validator slashed mid-exit): handled gracefully with pro-rata loss

## 3. Exchange Rate and Accounting
- [ ] **CRITICAL** Exchange rate: totalPooledETH / totalShares updated by oracle report only
- [ ] **CRITICAL** Oracle report bounded — rate cannot change by more than X% per report
- [ ] **CRITICAL** Exchange rate monotonically increases (barring slashing events)
- [ ] **HIGH** Rebase vs non-rebase: stETH rebases balances, wstETH does not — documented
- [ ] **HIGH** Accrued rewards: beacon chain rewards added to totalPooledETH by oracle
- [ ] **HIGH** Penalties and slashing: correctly decrease totalPooledETH and share value
- [ ] **MEDIUM** Rounding: always in protocol's favor (round down shares minted, round up redeemed)
- [ ] **MEDIUM** Exchange rate attack: large deposit before oracle report cannot steal rewards
- [ ] **LOW** Historical exchange rate queryable for integrations

## 4. Validator and Node Operator Management
- [ ] **CRITICAL** Operator cannot withdraw staked ETH to their own address
- [ ] **CRITICAL** Withdrawal credentials set to protocol contract, not operator
- [ ] **CRITICAL** Validator key uniqueness: same key cannot be registered twice
- [ ] **HIGH** Operator set: permissioned/curated list with performance requirements
- [ ] **HIGH** Operator exit: protocol can force validator exit via signed exit message
- [ ] **HIGH** Operator reward commission capped and transparent
- [ ] **MEDIUM** Validator distribution: ETH spread across operators to prevent concentration
- [ ] **MEDIUM** Operator key rotation: supported without disrupting staked positions
- [ ] **LOW** Operator performance metrics (uptime, attestation rate) tracked on-chain

## 5. Oracle and Reporting
- [ ] **CRITICAL** Oracle committee/quorum: multiple reporters must agree on beacon state
- [ ] **CRITICAL** Oracle report validated: balance change bounded per epoch
- [ ] **CRITICAL** Oracle cannot report balance increase beyond expected rewards
- [ ] **HIGH** Oracle liveness: fallback if oracle committee doesn't report in time
- [ ] **HIGH** Oracle manipulation: committee members cannot collude to inflate exchange rate
- [ ] **HIGH** Report includes: total validators, total balance, exited validators
- [ ] **MEDIUM** L2 oracle bridging: exchange rate relayed to L2 via secure bridge
- [ ] **MEDIUM** Oracle mismatch: beacon chain balance vs protocol accounting reconciled
- [ ] **LOW** Oracle report frequency documented and sufficient for integrators

## 6. Slashing Risk
- [ ] **CRITICAL** Slashing loss distributed pro-rata across all LST holders
- [ ] **CRITICAL** Slashing reduces totalPooledETH — exchange rate drops correctly
- [ ] **HIGH** Slashing insurance: coverage fund or operator bond absorbs first loss
- [ ] **HIGH** Operator slashing: penalized operator's future rewards redirected to cover loss
- [ ] **HIGH** Multiple slashing events: cumulative tracking and bounded protocol exposure
- [ ] **MEDIUM** Correlated slashing: protocol diversifies across clients and geographies
- [ ] **MEDIUM** Slashing events emitted with operator, validator pubkey, and amount
- [ ] **LOW** Slashing risk parameters per operator documented and auditable

## 7. LST Token Properties
- [ ] **CRITICAL** stETH: rebasing balance matches totalPooledETH × user share ratio
- [ ] **CRITICAL** wstETH: non-rebasing wrapper exchange rate correct (stETH per wstETH)
- [ ] **HIGH** LST ERC-20: transfer, approve, transferFrom standards compliant
- [ ] **HIGH** LST permit (EIP-2612): supported with correct domain separator
- [ ] **HIGH** LST used as collateral: rebasing correctly handled by lending protocols
- [ ] **MEDIUM** LST bridge to L2: exchange rate preserved across chains
- [ ] **MEDIUM** LST token upgrade: proxy upgrade path timelocked and governed
- [ ] **LOW** LST metadata (name, symbol, decimals) consistent — decimals = 18

## 8. DeFi Integration Risks
- [ ] **CRITICAL** LST/ETH price: integrators use exchange rate, not DEX pool spot price
- [ ] **CRITICAL** stETH rebase: lending protocol collateral value updates correctly post-rebase
- [ ] **HIGH** LST in Curve/Uniswap: depeg risk during market stress analyzed
- [ ] **HIGH** LST as collateral in lending: liquidation uses fair value oracle
- [ ] **HIGH** wstETH: integrators correctly convert to stETH value for accounting
- [ ] **MEDIUM** LST yield: integrators compound or claim rewards correctly
- [ ] **MEDIUM** LST withdrawal: integrators handle withdrawal delay gracefully
- [ ] **LOW** LST token transfer: no unexpected callbacks or hooks

## 9. Protocol Governance and Safety
- [ ] **CRITICAL** Protocol upgrade timelocked — contract changes require governance + delay
- [ ] **CRITICAL** Pause mechanism: halts deposits/withdrawals during emergency
- [ ] **HIGH** Operator onboarding/offboarding requires governance vote
- [ ] **HIGH** Fee changes (protocol fee, operator commission) timelocked
- [ ] **HIGH** Maximum ETH per operator bounded to limit single-operator risk
- [ ] **MEDIUM** Dual governance: both stakers and governance token holders can veto
- [ ] **MEDIUM** Insurance fund: percentage of protocol revenue allocated to cover losses
- [ ] **LOW** Transparent treasury: protocol-owned ETH and revenue visible on-chain
