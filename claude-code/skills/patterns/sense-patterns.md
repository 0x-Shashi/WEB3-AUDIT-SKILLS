# Sense Security Patterns

## Overview

**Frequency**: 3 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 2 | 0 | 1 | 0 |

**Common Sources**: Sherlock, Pashov Audit Group

---

## Detection Checklist

- [ ] Check for sense vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: H-2: AutoRoller#eject can be used to steal all the yield from vault's YTs

**Source**: Sherlock
**Protocol**: Sense
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-sense-judging/issues/22 

## Found by 
0x52

## Summary

AutoRoller#eject collects all the current yield of the YTs, combines the users share of the PTs and YTs then sends the user the entire target balance of the contract. The problem is that combine claims the yield for ALL YTs, which sends the AutoRoller target assets. Since it sends the user the entire target balance of the contract it accidentally sends the user the yield from all the pool's YTs. 

## Vulnerability Detail

    function eject(
        uint256 shares,
        address receiver,
        address owner
    ) public returns (uint256 assets, uint256 excessBal, bool isExcessPTs) {

        ...

        //@audit call of interest
        (excessBal, isExcessPTs) = _exitAndCombine(shares);

        _burn(owner, shares); // Burn after percent ownership is determined in _exitAndCombine.

        if (isExcessPTs) {
            pt.transfer(receiver, excessBal);
        } else {
            yt.transfer(receiver, excessBal);
        }

        //@audit entire asset (adapter.target) balance transferred to caller, which includes collected YT yield and combined
        asset.transfer(receiver, assets = asset.balanceOf(address(this)));

        emit Ejected(msg.sender, receiver, owner, assets, shares,
            isExcessPTs ? excessBal : 0,
            isExcessPTs ? 0 : excessBal
        );
    }

    function _exitAndCombine(uint256 shares) internal returns (uint256, bool) {

*[Content truncated...]*

---

### Example 2: H-4: Adversary can brick AutoRoller by creating another AutoRoller on the same adapter

**Source**: Sherlock
**Protocol**: Sense
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-sense-judging/issues/20 

## Found by 
0x52

## Summary

onSponsorWindowOpened attempts to make a new series at the desired maturity. Each adapter can only have one of each maturity. If the maturity requested already exists then onSponsorWindowOpened will revert, making it impossible to roll the AutoRoller. An adversary can take advantage of this to brick an AutoRoller by creating a second AutoRoller on the same adapter that will create a target maturity before the first AutoRoller. Since the maturity now exists, the first AutoRoller will always revert when trying to Roll.  

## Vulnerability Detail

    uint256 _maturity = utils.getFutureMaturity(targetDuration);

    function getFutureMaturity(uint256 monthsForward) public view returns (uint256) {
        (uint256 year, uint256 month, ) = DateTime.timestampToDate(DateTime.addMonths(block.timestamp, monthsForward));
        return DateTime.timestampFromDateTime(year, month, 1 /* top of the month */, 0, 0, 0);
    }

Inside AutoRoller#onSponsorWindowOpened the maturity is calculated using RollerUtils#getFutureMaturity. This returns the timestamp the requested months ahead, truncated down to the first of the month. It passes this calculated maturity as the maturity to sponsor a new series.

    (ERC20 _pt, YTLike _yt) = periphery.sponsorSeries(address(adapter), _maturity, true);

https://etherscan.io/address/0xFff11417a58781D3C72083CB45EF54d79Cd02437#code#F1#L90

    function s

*[Content truncated...]*

---

### Example 3: [L-04] Frontrunnable Initialization

**Source**: Pashov Audit Group
**Protocol**: Enclave_2025-10-25
**Impact**: LOW

**Details**:

_Acknowledged_

The `initialize` instruction creates the global `fund_pool` PDA (`seed = b"fund_pool"`) and sets `initial_admin` to an arbitrary public key supplied by the caller. There is no access control restricting who may invoke this first-use initializer. An attacker can front-run deployment, initialize the pool, and seize control over all admin- and signer-gated operations for the lifetime of the program (until redeploy).

**Recommendations**

Implement a robust access control mechanism that ensures only a trusted entity, such as the program's deployer or a predefined address, can call the `initialize` function. This restriction can be enforced by verifying the caller's identity or using a specific signature during initialization.

**Reference**: [View Original Finding](https://github.com/pashov/audits/blob/master/team/md/Enclave-security-review_2025-10-25.md)

---

## Statistics

- Total findings analyzed: 3
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

