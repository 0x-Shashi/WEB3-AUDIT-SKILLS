---
id: PAT-TIME-ROUNDING
title: Time Rounding Security Patterns
category: timing
severity: medium
difficulty: intermediate
chains:
  - ethereum
  - arbitrum
  - optimism
  - polygon
  - bsc
tags:
  - timestamp
  - block
  - deadline

finding_count: 3
last_updated: 2026-01-31
---
# Time Rounding Security Patterns

## Overview

**Frequency**: 3 occurrences (0.01% of all findings)

**Severity Distribution**:
| Critical | High | Medium | Low | Gas |
|----------|------|--------|-----|-----|
| 0 | 1 | 2 | 0 | 0 |

**Common Sources**: Sherlock

---

## Detection Checklist

- [ ] Check for time rounding vulnerabilities in all external functions
- [ ] Verify proper validation and access controls
- [ ] Review state changes and their ordering
- [ ] Analyze edge cases and boundary conditions
- [ ] Test with malicious inputs and sequences

---

## Real-World Examples

### Example 1: H-1: Fixed Term Teller tokens can be created with an expiry in the past

**Source**: Sherlock
**Protocol**: Bond Protocol
**Impact**: HIGH

**Details**:

Source: https://github.com/sherlock-audit/2022-11-bond-judging/issues/34 

## Found by 
obront

## Summary

The Fixed Term Teller does not allow tokens to be created with a timestamp in the past. This is a fact that protocols using this feature will expect to hold and build their systems around. However, users can submit expiry timestamps slightly in the future, which correlate to tokenIds in the past, which allows them to bypass this check.

## Vulnerability Detail

In `BondFixedTermTeller.sol`, the `create()` function allows protocols to trade their payout tokens directly for bond tokens. The expectation is that protocols will build their own mechanisms around this. It is explicitly required that they cannot do this for bond tokens that expire in the past, only those that have yet to expire:

```solidity
if (expiry_ < block.timestamp) revert Teller_InvalidParams();
```

However, because tokenIds round timestamps down to the latest day, protocols are able to get around this check.

Here's an example:
- The most recently expired token has an expiration time of 1668524400 (correlates to 9am this morning)
- It is currently 1668546000 (3pm this afternoon)
- A protocol calls create() with an expiry of 1668546000 + 1
- This passes the check that `expiry_ >= block.timestamp`
- When the expiry is passed to `getTokenId()` it rounds the time down to the latest day, which is the day corresponding with 9am this morning
- This expiry associated with this tokenId is 9am this morning, so t

*[Content truncated...]*

---

### Example 2: M-2: Fixed Term Bond tokens can be minted with non-rounded expiry

**Source**: Sherlock
**Protocol**: Bond Protocol
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2022-11-bond-judging/issues/32 

## Found by 
obront

## Summary

Fixed Term Tellers intend to mint tokens that expire once per day, to consolidate liquidity and create a uniform experience. However, this rounding is not enforced on the external `deploy()` function, which allows for tokens expiring at unexpected times.

## Vulnerability Detail

In `BondFixedTermTeller.sol`, new tokenIds are deployed through the `_handlePayout()` function. The function calculates the expiry (rounded down to the nearest day), uses this expiry to create a tokenId, and if that tokenId doesn't yet exist deploys it.

```solidity
...
expiry = ((vesting_ + uint48(block.timestamp)) / uint48(1 days)) * uint48(1 days);

// Fixed-term user payout information is handled in BondTeller.
// Teller mints ERC-1155 bond tokens for user.
uint256 tokenId = getTokenId(payoutToken_, expiry);

// Create new bond token if it doesn't exist yet
if (!tokenMetadata[tokenId].active) {
    _deploy(tokenId, payoutToken_, expiry);
}
...
```
This successfully consolidates all liquidity into one daily tokenId, which expires (as expected) at the time included in the tokenId.

However, if the `deploy()` function is called directly, no such rounding occurs:

```solidity
function deploy(ERC20 underlying_, uint48 expiry_)
    external
    override
    nonReentrant
    returns (uint256)
{
    uint256 tokenId = getTokenId(underlying_, expiry_);
    // Only creates token if it does not exi

*[Content truncated...]*

---

### Example 3: M-2: `optionTokens` can be expired even though the epoch is not over

**Source**: Sherlock
**Protocol**: Bond Options
**Impact**: MEDIUM

**Details**:

Source: https://github.com/sherlock-audit/2023-06-bond-judging/issues/63 

## Found by 
BenRai, qandisa
## Summary

When deploying an `optionToken` the parameter `expiry` is rounded down to the nearest day at 0000 UTC but since the end of an epoch is calculated by the `epochDuration` and the exact time the epoch has stared and the `optionToken` was created this can lead to an epoch still being active but the corresponding `optionToken` to be already expired. 

## Vulnerability Detail

When starting a new epoch, the variable `epochStart` is set to the current time (`block.timestamp`) and the end of the epoch is calculated by adding the `epochDuration` to the `epochStart` variable. 

The `optionToken` of the new epoch is deployed with the parameter `expire` calculated based on the current time stamp, the `timeUntilEligible` and the `eligibleDuration`. (`uint48(block.timestamp) + timeUntilEligible + eligibleDuration`). The final expiration date of the optionToken is rounded down to the nearest day at 0000 UTC before the token is deployed.

Since the `epochDuration` can be as close as 1 second to the sum of `timeUntilEligible + eligibleDuration` this can lead to an epoch still being active but its `optionToken` to be already expired.

Example:

epochDuration = 7 days
timeUntilEligible = 0
eligibleDuration = 7 days + 12 hours


New epoch is launched on the 01.01.2024 at 11:45 am.

=>
epochStart = block.timestamp  = 01.01.2024 at 11:45 am
epochEnd = epochStart + epochDuration =

*[Content truncated...]*

---

## Statistics

- Total findings analyzed: 3
- Examples shown: 3
- Data source: Cyfrin Solodit (50,530 total findings)
- Last updated: 2026-01-29

