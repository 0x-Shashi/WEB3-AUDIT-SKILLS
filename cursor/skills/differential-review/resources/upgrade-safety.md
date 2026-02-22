# Upgrade Safety Guide

## Storage Layout Compatibility
- New variables MUST be appended (not inserted)
- Existing variable types MUST NOT change
- Existing variable order MUST NOT change
- Gaps/reserved slots for future use are best practice

## Proxy Upgrade Checks
- [ ] Storage layout compatible (no slot collisions)
- [ ] Initializer cannot be re-called
- [ ] New implementation has no selfdestruct
- [ ] Function selectors don't collide
- [ ] New dependencies compatible with existing storage
- [ ] State migration logic tested

## Dependency Update Checks
- [ ] OpenZeppelin version change: review changelog for breaking changes
- [ ] Solidity compiler upgrade: check for behavior changes
- [ ] External protocol updates: verify interface compatibility
