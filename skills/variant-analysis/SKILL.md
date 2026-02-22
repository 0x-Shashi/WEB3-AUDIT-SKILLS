# Variant Analysis Skill

## Purpose
Find instances of known vulnerability patterns across a codebase. When one bug is found, systematically search for all variants of the same class.

## Core Concept
If you find one instance of a bug pattern, there are likely more. Variant analysis turns a single finding into comprehensive coverage by:
1. Abstracting the bug to its root pattern
2. Searching the entire codebase for similar patterns
3. Checking historical exploits for the same pattern class

## Variant Sources
- Current audit findings (found one? find them all)
- Historical exploit databases (Rekt, DeFiHackLabs)
- Cyfrin findings database
- Solodit patterns
- Known CVEs in dependencies

## Process
1. **Abstract**: Reduce the found bug to its essential pattern
2. **Search**: Grep/AST-search for all instances of the pattern
3. **Validate**: Confirm each instance is actually vulnerable
4. **Expand**: Check for related patterns (same root cause, different manifestation)
5. **Cross-Contract**: Check if the pattern exists in other contracts/modules

## Workflows
- [Variant Hunt](workflows/variant-hunt.md)
