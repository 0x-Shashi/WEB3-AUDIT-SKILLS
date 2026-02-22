# Fuel Scanner Skill

## Purpose
Analyze Fuel Network smart contracts written in Sway for security vulnerabilities.

## Detection Capabilities
- UTXO model vulnerabilities
- Predicate logic errors
- Script/contract interaction issues
- Asset handling (native multi-asset)
- Access control in Sway contracts
- Storage management issues

## Resources
- [Fuel Patterns](resources/fuel-patterns.md)

## Workflows
- [Fuel Audit](workflows/fuel-audit.md)

## Overview
Fuel is a modular execution layer with:
- Sway language (Rust-inspired)
- UTXO-based model (not account-based)
- FuelVM (not EVM)
- Native multi-asset support
- Predicates (stateless UTXO conditions)
