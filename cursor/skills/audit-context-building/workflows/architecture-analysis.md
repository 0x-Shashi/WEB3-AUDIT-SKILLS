# Architecture Analysis Workflow

## Steps
1. **Contract Inventory**: List all .sol/.rs/.cairo files with line counts
2. **Inheritance Tree**: Map is/extends relationships
3. **Interface Analysis**: List all external interfaces and their implementations
4. **Dependency Audit**: Check versions of imported libraries
5. **Storage Layout**: Map storage slots (especially for upgradeable contracts)
6. **Event Analysis**: List all events and their emission points
7. **External Call Map**: List all cross-contract calls and their targets
8. **Diagram Output**: Generate contract interaction diagram

## Output Format
```
Contract A (upgradeable proxy)
  ├── inherits: OpenZeppelin Ownable2Step
  ├── uses: Chainlink AggregatorV3Interface
  ├── calls: Contract B.deposit()
  ├── calls: Contract C.getPrice()
  └── emits: Deposit(address,uint256)
```
