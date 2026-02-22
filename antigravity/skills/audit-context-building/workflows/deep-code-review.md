# Deep Code Review Workflow

## Per-Function Analysis
For each external/public function:
1. **Access**: Who can call this? (modifier, require)
2. **Parameters**: What inputs are accepted? Validated?
3. **State Changes**: What storage is modified?
4. **External Calls**: What external contracts are called?
5. **Return Values**: What is returned? Checked by callers?
6. **Events**: What events are emitted?
7. **Reentrancy**: Can this be re-entered? Is it guarded?
8. **Edge Cases**: What happens with 0, max, or unusual inputs?

## Priority Order
1. Functions that move tokens/ETH
2. Functions that modify access control
3. Functions that interact with oracles
4. Functions that modify protocol parameters
5. View/pure functions (lowest priority)
