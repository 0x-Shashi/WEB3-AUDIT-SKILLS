# Aztec Vulnerability Patterns

## Critical
- **Privacy leak**: Private data exposed through public state or events
- **Nullifier collision**: Two different notes produce same nullifier
- **Double spend**: Note consumed without proper nullifier emission

## High
- **Public/private desync**: Public state doesn't match private state
- **Oracle manipulation**: Private oracle returns incorrect data
- **Access control**: Private function callable by unauthorized party

## Medium
- **Note discovery**: Notes not properly encrypted for recipient
- **Gas estimation**: Private functions underestimate gas
- **Circuit constraints**: Missing constraints allow invalid proofs

## Aztec Checklist
- [ ] Private state properly encrypted
- [ ] Nullifiers unique and collision-resistant
- [ ] Public/private state transitions consistent
- [ ] Oracle callbacks validated
- [ ] Circuit constraints complete (no under-constrained circuits)
- [ ] Note lifecycle (create, read, destroy) correct
