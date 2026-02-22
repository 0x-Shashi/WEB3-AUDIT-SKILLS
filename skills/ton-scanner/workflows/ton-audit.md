# TON Audit Workflow

## Steps
1. **Contract Structure**: Map internal/external message handlers
2. **Message Flow**: Trace all message chains between contracts
3. **Gas Analysis**: Verify sufficient gas forwarded in each message hop
4. **Bounce Handling**: Check all receivers handle bounced messages
5. **Storage Analysis**: Estimate storage growth and fee impact
6. **Replay Protection**: Verify seqno or nonce mechanisms
7. **Serialization**: Check cell packing doesn't exceed limits
8. **Sharding**: Consider message ordering across shards
9. **Workchain**: Validate workchain IDs in address handling
10. **Report**: Document findings with TON-specific context
