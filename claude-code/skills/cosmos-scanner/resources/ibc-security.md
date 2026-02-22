# IBC Security Guide

## IBC Packet Validation
- Always validate `packet.source_port` and `packet.source_channel`
- Verify counterparty chain identity through connection/client
- Check packet data format and version compatibility
- Handle timeout packets correctly (refund/revert state)

## Common IBC Vulnerabilities
1. **Unvalidated packet source**: Processing packets from unknown channels
2. **Timeout mishandling**: Not refunding users on packet timeout
3. **Channel ordering**: Using ORDERED when UNORDERED appropriate (or vice versa)
4. **Middleware bugs**: IBC middleware intercepting/modifying packets incorrectly
5. **Light client attacks**: Forged proofs from compromised light client

## IBC Checklist
- [ ] OnRecvPacket validates source port and channel
- [ ] OnTimeoutPacket properly refunds/reverts
- [ ] OnAcknowledgementPacket handles success and failure
- [ ] Channel ordering matches protocol requirements
- [ ] Middleware chain correctly ordered
- [ ] Relayer cannot profit from reordering
