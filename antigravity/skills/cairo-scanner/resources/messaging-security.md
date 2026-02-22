# L1-L2 Messaging Security

## L1 to Starknet
- Messages sent via `StarknetCore.sendMessageToL2()` on Ethereum
- Consumed on Starknet via `l1_handler` functions
- Must validate: message sender, source chain, nonce

## Starknet to L1
- Messages sent via `send_message_to_l1_syscall`
- Consumed on L1 after proof verification
- Must check: message not already consumed, correct format

## Security Checklist
- [ ] L1 handler validates msg sender address
- [ ] Message nonce prevents replay
- [ ] Message hash includes all relevant fields
- [ ] Proof finalization waited before L1 consumption
- [ ] Error handling for failed message consumption
