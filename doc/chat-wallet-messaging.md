# Wallet chat storage and sync

The wallet RPC now exposes a `chat` command for storing wallet-scoped chat history:

- `dash-cli -rpcwallet=<wallet> chat message <address> "<text>"`
- `dash-cli -rpcwallet=<wallet> chat list [address]`
- `dash-cli -rpcwallet=<wallet> chat syncstatus`
- `dash-cli -rpcwallet=<wallet> chat syncexport`
- `dash-cli -rpcwallet=<wallet> chat syncimport <hex_blob>`

## Security model

- Messages are stored inside the wallet database under dedicated chat records.
- If the wallet is encrypted and unlocked, message bodies are encrypted at rest with the wallet master key before being written to disk.
- If the wallet is locked, encrypted messages remain unreadable until the wallet is unlocked again.
- Sync export returns the serialized wallet chat records as a hex blob. This is intended for syncing cloned copies of the same wallet data. Encrypted payloads require the same wallet master key to be readable after import.

## Important limitations

- This change provides secure wallet-local persistence and backup/sync serialization, but it does not yet broadcast messages over the Dash network.
- End-to-end transport encryption with a remote counterparty address is not implemented in this patch; current encryption covers wallet storage at rest.
