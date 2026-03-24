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

## Network delivery and security

- `chat message <address> "<text>" "<shared_secret>"` stores the outbound wallet record and relays an encrypted network packet to connected peers.
- `chat networkinbox <address> "<shared_secret>"` consumes pending inbound packets for the recipient address and verifies/decrypts them.
- Network payload confidentiality/integrity is provided through shared-secret encryption plus MAC verification in the wallet RPC layer.
- Receivers send a network ACK (`wchatack`) for each valid inbound packet, and senders keep a bounded retry queue until ACK arrives.

## Important limitations

- Retry is opportunistic and driven by wallet chat RPC activity (send/inbox polling), not by a dedicated background scheduler.
- The shared secret must be exchanged out-of-band by participants and rotated by application policy.

## Design note

For a longer-term dedicated ChatDB design inside Dash Core, see [doc/design/chatdb.md](design/chatdb.md).
