# ChatDB design for Dash Core

## Purpose

This document describes a **dedicated ChatDB** design for storing wallet-scoped,
private person-to-person chat inside **Dash Core** rather than in an external
service.

The current wallet chat feature persists messages directly in the wallet
database under `chatmsg` and `chatsync` records and exposes them through the
wallet RPC `chat`. A dedicated ChatDB should preserve that user-facing behavior
while improving separation of concerns, queryability, migration safety, and
future support for richer message metadata and transport state.

## Goals

- Keep chat storage **inside Dash Core**.
- Keep chat storage **wallet-scoped** so each wallet owns its own conversations.
- Preserve support for **private messages between individuals**.
- Make records efficiently queryable by:
  - conversation
  - peer address
  - message id
  - created time
  - delivery state
- Support encrypted-at-rest payloads using the wallet master key.
- Enable forward-compatible schema upgrades and optional network delivery later.

## Non-goals

- This document does not define a P2P transport protocol for relaying chat over
  the Dash network.
- This document does not require chat messages to be consensus data.
- This document does not require chat content to be publicly replicated on
  chain.

## Why a dedicated ChatDB

The current wallet chat storage is intentionally minimal and works well for
wallet-local history and sync export/import. However, a dedicated ChatDB would
be a better long-term design because it:

- avoids growing the wallet DB with non-transaction records,
- allows multiple secondary indexes without overloading wallet keyspaces,
- makes migrations and corruption handling more targeted,
- separates chat history from spendable key material and wallet accounting, and
- creates a clear place for delivery receipts, tombstones, attachments, and
  message status metadata.

## Database placement

ChatDB should live **inside Dash Core's data model** but as a dedicated store.
The recommended on-disk location is:

- single-wallet: `<wallet_path>/chatdb/`
- multiwallet: `<wallet_path>/chatdb/`

This keeps chat history tied to the wallet that owns the relevant addresses,
while avoiding cross-wallet contamination.

Implementation recommendation:

- backend: `CDBWrapper`
- wrapper class: `CWalletChatDB`
- namespace: `wallet`

## High-level model

A chat system needs four categories of records:

1. **Conversation metadata**
2. **Message records**
3. **Indexes**
4. **Sync / delivery state**

### 1. Conversation metadata

A conversation is the stable container for messages exchanged with one peer or a
small participant set.

Recommended structure:

```cpp
struct CChatConversation
{
    uint256 conversation_id;
    std::string wallet_id;
    std::set<std::string> participants;
    bool direct_message{true};
    int64_t created_at{0};
    int64_t updated_at{0};
    uint64_t last_message_id{0};
    bool archived{false};
    bool muted{false};
    uint32_t version{1};
};
```

Notes:

- `conversation_id` should be deterministic for a direct-message conversation.
  A good default is a hash of a normalized participant set plus wallet scope.
- `participants` should initially contain two addresses for direct chat.
- `updated_at` should be rewritten whenever a new message is appended.

### 2. Message records

A message record should contain immutable message content plus mutable delivery
state.

Recommended structure:

```cpp
enum class ChatMessageDirection : uint8_t {
    INBOUND = 0,
    OUTBOUND = 1,
};

enum class ChatMessageState : uint8_t {
    PENDING = 0,
    SENT = 1,
    DELIVERED = 2,
    READ = 3,
    FAILED = 4,
    DELETED = 5,
};

struct CChatMessage
{
    uint64_t local_id{0};
    uint256 message_id;
    uint256 conversation_id;
    std::string sender;
    std::string recipient;
    ChatMessageDirection direction{ChatMessageDirection::OUTBOUND};
    ChatMessageState state{ChatMessageState::PENDING};
    int64_t created_at{0};
    int64_t updated_at{0};
    bool encrypted{true};
    std::vector<unsigned char> nonce;
    std::vector<unsigned char> payload;
    std::vector<unsigned char> metadata;
    std::optional<uint256> reply_to;
    uint32_t schema_version{1};
};
```

Notes:

- `local_id` is a monotonically increasing wallet-local sequence number used for
  efficient listing and pagination.
- `message_id` is a globally unique identifier for deduplication and sync.
- `payload` stores either encrypted message bytes or plaintext only for
  unencrypted wallets.
- `metadata` can later encode MIME type, attachment references, ephemeral TTL,
  or application-defined flags.

### 3. Indexes

Chat history becomes painful without secondary indexes. ChatDB should store
materialized indexes explicitly.

Recommended keys:

- message-by-local-id
- message-by-message-id
- conversation-by-id
- conversation-by-participant
- conversation-message-order index
- undelivered-message index
- unread-message index

### 4. Sync and delivery state

Recommended structure:

```cpp
struct CChatSyncState
{
    uint64_t last_local_id{0};
    int64_t last_sync_time{0};
    uint32_t format_version{1};
};
```

Optionally, per-conversation state:

```cpp
struct CChatConversationState
{
    uint256 conversation_id;
    uint64_t last_read_local_id{0};
    uint64_t unread_count{0};
    int64_t last_opened_at{0};
};
```

## Key schema

Use compact prefixed keyspaces so iteration remains efficient and explicit.

### Primary records

- `chatversion` -> `uint32_t`
- `chatmeta` -> `CChatSyncState`
- `chatconv:<conversation_id>` -> `CChatConversation`
- `chatmsgid:<message_id>` -> `CChatMessage`
- `chatmsglocal:<local_id>` -> `message_id`

### Secondary indexes

- `chatconvpeer:<normalized_peer_key>:<conversation_id>` -> null
- `chatconvmsg:<conversation_id>:<local_id>` -> `message_id`
- `chatpending:<local_id>` -> `message_id`
- `chatunread:<conversation_id>:<local_id>` -> `message_id`
- `chattime:<created_at>:<message_id>` -> null

### Tombstones and housekeeping

- `chattomb:<message_id>` -> deletion marker
- `chatexpires:<expiry_time>:<message_id>` -> null

## Record semantics

### Conversation record

A conversation is the canonical owner of participant and UI state. It should
not duplicate message bodies.

### Message record

A message record should be append-only for content. Mutable state transitions
should update `state` and `updated_at`, but should never rewrite the semantic
message body unless the change is a local redaction/tombstone operation.

### Pending and unread indexes

These exist for speed, not as source of truth. They should be regenerated from
primary records during repair if necessary.

## Encryption model

Private chat messages should be unreadable at rest whenever the wallet is
encrypted.

Recommended model:

- Use the wallet master key to encrypt `payload`.
- Derive IV/nonce material from stable message identifiers, for example from
  `conversation_id || local_id || message_id`.
- Keep only encrypted bytes in `payload` for encrypted wallets.
- Leave `sender`, `recipient`, `timestamps`, and delivery state unencrypted so
  the wallet can list conversations while locked.

Important tradeoff:

- leaving routing metadata unencrypted supports UX and indexing,
- but conversation metadata still leaks communication patterns locally.

If stronger local privacy is desired later, a second design phase can encrypt
participant metadata and maintain a minimal encrypted index cache only while the
wallet is unlocked.

## Creation and lookup flow

### Sending a message

1. Resolve or create a direct-message conversation.
2. Increment `last_local_id` in `CChatSyncState`.
3. Construct `CChatMessage`.
4. Encrypt payload if wallet encryption is enabled.
5. Write the primary message record.
6. Write/update indexes.
7. Update conversation `last_message_id` and `updated_at`.
8. Optionally queue transport delivery.

### Receiving a message

1. Resolve conversation by participants or explicit conversation id.
2. Deduplicate by `message_id`.
3. Persist the message.
4. Mark as unread if inbound.
5. Update conversation metadata.

### Listing a conversation

1. Load `chatconvmsg:<conversation_id>:*` index range.
2. Resolve each `message_id`.
3. Read `chatmsgid:<message_id>` records.
4. Decrypt payloads if wallet is unlocked; otherwise return locked placeholders.

## Migration from current wallet chat records

Current wallet chat uses:

- `chatmsg` for persisted `CWalletChatMessage`
- `chatsync` for `CWalletChatSyncState`

Migration path:

1. On wallet open, detect legacy `chatmsg` / `chatsync` keys.
2. Create ChatDB if absent.
3. Group legacy records by `peer_address` into one direct-message conversation
   per peer.
4. Convert each legacy message:
   - `id` -> `local_id`
   - derive `message_id`
   - map `peer_address` into `sender` / `recipient`
   - preserve `created_at`, `encrypted`, and `payload`
5. Write `chatconv`, `chatmsgid`, `chatmsglocal`, and `chatconvmsg` records.
6. Mark migration complete with `chatversion`.
7. Stop writing new `chatmsg` / `chatsync` records once migration succeeds.

## RPC surface

The existing wallet RPC shape is a good starting point and should be preserved
for compatibility:

- `chat message <address> <message>`
- `chat list [address]`
- `chat syncstatus`
- `chat syncexport`
- `chat syncimport <hex_blob>`

Recommended extensions:

- `chat conversations`
- `chat getconversation <conversation_id>`
- `chat markread <conversation_id> [local_id]`
- `chat delete <message_id>`
- `chat resend <message_id>`
- `chat exportconversation <conversation_id>`

## Sync format

Sync export/import should use a versioned envelope instead of raw serialized map
state only.

Recommended format:

```cpp
struct CChatSyncEnvelope
{
    uint32_t version{1};
    CChatSyncState state;
    std::vector<CChatConversation> conversations;
    std::vector<CChatMessage> messages;
};
```

This makes imports less ambiguous and more future-proof.

## Failure handling

ChatDB should support targeted recovery without endangering wallet funds.

Recommended behavior:

- if ChatDB fails to open, wallet open should continue with chat disabled,
- if a write fails, return an RPC error but do not affect balance/accounting,
- add a `chat repair` or `-salvagechat` flow later if needed,
- rebuild secondary indexes from primary records when possible.

## Retention and pruning

Suggested defaults:

- keep messages indefinitely unless the user deletes them,
- support future optional retention policies per conversation,
- use tombstones rather than hard deletes when sync correctness matters.

## Why this is better than the current minimal schema

The current wallet chat schema stores only:

- `id`
- `peer_address`
- `direction`
- `created_at`
- `encrypted`
- `payload`
- plus global sync state

That is good enough for basic wallet-local history, but a dedicated ChatDB gives
Dash Core a cleaner long-term foundation for:

- unread counts,
- delivery state,
- per-conversation history,
- pagination,
- deduplication,
- imports/exports,
- deletion/tombstones,
- and future transport integration.

## Recommended implementation phases

### Phase 1

- Keep the current `chat` RPC contract.
- Introduce `CWalletChatDB` as a dedicated `CDBWrapper` store.
- Migrate legacy wallet chat keys into ChatDB.
- Add conversation and message primary/index records.

### Phase 2

- Add unread and pending indexes.
- Add richer RPCs for conversation listing and read tracking.
- Add repair/reindex support.

### Phase 3

- Add optional transport queue and delivery receipts.
- Add attachment metadata.
- Add retention/expiration policy handling.

## Recommendation

If the goal is **private chat between individuals inside Dash Core**, then the
right design is **not** to leave chat data floating in ad hoc wallet records
forever. The proper design is a dedicated, wallet-scoped **ChatDB** inside Dash
Core with:

- a conversation table,
- a message table,
- explicit secondary indexes,
- wallet-key encryption at rest,
- migration from the current wallet chat records,
- and RPC compatibility with the existing `chat` commands.
