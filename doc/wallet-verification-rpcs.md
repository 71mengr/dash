# Wallet verification and ownership RPCs

This document summarizes the wallet verification and ownership-proof RPC commands recently added to Dash Core, along with practical CLI examples.

> All commands below assume a wallet is loaded and `-rpcwallet=<wallet_name>` is provided.

## 1) Configure and run KYC verification

### `setkycprovider`
Configure which KYC backend the wallet should use.

```bash
dash-cli -rpcwallet=mywallet setkycprovider local-verification
```

With provider credentials:

```bash
dash-cli -rpcwallet=mywallet setkycprovider didit "<api_key>" "<workflow_id>"
```

### `startkyc`
Start a provider KYC session.

```bash
dash-cli -rpcwallet=mywallet startkyc basic
```

### `checkkyc`
Check the status of a previously started session.

```bash
dash-cli -rpcwallet=mywallet checkkyc "<session_id>"
```

### `completekyc`
Complete a provider session and attempt to finalize verification.

```bash
dash-cli -rpcwallet=mywallet completekyc "<session_id>"
```

### `importkyccredential`
Import a provider-issued credential blob (JWT/VC JSON) into the wallet.

```bash
dash-cli -rpcwallet=mywallet importkyccredential "<jwt-or-vc-json>"
```

Attach to an explicit provider session:

```bash
dash-cli -rpcwallet=mywallet importkyccredential "<jwt-or-vc-json>" "<session_id>"
```

### `local-verify`
Run built-in local verification flow (no external KYC provider call required).

```bash
dash-cli -rpcwallet=mywallet local-verify "Ada Lovelace" 36 "United Kingdom"
```

---

## 2) Wallet credential management

### `importcredential`
Import a trusted, verified credential directly.

```bash
dash-cli -rpcwallet=mywallet importcredential "<credential_jwt>"
```

With explicit issuer override/check:

```bash
dash-cli -rpcwallet=mywallet importcredential "<credential_jwt>" "coinfirm"
```

### `getwalletcredential`
Return the currently stored credential state and metadata.

```bash
dash-cli -rpcwallet=mywallet getwalletcredential
```

### `setwalletcredential` (testing only)
Create/set a test credential in mockable test-chain environments.

```bash
dash-cli -rpcwallet=mywallet setwalletcredential basic
```

With custom issuer and expiry days:

```bash
dash-cli -rpcwallet=mywallet setwalletcredential full "test-issuer" 90
```

> `setwalletcredential` is restricted to mockable test chains and is not for production use.

---

## 3) Ownership confirmation and proof exchange

### `confirmownership`
Local wallet check: confirm that a given credential hash belongs to the currently loaded wallet.

```bash
dash-cli -rpcwallet=mywallet confirmownership "<credential_hash>"
```

Use this for local introspection. For third-party verification, use challenge-bound proofs (`generateownershipproof` / `verifyownershipproof`).

### `generateownershipproof`
Generate a selective-disclosure ownership proof bound to a verifier challenge.

```bash
dash-cli -rpcwallet=mywallet generateownershipproof '{
  "challenge": "nonce-123",
  "requested_claims": ["full_name", "country", "age_over_18"],
  "subject_address": "<wallet_address>"
}'
```

Optional recipient key hint (for transport/encryption workflows):

```bash
dash-cli -rpcwallet=mywallet generateownershipproof '{
  "challenge": "nonce-123",
  "requested_claims": ["wallet_address"],
  "subject_address": "<wallet_address>",
  "recipient_pubkey": "<recipient_pubkey>"
}'
```

Supported claim names:

- `full_name`
- `country`
- `age`
- `age_over_18`
- `age_band`
- `wallet_address`

### `verifyownershipproof`
Verify a proof blob created by `generateownershipproof`.

```bash
dash-cli verifyownershipproof "<proof_blob_returned_by_generateownershipproof>"
```

A successful response includes `valid=true` plus normalized claims and proof metadata (issuer/challenge/expiry/subject address).

---

## 4) Typical end-to-end flows

### A) Provider KYC flow
1. `setkycprovider`
2. `startkyc`
3. `checkkyc` (poll as needed)
4. `completekyc` or `importkyccredential`
5. `getwalletcredential`
6. Optionally `generateownershipproof` for external verification

### B) Local verification + proof flow
1. `local-verify`
2. `getwalletcredential`
3. `generateownershipproof`
4. Verifier calls `verifyownershipproof`

### C) Local wallet ownership check by hash
1. `getwalletcredential` (extract `credential_hash`)
2. `confirmownership <credential_hash>`

