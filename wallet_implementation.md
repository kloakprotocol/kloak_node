# Wallet Implementation Flow (KPP v1)

This is the **exact step-by-step wallet flow** for integrating Kloak Payment Protocol (KPP) in any language.
KPP is a two-wallet protocol using a Kloak node only as a **matcher + relay**.

- The **node** matches sender/receiver by `session_id` and relays messages.
- The **wallets** build, sign, and broadcast the transaction.
- Wallet-to-wallet messages are end-to-end encrypted with a shared 32-byte key.

---

## Shared Primitives (Both Wallets)

### 1) E2EE key ownership
- **Receiver generates** `e2ee_key`: 32 random bytes (single-use).
- **Sender parses** `e2ee_key` from the payment request (QR/NFC).

### 2) Compute the session id
- `session_id = sha256(e2ee_key).hex()`
- This is what both wallets send to the node (the node never sees `e2ee_key`).

### 3) WebSocket endpoint
- Both wallets connect to the same node endpoint:
  - `ws://<host>:<port>/kpp` (or `wss://.../kpp`)

### 4) E2EE message encryption (wallet ↔ wallet)
- Algorithm: ChaCha20-Poly1305
- Nonce: 12 random bytes
- Plaintext: UTF-8 JSON
- AAD: none
- Wire format: `base64(nonce || ciphertext)` (a base64 string sent over the websocket)

---

## Receiver Wallet Flow (Creates the Payment Request)

1. Generate `e2ee_key` (32 bytes).
2. Compute `session_id = sha256(e2ee_key).hex()`.
3. Choose a node `ws_url` like `ws://node:8765/kpp`.
4. Create a payment request (QR/NFC):
   - Recommended: a `kaspa:` URI including `ws_url` and `e2ee_key` (base64url, no padding).
   - "kaspa:qqq&amount=1&ws_url=url&e2ee_key=key"
5. Connect to the node websocket at `ws_url`.
6. Send the plaintext handshake JSON:
   - `{ "role": "receiver", "session_id": "<session_id_hex>" }`
7. Send an E2EE-encrypted receiver payload containing:
   - `{ "utxo": <receiver_utxo>, "address_1": <recv_addr1>, "address_2": <recv_addr2>, "amount": <amount_kas> }`
8. Wait for an E2EE message from the sender (sender’s encrypted data). Decrypt it.
9. Wait for the E2EE transaction proposal:
   - `{ "type": "transaction", "tx": <tx_json>, "your_input_index": 1, "sender_input_index": 0 }`
10. Sign the transaction input at `your_input_index` (receiver signs input #1).
11. Send back an E2EE message:
   - `{ "type": "receiver_signature", "tx": <tx_with_receiver_signature> }`
12. Wait for the sender’s broadcast result (E2EE):
   - Success: `{ "type": "broadcast_success", "transaction_id": "<txid>" }`
   - Failure: `{ "type": "broadcast_error", "error": "<string>" }`

---

## Sender Wallet Flow (Pays After Scanning)

1. Parse the payment request and extract: `ws_url`, `e2ee_key`, `amount`.
2. Compute `session_id = sha256(e2ee_key).hex()`.
3. Select:
   - a sender UTXO
   - a sender change address
4. Connect to the node websocket at `ws_url`.
5. Send the plaintext handshake JSON:
   - `{ "role": "sender", "session_id": "<session_id_hex>" }`
6. Receive plaintext from the node:
   - `{ "type": "dust_address", "address": "kaspa:..." }`
7. Receive an E2EE message containing receiver data (node forwarded it). Decrypt it to get:
   - receiver contributed UTXO
   - receiver output addresses (2)
   - amount
8. Send an E2EE message with sender data:
   - `{ "utxo": <sender_utxo>, "change_address": <change_addr>, "amount": <amount_kas> }`
9. Construct the KPP transaction template:
   - Inputs: sender UTXO (input #0), receiver UTXO (input #1)
   - Outputs: receiver split outputs, sender change, node dust output to the received `dust_address`
10. Send the E2EE transaction proposal:
   - `{ "type": "transaction", "tx": <tx_json>, "your_input_index": 1, "sender_input_index": 0 }`
11. Receive the receiver signature response (E2EE):
   - `{ "type": "receiver_signature", "tx": <tx_with_receiver_signature> }`
12. Sign sender input #0.
13. Broadcast the fully signed transaction to the network.
14. Send receiver the broadcast result (E2EE):
   - Success: `{ "type": "broadcast_success", "transaction_id": "<txid>" }`
   - Failure: `{ "type": "broadcast_error", "error": "<string>" }`

---

## What the Node Does (Wallets Don’t Implement This)

- Matches sender + receiver connections by `session_id`.
- Sends the `dust_address` (plaintext) to the sender.
- Relays all other messages blindly (E2EE base64 strings) between wallets.

