# Kloak Payment Protocol Node

> "liberty, when it begins to take root, is a plant of rapid growth"

## Quick Start (Windows)

1. **Download** the latest release ZIP
2. **Extract** to any folder
3. **Double-click** `install_kloak.bat` (one-time setup)
4. Build the EXE: `python build_exe.py`
5. Run: `run_kloak.bat` (recommended)

If you prefer, you can also run the EXE directly: `dist\KloakNode.exe`

That's it! The node will start running on your machine.

## Recommended: Build Your Own EXE (No Signing Needed)

If you want to avoid Windows SmartScreen/code-signing headaches, the simplest approach is:
clone/download this repo and build the executable locally.

### Steps

1. Install Python (recommended: 3.11 or 3.12)
2. Open a terminal in this folder
3. Run the installer (creates `.venv` and installs deps):

```bat
install_kloak.bat
```

4. Build the standalone EXE (PyInstaller):

```bat
python build_exe.py
```

By default, `build_exe.py` builds a **one-file** EXE (no prompt). The output will be:

- `dist\KloakNode.exe`

To choose build mode interactively:

```bat
python build_exe.py --interactive
```

### What are the .bat files for?

- `install_kloak.bat`: sets up a local venv + installs dependencies for running from source and/or building.
- `run_kloak.bat`: launches `dist\KloakNode.exe` in a console window (and pauses if it exits).

## Overview

Kloak is a novel fungibility layer built on Kaspa - a decentralized, non-custodial payjoin coordinator that transforms regular payments into privacy-enhanced transactions.

## Features

✅ **Full Wallet Implementation**
- 12-word BIP39 mnemonic generation
- BIP32 hierarchical deterministic derivation
- Kaspa bech32 address encoding (Kaspa PubKey addresses)
- Encrypted wallet storage (Scrypt + ChaCha20-Poly1305)

✅ **Wallet Integration Helpers (for external wallets)**
- Single-call receiver flow: `receiver_initiate_kpp()`
- Single-call sender flow: `sender_prepare_kpp_transaction()`
- Kaspa-URI QR format: `kpp_payment_uri()` + `parse_kpp_payment_request()`

✅ **Complete RPC Integration**
- Connected to Kaspa network via kaspy
- Balance queries and UTXO management
- Transaction construction and broadcasting

✅ **WebSocket Server**
- End-to-end encrypted handshakes (ChaCha20-Poly1305)
- Coordinated 2-in, 4-out payjoin transactions
- Real-time sender/receiver coordination

✅ **Node Operations**
- Periodic pulse mechanism for node discovery
- Dust collection revenue model
- Automated wallet management

✅ **Operator Console**
- Text-based commands while node runs (`help`, `status`, `pulse`, `sweep`, etc.)

## Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Run the node
python kloak_node.py
```

## Quick Start

### 1. Create a Wallet

```
1. Create new wallet
Enter encryption passphrase: ****
```

**⚠️ IMPORTANT:** Write down your 12-word recovery phrase!

### 2. Fund the Node

```
4. Get funding address
💰 Send KAS to: kaspa:xxxxx...
```

Send at least the configured reserve amount (default: 2 KAS) to cover pulse transaction fees.

### 3. Start the Node

```
6. Start node (server + pulse)
🚀 Starting Kloak Node...
WebSocket server will run on port 8765
```

## Architecture

### Transaction Flow

**Standard Kaspa Transaction:**
```
1 input → 2 outputs (recipient + change)
```

**Kloak Transaction:**
```
2 inputs  → 4 outputs (2 receiver addrs + sender change + dust)
```

### Privacy Features

1. **Amount Obfuscation**: Receiver amount split randomly between 2 addresses
2. **Dust Collection**: Amounts rounded to 0.1 KAS, remainder goes to node
3. **No Round Numbers**: Breaks chain analysis heuristics
4. **Indistinguishable**: Looks like wallet consolidation or batched transactions

### E2EE Handshake

Important: the node is a **blind relay**.

- The node never receives the `e2ee_key` and cannot decrypt wallet payloads.
- Wallets derive `session_id = SHA256(e2ee_key)` and send only `session_id` to the node for pairing.

Flow:

1. Receiver connects to node and sends `role=receiver` + `session_id` (plaintext)
2. Receiver sends an encrypted blob (UTXO + 2 addresses + amount)
3. Receiver shows a **Kaspa URI QR** containing `ws_url` + `e2ee_key`
4. Sender scans QR, derives the same `session_id`, connects, and receives:
    - a fresh dust address (plaintext)
    - the receiver encrypted blob (forwarded as-is)
5. Sender builds the 2-in/4-out transaction locally and sends it to receiver (encrypted)
6. Receiver signs its input and returns the partially-signed transaction (encrypted)
7. Sender signs its input, broadcasts, and notifies receiver of the txid (encrypted)

## Configuration

You can still edit `CONFIG` in the script, but runtime overrides are supported:

- CLI: `--ws-port`, `--ws-bind`, `--wallet-file`, `--cli`
- CLI: `--ws-port`, `--ws-bind`, `--wallet-file`
- Env: `KLOAK_WS_PORT`, `KLOAK_WS_BIND`, `KLOAK_WALLET_FILE`

```python
CONFIG = {
    "PULSE_INTERVAL_SECONDS": 21600,  # 6 hours
    "FUND_AMOUNT_KAS": 5,             # Reserve for fees
    "KASPA_NODE": "seeder1.kaspad.net",
    "KASPA_RPC_PORT": 16110,
    "WEBSOCKET_PORT": 8765,
}
```

## Node Discovery

Kloak nodes advertise themselves by broadcasting "pulse" transactions periodically. Wallets discover nodes by:

1. Scanning recent blocks for pulse transactions
2. Extracting node metadata (WebSocket URL)
3. Pinging top 3 most recent nodes
4. Selecting lowest-latency node

## Security

- **Non-custodial**: Node never holds private keys
- **E2EE**: All coordination encrypted with ChaCha20-Poly1305
- **Trustless**: Both parties must sign; node can't steal funds
- **Privacy**: True amounts and participants hidden on-chain

## Revenue Model

Nodes earn "dust" from each transaction:
- Amount rounded to nearest 0.1 KAS
- Remainder (typically 0.01-0.09 KAS) sent to node
- Incentivizes high-uptime, low-latency nodes
- No setup fees or subscriptions

## Operator Commands (Text, While Node Runs)

These are separate from the numbered startup menu above. When the node is running, you can type commands into the console (type `help` to see them):

| Command | Description |
|---------|-------------|
| `help` | Show available operator commands |
| `pulse` | Trigger an immediate pulse |
| `sweep <address>` | Drain all funds to address (keeps minimum reserve) |
| `status` | Show node + wallet status |
| `balance` | Show wallet balance summary |
| `fundaddr` | Show the current funding address (+ funding QR if available) |

Stop the node with **Ctrl+C**.

## Wallet Integration

To integrate Kloak into your Kaspa wallet, use the **single-call** helper APIs.

KPP request format (QR): a Kaspa URI string produced by `kpp_payment_uri()`:

`kaspa:<address>?amount=...&payload=...&ws_url=...&e2ee_key=...`

### Receiver Side

```python
from kloak_node import (
    ReceiverWalletAPI,
    set_receiver_wallet_api,
    receiver_initiate_kpp,
    receiver_sign_and_return,
)

class MyReceiverWallet(ReceiverWalletAPI):
    def select_utxo(self, amount_kas=None) -> dict:
        return pick_contributed_utxo_somehow(amount_kas)

set_receiver_wallet_api(MyReceiverWallet())

# 1) Receiver generates a QR URI and connects to the node.
init = await receiver_initiate_kpp(
    addr1="kaspa:recv_addr_1",
    addr2="kaspa:recv_addr_2",
    amount=10.5,
    ws_url="ws://node.example.com:8765/kpp",
    payload="",
)

qr_uri = init["qr_uri"]

# 2) Show qr_uri as a QR code. Keep init["result"] for signing.

# 3) When the sender sends the tx, sign input #1 and return it.
signed = await receiver_sign_and_return(init["result"], private_key=my_privkey)
```

### Sender Side

```python
from kloak_node import (
    SenderWalletAPI,
    set_sender_wallet_api,
    sender_prepare_kpp_transaction,
    parse_kpp_payment_request,
    sign_kaspa_transaction_input,
    broadcast_transaction,
    get_utxo_script_pubkey,
)

class MySenderWallet(SenderWalletAPI):
    def select_utxo(self, amount_kas: float) -> dict:
        return pick_sender_utxo_somehow(amount_kas)

    def get_change_address(self) -> str:
        return new_change_address()

set_sender_wallet_api(MySenderWallet())

qr_uri = scan_qr_code()
req = parse_kpp_payment_request(qr_uri)

prep = await sender_prepare_kpp_transaction(
    amount=req["amount"],
    ws_url=req["ws_url"],
    e2ee_key=req["e2ee_key"],
)

# Receiver already signed input #1; sender signs input #0, then broadcasts.
tx = prep["transaction"]
sender_utxo = prep["sender_utxo"]
spk_version, script_pubkey = get_utxo_script_pubkey(sender_utxo)
tx = sign_kaspa_transaction_input(
    tx,
    input_index=prep["sender_input_index"],
    private_key=my_sender_privkey,
    utxo_amount=int(sender_utxo["utxoEntry"]["amount"]),
    script_pubkey=script_pubkey,
    script_pubkey_version=spk_version,
)

txid = broadcast_transaction(rpc_client, tx)
await prep["finalize"](transaction_id=txid, error=None if txid else "broadcast_failed")
```

## Technical Details

### Cryptography

- **Mnemonic**: BIP39 (128-bit entropy = 12 words)
- **Key Derivation**: BIP32-style with Blake2b
- **Address Encoding**: Kaspa format with Blake2b checksums
- **Wallet Encryption**: Scrypt KDF + ChaCha20-Poly1305
- **E2EE**: ChaCha20-Poly1305 AEAD

### Network

- **RPC Client**: `kaspy` JSON/protobuf RPC client (talks to kaspad)
- **WebSocket**: Async with websockets library
- **Serialization**: JSON for application data
- **Encoding**: Base64 for binary data in JSON

## Limitations & Disclaimers

⚠️ **This is a proof-of-concept implementation:**

1. **Not Production-Ready**: Requires extensive testing and auditing
2. **Fee estimation is approximate**: wallets should provide their own fee policy
3. **UTXO selection is minimal**: real wallets should do robust selection/locking
4. **Basic UTXO Handling**: Real implementation needs better UTXO selection
5. **Node discovery scanning can be expensive**: consider caching / limiting block scan

**DO NOT USE WITH REAL FUNDS WITHOUT THOROUGH SECURITY AUDIT**

## Development Status

- [x] Wallet creation with BIP39
- [x] Encrypted storage
- [x] RPC client integration
- [x] WebSocket server
- [x] E2EE handshake
- [x] Transaction construction
- [x] CLI interface
- [x] Node pulse mechanism
- [ ] UTXO selection algorithm
- [ ] Fee estimation
- [ ] Node discovery on-chain
- [ ] Production-grade crypto

## License

Open source - free forever

## Philosophy

> "kloak is, and will forever be, open-source software, written for no other purpose than the good of humanity and in defense of the right to individual security, and as protection against violations of freedom by those seeking to control, surveil, oppress, and steal"

