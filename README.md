# Kloak Payment Protocol Node

> "liberty, when it begins to take root, is a plant of rapid growth"

## Quick Start (Windows)

1. Install Python (recommended: 3.11 or 3.12)
2. Clone/download this repo
3. **Double-click** `install_kloak.bat` (one-time setup)
4. Build the EXE: `python build_exe.py`
5. Run: `run_kloak.bat` (recommended)

You can also run the built EXE directly: `dist\KloakNode.exe`

That's it! The node will start running on your machine.

## Networking (Port Forwarding)

If you want wallets on the **public internet** to connect to your node, you must make your WebSocket port reachable (default: TCP `8765`).

- **Same PC (localhost)**: no port forwarding needed.
- **Same home LAN/Wi-Fi**: usually only **Windows Firewall** inbound allow for TCP `8765`.
- **Public node (anyone can connect)**: you typically need **both**:
    - Windows Firewall: allow inbound TCP `8765` to the node machine
    - Router/NAT: port-forward `8765` from WAN → your node machine’s LAN IP

If you’re behind **CGNAT**, router port forwarding won’t work; you’ll need a VPS/tunnel/reverse-proxy approach.

### What are the .bat files for?

- `install_kloak.bat`: sets up a local venv + installs dependencies for running from source and/or building.
- `run_kloak.bat`: launches `dist\KloakNode.exe` in a console window (and pauses if it exits).

## Overview

Kloak is a novel fungibility layer built on Kaspa - a decentralized, censorship resistant, non-custodial payjoin coordinator that transforms regular payments into privacy-enhanced transactions.

## Features

**Wallet Implementation**
- 12-word BIP39 mnemonic generation
- BIP32 hierarchical deterministic derivation
- Encrypted wallet storage (Scrypt + ChaCha20-Poly1305)

**Wallet Integration Helpers (for external wallets)**
- Single-call receiver flow: `receiver_initiate_kpp()`
- Single-call sender flow: `sender_prepare_kpp_transaction()`
- Kaspa-URI QR format: `kpp_payment_uri()` + `parse_kpp_payment_request()`

**Complete RPC Integration**
- Connected to Kaspa network via kaspy (python kaspa library)
- Balance queries and UTXO management
- Transaction construction and broadcasting

**WebSocket Server**
- End-to-end encrypted handshakes (ChaCha20-Poly1305)
- Coordinated 2-in, 4-out payjoin transactions
- Real-time sender/receiver coordination

**Node Operations**
- Periodic kaspa network pulse mechanism for node discovery
- Dust collection revenue model
- Automated wallet management

**Operator Console**
- Text-based commands while node runs (`help`, `status`, `pulse`, `sweep`, etc.)

## Installation

Everyone who runs a node builds it locally.

Recommended (Windows):

```bat
install_kloak.bat
python build_exe.py
run_kloak.bat
```

Alternative (manual):

```bat
python -m venv .venv
call .venv\Scripts\activate.bat
pip install -r requirements.txt
python build_exe.py
run_kloak.bat
```

First run will prompt you to create/load an encrypted wallet and will show a funding address/QR.

To run from source instead of the EXE:

```bat
call .venv\Scripts\activate.bat
python kloak_node.py
```

## Architecture

### Transaction Flow

**Standard Kaspa Transaction:**
```
1 input → 2 outputs (recipient + change)
```

**Kloak Transaction:**
```
2 inputs → 4 outputs (2 receiver addrs + sender change + dust)
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

- CLI: `--ws-port`, `--ws-bind`, `--wallet-file`
- Env: `KLOAK_WS_PORT`, `KLOAK_WS_BIND`, `KLOAK_WALLET_FILE`

## Node Discovery

Kloak nodes advertise themselves by broadcasting "pulse" transactions periodically. Wallets discover nodes by:

1. Scanning recent blocks for pulse transactions
2. Extracting node payload data and converting it from hex to json string
3. Kloak node pulse transactions will have specific data attached
4. Pinging top 3 most recently pulsed nodes
5. Selecting lowest-latency node of the 3

## Security

- **Non-custodial**: Node never holds sender and receiver keys
- **E2EE**: All coordination encrypted with ChaCha20-Poly1305
- **Trustless**: Both parties must sign; node cannot touch funds
- **Privacy**: True amounts and participants completely hidden on-chain

## Revenue Model

Nodes earn "dust" from each transaction:
- Amount rounded to nearest 0.1 KAS
- Remainder (typically 0.01-0.09 KAS) sent to node
- Incentivizes high-uptime, low-latency nodes
- No setup fees or subscriptions

## Operator Commands (Text, While Node Runs)

When the node is running, you can type commands into the console (type `help` to see them):

| Command | Description |
|---------|-------------|
| `help` | Show available operator commands |
| `pulse` | Trigger an immediate pulse |
| `sweep <address>` | Sweep all wallet UTXOs to address (keeps minimum reserve as change to a newly derived internal address) |
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

# 3) When the sender sends the tx, receiver signs input #1 and return it.
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

1. **Not Fully Production-Ready**: Requires extensive testing and auditing
2. **Fee estimation is approximate**: wallets should provide their own fee policy
3. **UTXO selection is minimal**: real wallets need to do proper UTXO selection
5. **Node discovery scanning can be expensive**: consider caching / limiting block scan on wallet side

## Development Status

> estimated ~70% node functionality/completion. Not fully production ready, need more R&D

## License

Open source - GNU 3 license

## Philosophy

> kloak is, and will forever be, open-source software, written for no other purpose than the good of humanity and in defense of the right to individual security, and as protection against violations of freedom by those seeking to control, surveil, oppress, and steal

