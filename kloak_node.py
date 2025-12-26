# "liberty, when it begins to take root, is a plant of rapid growth"


# sentiment:


# welcome to the kloak payment protocol standalone node implementation
# if you're reading this, you care about the future of money and cryptography

# kloak is a novel fungibility layer built on kaspa, the fastest, most decentralized
# cryptographic network in the world

# for the first time in human history, completely trustless, completely liquid fungibility exists
# bitcoin was a major leap forward from fiat currency, but has limitations that no scalability layer can overcome

# kloak is the only protocol to ever leverage a public ledger DAG network to achieve plausible deniability
# for transactions. this is the statement we are making: you, only you, are in control of your funds

# kloak is, and will forever be, open-source software, written for no other purpose than the good of humanity
# and in defense of the right to individual security, and as protection against violations of freedom
# by those seeking to control, surveil, oppress, and steal


# tech:


# kloak payment protocol is, fundamentally, a decentralized, non-custodial payjoin coordinator
# instead of using a centralized mediator to accomplish a deliberate joining action, this software transforms
# regular day-to-day payments into kaspa fungibility enhancers, benefitting both the network and the users

# typical kaspa transactions have one input and two outputs (recipient and change)
# kloak transactions allow a receiver to contribute one of their own random UTXO's and an extra receiving address to a transaction
# to create a 2+in, 4out payment that breaks all chain heuristics

# neither the true amount of the transfer, nor the true sender/receiver can be determined by analysis

# this is done in a way that is completely trustless and secure for all parties involved
# this "handshake" is done via an end-to-end encrypted websocket connection
# which never touches any sensitive data, or your keys


# tx:


# kpp transactions are mathematically indistiguishable from regular wallet consolidation/reorg or batched txns
# receiver owed output is split randomly between the two unique addresses they provide
# kloak nodes are rewarded for facilitating the handshake by receiving the "dust" output from the tx

# the total UTXO value is rounded to the nearest 0.1 and the remainder is sent to a unique dust collection addr
# that is provided by the node. not only does this incentivize node operators to run the software,
# but it also breaks the chain analysis heuristic of "round number" transactions, so change outputs cannot be assumed


# deployment:


# kloak nodes compete for usage by acting as a beacon on the kaspa network periodically
# this pulse rate can be configured by the node operator, with a default of once every 6 hours
# the more often a node pulses, the more likely it is to be selected by wallets for use,
# as wallets will crawl the DAG for the 3 most recently pulsed nodes, and select the one with the lowest latency
# the tradeoff is that a very high pulse rate will cost more in transaction fees for the operator

# high uptime and low latency nodes have good revenue potential and can cover their operating costs
# rogue nodes will be naturally weeded out by the network
# zombie nodes that do not pulse or are disconnected cannot be selected by wallets


# integration:


# kpp is designed to be incredibly simple to integrate into existing kaspa wallets

# qr_code = scan_qr()
#if is_kloak_payment_request(qr_code):
#    # Handle as Kloak payment
#    result = await sender_connect_to_kloak_node(qr_code, utxo, change_addr)
#else:
#    # Handle as standard Kaspa payment
#    normal_payment(qr_code)


from typing import Final, Optional, Dict, Any, Tuple
import asyncio
import argparse
import sys
import logging
import json
import os
import hashlib
import secrets
import shlex
import base64
import struct
import time
import socket
import threading
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass

try:
    # msvcrt previously used for ESC-to-exit console handling.
    # We intentionally avoid single-key exits for production operation.
    import msvcrt  # type: ignore  # noqa: F401
except Exception:
    pass

# Kaspa/crypto imports
from kaspy.kaspa_clients import RPCClient
from kaspy.defines import MAINNET, RPC_SERVICE, RPC_DEF_PORTS

try:
    import grpc  # type: ignore
except Exception:
    grpc = None  # type: ignore

# WebSocket imports
import websockets
from websockets.asyncio.server import serve, ServerConnection

# HTTP imports for IP discovery
import requests

# Cryptography imports
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

# BIP39/BIP32 imports
from mnemonic import Mnemonic
import hmac
import ecdsa
from ecdsa import SECP256k1
from ecdsa.util import string_to_number

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
LOG = logging.getLogger('[KLOAK_NODE]')

SOMPI_PER_KAS: Final[int] = 100_000_000

CONFIG: Final[Dict[str, Any]] = {
    "VERSION": "1.0.0",
    "PULSE_INTERVAL_SECONDS": 600,  # 6 hours
    "LOG_LEVEL": logging.INFO,
    "FUND_AMOUNT_KAS": 2,
    # Mempool standardness: some nodes require a minimum absolute fee even if
    # feerate * mass would be smaller. Keep conservative to avoid rejection.
    "MIN_TX_FEE_SOMPI": 2000,
    # Local fee estimation safety knobs. Larger values reduce mempool rejections
    # at the cost of paying higher fees.
    "FEE_SAFETY_MULTIPLIER": 2.0,
    "FEE_EXTRA_SOMPI": 2000,
    # NOTE: This is a *basename*; at runtime we resolve it to a persistent
    # user-data location so running from source vs a bundled EXE shares wallets.
    "WALLET_FILE": "kloak_wallet.enc",
    "KASPA_NODE": "seeder2.kaspad.net",  # Try seeder2 if seeder1 is down
    "KASPA_RPC_PORT": 16110,
    "WEBSOCKET_PORT": 8765,
    "WEBSOCKET_BIND": "0.0.0.0",
    "AUTO_DETECT_IP": True,  # Automatically detect public IP
    "MANUAL_IP": None,  # Set to override auto-detection (e.g., "123.45.67.89")
    "NETWORK": MAINNET,
    "DERIVATION_PATH": "m/44'/111111'/0'/0",  # Kaspa BIP44 path
}


def _program_dir() -> Path:
    """Directory of the running program (script dir or frozen EXE dir)."""
    try:
        if getattr(sys, "frozen", False):
            return Path(sys.executable).resolve().parent
    except Exception:
        pass
    return Path(__file__).resolve().parent


def _default_wallet_path() -> Path:
    """Default wallet path in a persistent user-data directory."""
    return _kloak_cache_dir() / "kloak_wallet.enc"


def _maybe_migrate_legacy_wallet(*, dest_path: Path) -> None:
    """Best-effort migration from legacy local wallet locations.

    Historically the wallet lived next to the script/exe (or in the CWD). That
    causes separate wallets when running from different directories.
    """
    try:
        if dest_path.exists():
            return

        candidates = []
        basename = dest_path.name

        cwd_candidate = Path.cwd() / basename
        if cwd_candidate.exists():
            candidates.append(cwd_candidate)

        prog_candidate = _program_dir() / basename
        if prog_candidate.exists() and prog_candidate not in candidates:
            candidates.append(prog_candidate)

        if not candidates:
            return

        # If multiple legacy wallets exist, prefer the most recently modified.
        def _mtime(p: Path) -> float:
            try:
                return p.stat().st_mtime
            except Exception:
                return 0.0

        legacy = max(candidates, key=_mtime)

        dest_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            # Preferred: move (atomic within volume) so the legacy file disappears.
            legacy.replace(dest_path)
            LOG.info(f"Migrated legacy wallet to {dest_path}")
        except Exception:
            import shutil

            # Fallback: copy then delete (best-effort) after verifying the copy.
            shutil.copy2(legacy, dest_path)
            try:
                if dest_path.exists() and legacy.exists():
                    if dest_path.stat().st_size == legacy.stat().st_size and dest_path.stat().st_size > 0:
                        legacy.unlink(missing_ok=True)
                        LOG.info(f"Migrated legacy wallet to {dest_path} (deleted legacy file at {legacy})")
                    else:
                        LOG.warning(
                            "Legacy wallet copy size mismatch; not deleting source (%s).",
                            str(legacy),
                        )
            except Exception:
                # Don't fail startup if deletion fails.
                LOG.info(f"Migrated legacy wallet to {dest_path} (could not delete legacy file at {legacy})")

        if len(candidates) > 1:
            LOG.warning(
                "Multiple legacy wallet files found (%s); migrated the newest (%s).",
                ", ".join(str(p) for p in candidates),
                str(legacy),
            )
    except Exception:
        # Never block startup on migration.
        return

# Global state
wallet_data: Optional[Dict] = None
rpc_client: Optional[RPCClient] = None
active_sessions: Dict[str, Dict] = {}  # Track active sessions
pending_receivers: Dict[str, Dict] = {}  # Receivers waiting for senders, keyed by session_id (NOT E2EE key!)
session_lock = None  # Will be set to asyncio.Lock() when running
wallet_lock = None  # Protects wallet mutation + saving
wallet_passphrase: Optional[str] = None  # Kept in memory while node is running (needed for auto-save)

# Kaspa RPC resilience
rpc_needs_reconnect: bool = False
rpc_last_error: Optional[str] = None
_rpc_reconnect_lock = threading.Lock()
_rpc_reconnect_thread: Optional[threading.Thread] = None

# Pulse triggering (wake the pulse loop early on first wallet initiation)
_pulse_trigger_event: Optional[asyncio.Event] = None
_pulse_last_sent_ts: float = 0.0
_pulse_next_periodic_ts: float = 0.0


def _request_immediate_pulse(*, reason: str = "") -> None:
    """Request the pulse loop to run ASAP (best-effort).

    This is used to broadcast the first pulse immediately after a wallet session
    has been initiated, instead of waiting for the periodic interval.
    """
    try:
        ev = _pulse_trigger_event
        if ev is not None:
            ev.set()
            if reason:
                LOG.debug(f"Immediate pulse requested: {reason}")
    except Exception:
        return


def _schedule_rpc_reconnect() -> None:
    """Kick off a background reconnect attempt (idempotent)."""
    global _rpc_reconnect_thread

    try:
        with _rpc_reconnect_lock:
            if _rpc_reconnect_thread is not None and _rpc_reconnect_thread.is_alive():
                return

            def _worker() -> None:
                backoff = 2.0
                max_backoff = 30.0
                # Keep trying until we reconnect or the process exits.
                while True:
                    try:
                        if _ensure_rpc_connected():
                            LOG.info("Kaspa RPC reconnected.")
                            return
                    except Exception:
                        # _ensure_rpc_connected already logs.
                        pass
                    time.sleep(backoff)
                    backoff = min(max_backoff, backoff * 1.7)

            _rpc_reconnect_thread = threading.Thread(
                target=_worker,
                name="kloak-rpc-reconnect",
                daemon=True,
            )
            _rpc_reconnect_thread.start()
    except Exception:
        return


def _is_transient_grpc_disconnect(exc: BaseException) -> bool:
    """Return True for common transient kaspad/grpc disconnects.

    kaspy uses background threads for stream subscriptions; when the peer drops
    the stream, grpc can raise UNAVAILABLE with 'End of TCP stream'.
    """
    try:
        if grpc is None:
            return False
        if not isinstance(exc, grpc.RpcError):
            return False

        code = None
        details = None
        try:
            code = exc.code()
        except Exception:
            code = None
        try:
            details = exc.details()
        except Exception:
            details = None

        if code == grpc.StatusCode.UNAVAILABLE:
            if details and "End of TCP stream" in str(details):
                return True
            # Treat UNAVAILABLE as reconnect-worthy even if message differs.
            return True
        return False
    except Exception:
        return False


def _mark_rpc_needs_reconnect(reason: str) -> None:
    global rpc_needs_reconnect, rpc_last_error
    rpc_needs_reconnect = True
    rpc_last_error = reason


def _ensure_rpc_connected() -> bool:
    """Ensure global rpc_client is connected; reconnect if marked stale."""
    global rpc_client, rpc_needs_reconnect, rpc_last_error

    if rpc_client is not None and not rpc_needs_reconnect:
        return True

    # Attempt reconnect
    try:
        if rpc_client is not None:
            try:
                rpc_client.close()
            except Exception:
                pass
        rpc_client = init_rpc_client()
        rpc_needs_reconnect = False
        rpc_last_error = None
        return True
    except Exception as e:
        LOG.error(f"Kaspa RPC reconnect failed: {e}")
        return False


def rpc_request(client: RPCClient, method: str, payload: dict) -> dict:
    """Call kaspad via kaspy with reconnect signaling on transient disconnects."""
    try:
        return client.request(method, payload)
    except Exception as exc:
        try:
            if _is_transient_grpc_disconnect(exc):
                _mark_rpc_needs_reconnect(str(exc))
                LOG.warning("Kaspa RPC request failed (transient). Auto-reconnecting...")
                _schedule_rpc_reconnect()
        except Exception:
            pass
        raise


def _install_thread_excepthook() -> None:
    """Downgrade noisy background grpc disconnect tracebacks to warnings."""
    try:
        if not hasattr(threading, "excepthook"):
            return
        original = threading.excepthook

        def _hook(args: threading.ExceptHookArgs) -> None:  # type: ignore[name-defined]
            exc = args.exc_value
            if exc is not None and _is_transient_grpc_disconnect(exc):
                _mark_rpc_needs_reconnect(str(exc))
                LOG.warning("Kaspa RPC stream disconnected (transient). Auto-reconnecting...")
                _schedule_rpc_reconnect()
                return
            original(args)

        threading.excepthook = _hook  # type: ignore[assignment]
    except Exception:
        return


_install_thread_excepthook()

# WebSocket/server safety limits
PENDING_SESSION_TTL_SECONDS: Final[int] = 300
WS_MAX_MESSAGE_BYTES: Final[int] = 1_000_000
WS_HANDSHAKE_TIMEOUT_SECONDS: Final[float] = 15.0
WS_RECV_TIMEOUT_SECONDS: Final[float] = 60.0


@dataclass
class KloakWallet:
    """
    Represents a Kloak node wallet with BIP44 HD key derivation.
    
    Attributes:
        mnemonic: BIP39 12-word recovery phrase
        master_seed: Master seed derived from mnemonic
        addresses: List of address dictionaries containing index, address, private_key, used status, and purpose
        xpub: Extended public key identifier
        current_index: Current address derivation index
        highest_used_index: Highest index of any used address
    """
    mnemonic: str
    master_seed: bytes
    addresses: list  # List of dicts with: index, address, private_key, used, purpose
    xpub: str
    current_index: int = 0
    highest_used_index: int = -1  # Track highest used address index

    # Pulse-chain state: index of the address expected to hold the next pulse UTXO.
    # Starts at 0 (node_primary). After each successful pulse, this advances to
    # the newly generated pulse address.
    pulse_source_index: int = 0
    
    def mark_address_used(self, index: int, purpose: str = "unknown"):
        """
        Mark an address as used and record the purpose.
        
        Args:
            index: Address index to mark as used
            purpose: Purpose for which address is being used (e.g., "pulse", "dust_collection", "node_primary")
        """
        if index < len(self.addresses):
            self.addresses[index]["used"] = True
            self.addresses[index]["used_at"] = datetime.now().isoformat()
            self.addresses[index]["purpose"] = purpose
            if index > self.highest_used_index:
                self.highest_used_index = index
    
    def get_next_unused_address(self, purpose: str = "general") -> Tuple[int, str]:
        """
        Get the next unused address, generating a new one if all existing addresses are used.
        
        Args:
            purpose: Purpose for which the address will be used
            
        Returns:
            Tuple of (address_index, address_string)
        """
        # Find first unused address
        for addr in self.addresses:
            if not addr.get("used", False):
                return addr["index"], addr["address"]
        
        # All addresses used, generate a new one
        next_index = len(self.addresses)
        master_seed = bytes.fromhex(self.master_seed)
        new_addr, new_priv = generate_kaspa_address(master_seed, next_index)
        
        self.addresses.append({
            "index": next_index,
            "address": new_addr,
            "private_key": new_priv.hex(),
            "used": False,
            "purpose": None,
            "created_at": datetime.now().isoformat()
        })
        
        return next_index, new_addr


# ============================================================================
# KASPA ADDRESS & KEY GENERATION (Real Implementation)
# ============================================================================

def blake2b_hash(data: bytes, digest_size: int = 32) -> bytes:
    """
    Compute Blake2b hash used by Kaspa.
    
    Args:
        data: Input data to hash
        digest_size: Output size in bytes (default 32)
        
    Returns:
        Blake2b hash digest
    """
    return hashlib.blake2b(data, digest_size=digest_size).digest()


_KASPA_BECH32_CHARSET = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_KASPA_BECH32_REV = [100] * 123
for _i, _c in enumerate(_KASPA_BECH32_CHARSET):
    if _c < len(_KASPA_BECH32_REV):
        _KASPA_BECH32_REV[_c] = _i


def _kaspa_bech32_polymod(values: bytes) -> int:
    c = 1
    for d in values:
        c0 = c >> 35
        c = ((c & 0x07FFFFFFFF) << 5) ^ d
        if c0 & 0x01:
            c ^= 0x98F2BC8E61
        if c0 & 0x02:
            c ^= 0x79B76D99E2
        if c0 & 0x04:
            c ^= 0xF33E5FB3C4
        if c0 & 0x08:
            c ^= 0xAE2EABE2A8
        if c0 & 0x10:
            c ^= 0x1E4F43E470
    return c ^ 1


def _kaspa_bech32_checksum(payload_u5: bytes, prefix: str) -> int:
    prefix_u5 = bytes([(c & 0x1F) for c in prefix.encode("ascii")])
    return _kaspa_bech32_polymod(prefix_u5 + b"\x00" + payload_u5 + (b"\x00" * 8))


def _conv8to5(payload: bytes) -> bytes:
    padding = 0 if (len(payload) % 5 == 0) else 1
    out = bytearray((len(payload) * 8) // 5 + padding)
    current_idx = 0
    buff = 0
    bits = 0
    for c in payload:
        buff = ((buff << 8) | c) & 0xFFFF
        bits += 8
        while bits >= 5:
            bits -= 5
            out[current_idx] = (buff >> bits) & 0x1F
            buff &= (1 << bits) - 1
            current_idx += 1
    if bits > 0:
        out[current_idx] = (buff << (5 - bits)) & 0x1F
    return bytes(out)


def _conv5to8(payload: bytes) -> bytes:
    out = bytearray((len(payload) * 5) // 8)
    current_idx = 0
    buff = 0
    bits = 0
    for c in payload:
        buff = ((buff << 5) | c) & 0xFFFF
        bits += 5
        while bits >= 8:
            bits -= 8
            out[current_idx] = (buff >> bits) & 0xFF
            buff &= (1 << bits) - 1
            current_idx += 1
    return bytes(out)


def encode_kaspa_address(payload: bytes, prefix: str = "kaspa", version: int = 0) -> str:
    """Encode a Kaspa address, aligned with `rusty-kaspa`.

    Address string format: `{prefix}:{bech32_payload}`.
    Payload format: `version (1 byte) || payload (32/33 bytes depending on version)`.

    Versions:
    - 0: PubKey (Schnorr, 32-byte x-only pubkey)
    - 1: PubKeyECDSA (33-byte compressed pubkey)
    - 8: ScriptHash (32-byte hash)
    """
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be bytes")

    if version == 0 and len(payload) != 32:
        raise ValueError("PubKey address payload must be 32 bytes")
    if version == 1 and len(payload) != 33:
        raise ValueError("PubKeyECDSA address payload must be 33 bytes")
    if version == 8 and len(payload) != 32:
        raise ValueError("ScriptHash address payload must be 32 bytes")

    payload_u5 = _conv8to5(bytes([version]) + bytes(payload))
    chk = _kaspa_bech32_checksum(payload_u5, prefix)
    chk_u5 = _conv8to5(chk.to_bytes(8, "big")[3:])
    encoded = bytes(_KASPA_BECH32_CHARSET[b] for b in (payload_u5 + chk_u5)).decode("ascii")
    return f"{prefix}:{encoded}"


def decode_kaspa_address(address: str) -> Tuple[str, int, bytes]:
    """Decode a Kaspa address into (prefix, version, payload) per `rusty-kaspa`."""
    if not isinstance(address, str):
        raise TypeError("address must be str")
    if ":" not in address:
        raise ValueError("Address missing prefix")

    prefix, payload_str = address.split(":", 1)
    if len(payload_str) < 8:
        raise ValueError("Bad address payload")

    payload_u5 = bytearray()
    for ch in payload_str.encode("ascii"):
        if ch >= len(_KASPA_BECH32_REV):
            raise ValueError(f"Invalid address character: {chr(ch)}")
        v = _KASPA_BECH32_REV[ch]
        if v == 100:
            raise ValueError(f"Invalid address character: {chr(ch)}")
        payload_u5.append(v)

    data_u5, checksum_u5 = bytes(payload_u5[:-8]), bytes(payload_u5[-8:])
    checksum_bytes = _conv5to8(checksum_u5)
    if len(checksum_bytes) != 5:
        raise ValueError("Bad checksum size")
    checksum_int = int.from_bytes(b"\x00\x00\x00" + checksum_bytes, "big")
    expected = _kaspa_bech32_checksum(data_u5, prefix)
    if expected != checksum_int:
        raise ValueError("Bad checksum")

    decoded = _conv5to8(data_u5)
    if len(decoded) < 1:
        raise ValueError("Bad payload")
    version = decoded[0]
    payload = decoded[1:]

    if version == 0 and len(payload) != 32:
        raise ValueError("PubKey payload must be 32 bytes")
    if version == 1 and len(payload) != 33:
        raise ValueError("PubKeyECDSA payload must be 33 bytes")
    if version == 8 and len(payload) != 32:
        raise ValueError("ScriptHash payload must be 32 bytes")
    if version not in (0, 1, 8):
        raise ValueError(f"Unsupported address version: {version}")
    return prefix, version, payload


def address_to_script_public_key(address: str) -> bytes:
    """
    Convert a Kaspa address to a standard script public key (ScriptVec), aligned with `rusty-kaspa`.

    Standard scripts:
    - PubKey (version=0): OP_DATA_32 <x-only pubkey 32> OP_CHECKSIG
    - PubKeyECDSA (version=1): OP_DATA_33 <compressed pubkey 33> OP_CHECKSIGECDSA
    - ScriptHash (version=8): OP_BLAKE2B OP_DATA_32 <32-byte hash> OP_EQUAL
    """
    _, version, payload = decode_kaspa_address(address)
    if version == 0:
        return bytes([0x20]) + payload + bytes([0xAC])
    if version == 1:
        return bytes([0x21]) + payload + bytes([0xAB])
    if version == 8:
        return bytes([0xAA, 0x20]) + payload + bytes([0x87])
    raise ValueError(f"Unsupported address version: {version}")


def pubkey_to_script_public_key(pubkey: bytes) -> bytes:
    """
    Convert a public key to a standard pay-to-pubkey script.

    For Schnorr-based (Kaspa default) scripts, the locking script expects a 32-byte x-only pubkey.
    This function accepts either:
    - 32-byte x-only pubkey
    - 33-byte compressed pubkey (will be converted to x-only by stripping prefix)
    
    Args:
        pubkey: 32-byte x-only pubkey or 33-byte compressed pubkey
        
    Returns:
        Script bytes ready for transaction output
    """
    if len(pubkey) == 33:
        pubkey = pubkey[1:33]
    if len(pubkey) != 32:
        raise ValueError(f"Invalid pubkey length: {len(pubkey)}, expected 32 (x-only) or 33 (compressed)")
    return bytes([0x20]) + pubkey + bytes([0xAC])


def derive_bip32_master_key(seed: bytes) -> Tuple[bytes, bytes]:
    """
    Derive BIP32 master private key and chain code from seed.
    
    Args:
        seed: BIP39 seed bytes
        
    Returns:
        Tuple of (master_key, chain_code)
    """
    # BIP32 master key derivation
    h = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_key = h[:32]
    chain_code = h[32:]
    
    return master_key, chain_code


def derive_bip32_child_key(parent_key: bytes, chain_code: bytes, index: int, hardened: bool = True) -> Tuple[bytes, bytes]:
    """
    Derive a BIP32 child key from parent key.
    
    Args:
        parent_key: Parent private key (32 bytes)
        chain_code: Parent chain code (32 bytes)
        index: Child index
        hardened: Whether to use hardened derivation
        
    Returns:
        Tuple of (child_key, child_chain_code)
        
    Raises:
        ValueError: If derived key is invalid (retry with next index)
    """
    if hardened:
        # Hardened derivation: index >= 2^31
        index_bytes = struct.pack('>I', index + 0x80000000)
        data = b'\x00' + parent_key + index_bytes
    else:
        # Normal derivation (not used for Kaspa typically)
        # Would need to compute public key first
        index_bytes = struct.pack('>I', index)
        # Simplified - in production compute actual pubkey
        data = parent_key + index_bytes
    
    # HMAC-SHA512 derivation
    h = hmac.new(chain_code, data, hashlib.sha512).digest()
    
    # Parse key and chain code
    key_int = int.from_bytes(h[:32], 'big')
    parent_int = int.from_bytes(parent_key, 'big')
    
    # Modular addition
    n = SECP256k1.order
    child_key_int = (key_int + parent_int) % n
    
    if child_key_int == 0:
        raise ValueError("Invalid child key - try next index")
    
    child_key = child_key_int.to_bytes(32, 'big')
    child_chain_code = h[32:]
    
    return child_key, child_chain_code


def private_key_to_public_key(private_key: bytes) -> bytes:
    """
    Convert private key to compressed public key using secp256k1.
    
    Args:
        private_key: 32-byte private key
        
    Returns:
        33-byte compressed public key (0x02/0x03 prefix + x-coordinate)
    """
    # Create signing key from private key
    sk = ecdsa.SigningKey.from_string(private_key, curve=SECP256k1)
    
    # Get verifying (public) key
    vk = sk.get_verifying_key()
    
    # Get compressed public key (33 bytes: 0x02/0x03 + x-coordinate)
    pubkey_point = vk.pubkey.point
    x = pubkey_point.x()
    y = pubkey_point.y()
    
    # Compressed format: 0x02 if y is even, 0x03 if y is odd
    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    compressed_pubkey = prefix + x.to_bytes(32, 'big')
    
    return compressed_pubkey


def derive_kaspa_address_from_path(seed: bytes, path: str = "m/44'/111111'/0'/0/0") -> Tuple[bytes, bytes, str]:
    """
    Derive Kaspa address using BIP44 path.
    
    Default path: m/44'/111111'/0'/0/0
    - 44' = BIP44 standard
    - 111111' = Kaspa coin type
    - 0' = Account 0
    - 0 = External chain
    - 0 = Address index
    
    Args:
        seed: Master seed bytes
        path: BIP44 derivation path string
        
    Returns:
        Tuple of (private_key, public_key, address)
        
    Raises:
        ValueError: If path format is invalid
    """
    # Parse path
    path_parts = path.split('/')
    if path_parts[0] != 'm':
        raise ValueError("Path must start with 'm'")
    
    # Start with master key
    key, chain_code = derive_bip32_master_key(seed)
    
    # Derive through path
    for part in path_parts[1:]:
        if part.endswith("'"):
            # Hardened derivation
            index = int(part[:-1])
            key, chain_code = derive_bip32_child_key(key, chain_code, index, hardened=True)
        else:
            # Normal derivation
            index = int(part)
            key, chain_code = derive_bip32_child_key(key, chain_code, index, hardened=False)
    
    # Generate compressed public key then convert to x-only (Kaspa PubKey addresses)
    pubkey_compressed = private_key_to_public_key(key)
    xonly_pubkey = pubkey_compressed[1:33]

    address = encode_kaspa_address(xonly_pubkey, prefix="kaspa", version=0)

    return key, xonly_pubkey, address


def generate_kaspa_address(seed: bytes, index: int) -> Tuple[str, bytes]:
    """
    Generate a Kaspa address from seed at given index.
    
    Uses BIP44 derivation path: m/44'/111111'/0'/0/{index}
    
    Args:
        seed: Master seed bytes
        index: Address derivation index
        
    Returns:
        Tuple of (address_string, private_key_bytes)
    """
    # Construct BIP44 path for this index
    path = f"m/44'/111111'/0'/0/{index}"
    
    try:
        priv_key, pub_key, address = derive_kaspa_address_from_path(seed, path)
        return address, priv_key
    except Exception as e:
        LOG.error(f"Failed to derive address at index {index}: {e}")
        # Fallback: try next index
        return generate_kaspa_address(seed, index + 1)


# ============================================================================
# WALLET MANAGEMENT
# ============================================================================

def create_wallet(passphrase: str) -> KloakWallet:
    """
    Create a new Kloak node wallet with BIP39 mnemonic and Kaspa addresses.
    
    Generates a 12-word BIP39 mnemonic, derives master seed, and creates initial
    set of 20 addresses using BIP44 derivation path m/44'/111111'/0'/0/N.
    First address is automatically marked as used for node operations.
    
    Args:
        passphrase: Encryption passphrase for wallet file (not BIP39 passphrase)
        
    Returns:
        KloakWallet instance with generated mnemonic and addresses
    """
    LOG.info("Creating new Kloak wallet...")
    
    # Generate 12-word mnemonic
    mnemo = Mnemonic("english")
    mnemonic_phrase = mnemo.generate(strength=128)  # 128 bits = 12 words
    
    # Generate seed from mnemonic
    master_seed = mnemo.to_seed(mnemonic_phrase, passphrase="")
    
    # Generate initial addresses
    addresses = []
    for i in range(20):  # Generate 20 addresses initially
        addr, priv = generate_kaspa_address(master_seed, i)
        addresses.append({
            "index": i,
            "address": addr,
            "private_key": priv.hex(),
            "used": False,
            "purpose": None,
            "created_at": datetime.now().isoformat()
        })
    
    # Mark first address as used for node operations
    addresses[0]["used"] = True
    addresses[0]["purpose"] = "node_primary"
    addresses[0]["used_at"] = datetime.now().isoformat()
    
    # Create wallet object
    wallet = KloakWallet(
        mnemonic=mnemonic_phrase,
        master_seed=master_seed.hex(),
        addresses=addresses,
        xpub=f"kpp_xpub_{secrets.token_hex(32)}",
        current_index=0,
        highest_used_index=0,
        pulse_source_index=0,
    )
    
    LOG.info(f"Success: Wallet created with {len(addresses)} addresses")
    LOG.info(f"First address: {addresses[0]['address']}")
    
    return wallet


def save_wallet(wallet: KloakWallet, passphrase: str, filename: str = None):
    """
    Save wallet to encrypted file using ChaCha20-Poly1305 encryption.
    
    Args:
        wallet: KloakWallet instance to save
        passphrase: Encryption passphrase
        filename: Output filename (defaults to CONFIG["WALLET_FILE"])
    """
    if filename is None:
        filename = CONFIG["WALLET_FILE"]
    
    LOG.info(f"Saving wallet to {filename}...")
    
    # Serialize wallet data
    wallet_json = json.dumps({
        "mnemonic": wallet.mnemonic,
        "master_seed": wallet.master_seed,
        "addresses": wallet.addresses,
        "xpub": wallet.xpub,
        "current_index": wallet.current_index,
        "highest_used_index": wallet.highest_used_index,
        "pulse_source_index": getattr(wallet, "pulse_source_index", 0),
        "created_at": datetime.now().isoformat(),
        "last_saved": datetime.now().isoformat(),
        "version": CONFIG["VERSION"]
    }, indent=2)
    
    # Derive encryption key from passphrase
    salt = secrets.token_bytes(16)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    key = kdf.derive(passphrase.encode())
    
    # Encrypt wallet data
    cipher = ChaCha20Poly1305(key)
    nonce = secrets.token_bytes(12)
    ciphertext = cipher.encrypt(nonce, wallet_json.encode(), None)
    
    # Save to file (atomic replace to reduce corruption risk)
    out_path = Path(filename)
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    tmp_filename = f"{out_path}.tmp"
    with open(tmp_filename, 'wb') as f:
        f.write(salt + nonce + ciphertext)
        try:
            f.flush()
            os.fsync(f.fileno())
        except Exception:
            pass
    os.replace(tmp_filename, str(out_path))
    
    LOG.info(f"Success: Wallet saved and encrypted")


def load_wallet(passphrase: str, filename: str = None) -> KloakWallet:
    """
    Load existing Kloak node wallet from encrypted file.
    
    Args:
        passphrase: Decryption passphrase
        filename: Wallet filename (defaults to CONFIG["WALLET_FILE"])
        
    Returns:
        KloakWallet instance loaded from file
        
    Raises:
        FileNotFoundError: If wallet file doesn't exist
        ValueError: If passphrase is incorrect or file is corrupted
    """
    if filename is None:
        filename = CONFIG["WALLET_FILE"]
    
    LOG.info(f"Loading wallet from {filename}...")
    
    if not os.path.exists(filename):
        raise FileNotFoundError(f"Wallet file not found: {filename}")
    
    # Read encrypted file
    with open(filename, 'rb') as f:
        data = f.read()
    
    # Extract components
    salt = data[:16]
    nonce = data[16:28]
    ciphertext = data[28:]
    
    # Derive decryption key
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    key = kdf.derive(passphrase.encode())
    
    # Decrypt wallet data
    cipher = ChaCha20Poly1305(key)
    try:
        plaintext = cipher.decrypt(nonce, ciphertext, None)
        wallet_dict = json.loads(plaintext.decode())
    except Exception as e:
        raise ValueError("Invalid passphrase or corrupted wallet file") from e
    
    # Reconstruct wallet object
    wallet = KloakWallet(
        mnemonic=wallet_dict["mnemonic"],
        master_seed=wallet_dict["master_seed"],
        addresses=wallet_dict["addresses"],
        xpub=wallet_dict["xpub"],
        current_index=wallet_dict.get("current_index", 0),
        highest_used_index=wallet_dict.get("highest_used_index", 0),
        pulse_source_index=int(wallet_dict.get("pulse_source_index", 0) or 0),
    )

    # Migrate legacy (non-bech32) addresses to bech32 PubKey addresses.
    # Older wallet versions stored a base58-style string; we can deterministically
    # regenerate the correct address from each stored private key.
    migrated = False
    for entry in wallet.addresses:
        addr = entry.get("address")
        priv_hex = entry.get("private_key")
        if not addr or not priv_hex:
            continue

        try:
            prefix, version, payload = decode_kaspa_address(addr)
            if prefix != "kaspa" or version != 0 or len(payload) != 32:
                raise ValueError("Unexpected address format")
        except Exception:
            try:
                priv_key = bytes.fromhex(priv_hex)
                pubkey_compressed = private_key_to_public_key(priv_key)
                xonly_pubkey = pubkey_compressed[1:33]
                entry["address"] = encode_kaspa_address(xonly_pubkey, prefix="kaspa", version=0)
                migrated = True
            except Exception as migrate_error:
                LOG.warning(
                    f"Could not migrate address index {entry.get('index', '?')}: {migrate_error}"
                )

    if migrated:
        LOG.info("Migrated legacy wallet addresses to Kaspa bech32 PubKey format")
        try:
            save_wallet(wallet, passphrase, filename)
            LOG.info("Updated wallet file after migration")
        except Exception as save_error:
            LOG.warning(f"Failed to persist migrated wallet addresses: {save_error}")
    
    LOG.info(f"Success: Wallet loaded successfully")
    return wallet


# ============================================================================
# NETWORK UTILITIES
# ============================================================================

def get_public_ip() -> Optional[str]:
    """
    Automatically discover public IP address.
    
    Tries multiple services (ipify.org, icanhazip.com, ifconfig.me) for reliability.
    
    Returns:
        Public IP address string, or None if all services fail
    """
    services = [
        "https://api.ipify.org",
        "https://icanhazip.com",
        "https://ifconfig.me/ip",
    ]
    
    for service in services:
        try:
            response = requests.get(service, timeout=5)
            if response.status_code == 200:
                ip = response.text.strip()
                LOG.info(f"Success: Public IP detected: {ip}")
                return ip
        except Exception as e:
            LOG.debug(f"Failed to get IP from {service}: {e}")
            continue
    
    LOG.warning("Could not auto-detect public IP")
    return None


def get_websocket_url() -> str:
    """
    Get the WebSocket URL for this node.
    
    Uses manual IP if CONFIG["MANUAL_IP"] is set, otherwise auto-detects public IP.
    Falls back to "localhost" if detection fails.
    
    Returns:
        WebSocket URL string (e.g., "ws://123.45.67.89:8765/kpp")
    """
    # Manual IP override
    if CONFIG.get("MANUAL_IP"):
        ip = CONFIG["MANUAL_IP"]
        LOG.info(f"Using manual IP: {ip}")
    # Auto-detect
    elif CONFIG.get("AUTO_DETECT_IP", True):
        ip = get_public_ip()
        if not ip:
            LOG.warning("Falling back to localhost (node won't be publicly accessible)")
            ip = "localhost"
    else:
        ip = "localhost"
    
    return f"ws://{ip}:{CONFIG['WEBSOCKET_PORT']}/kpp"


def _print_ascii_qr(data: str) -> bool:
    """Print an ASCII QR code to the console.

    Returns True if printed, False if the optional dependency isn't available.
    """
    try:
        import qrcode  # type: ignore

        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=1,
            border=2,
        )
        qr.add_data(data)
        qr.make(fit=True)

        # Invert so it scans better on typical dark terminals.
        qr.print_ascii(invert=True)
        return True
    except Exception:
        return False


def _funding_qr_payload(address: str) -> str:
    """Return the string we encode into the funding QR.

    Many wallets expect the raw Kaspa address (often already prefixed with
    'kaspa:'). We therefore encode the address itself and only guard against
    accidental double-prefixes like 'kaspa:kaspa:...'.
    """
    s = (address or "").strip()
    # Guard against accidental double prefix.
    while s.lower().startswith("kaspa:kaspa:"):
        s = s[len("kaspa:"):]
    return s


# ============================================================================
# RPC CLIENT OPERATIONS
# ============================================================================

def init_rpc_client(host: str = None, port: int = None) -> RPCClient:
    """
    Initialize connection to Kaspa RPC node.
    
    Args:
        host: Kaspa node hostname (defaults to CONFIG["KASPA_NODE"])
        port: Kaspa RPC port (defaults to CONFIG["KASPA_RPC_PORT"])
        
    Returns:
        Connected RPCClient instance
        
    Raises:
        Exception: If connection to Kaspa node fails
    """
    if host is None:
        host = CONFIG["KASPA_NODE"]
    if port is None:
        port = CONFIG["KASPA_RPC_PORT"]
    
    LOG.info(f"Connecting to Kaspa node at {host}:{port}...")
    
    client = RPCClient()
    client.connect(host, port, retry_count=3, retry_wait=2)
    
    # Test connection
    try:
        info = rpc_request(client, "getInfoRequest", {})
        LOG.info(f"Success: Connected to Kaspa node (version: {info.get('getInfoResponse', {}).get('serverVersion', 'unknown')})")
    except Exception as e:
        LOG.error(f"Failed to connect to Kaspa node: {e}")
        raise
    
    return client


def get_address_balance(client: RPCClient, address: str) -> float:
    """
    Get balance for a Kaspa address.
    
    Args:
        client: Connected RPCClient instance
        address: Kaspa address to query
        
    Returns:
        Balance in KAS (converted from sompi)
    """
    try:
        response = rpc_request(client, "getBalanceByAddressRequest", {
            "address": address
        })
        balance = response.get("getBalanceByAddressResponse", {}).get("balance", 0)
        return float(balance) / 100000000  # Convert sompi to KAS
    except Exception as e:
        LOG.error(f"Failed to get balance for {address}: {e}")
        return 0.0


def get_wallet_total_balance(client: RPCClient, wallet: KloakWallet) -> Dict[str, Any]:
    """
    Get total balance across all wallet addresses.
    
    Args:
        client: Connected RPCClient instance
        wallet: KloakWallet instance to check
        
    Returns:
        Dict containing:
            - total: Total balance in KAS
            - addresses: List of address balance info dicts
            - address_count: Number of addresses with non-zero balance
    """
    total = 0.0
    address_balances = []
    
    for addr_info in wallet.addresses:
        if addr_info.get("used", False):  # Only check used addresses
            balance = get_address_balance(client, addr_info["address"])
            if balance > 0:
                address_balances.append({
                    "index": addr_info["index"],
                    "address": addr_info["address"],
                    "balance": balance,
                    "purpose": addr_info.get("purpose", "unknown")
                })
                total += balance
    
    return {
        "total": total,
        "addresses": address_balances,
        "address_count": len(address_balances)
    }


def get_utxos_by_address(client: RPCClient, address: str) -> list:
    """
    Get unspent transaction outputs (UTXOs) for an address.
    
    Args:
        client: Connected RPCClient instance
        address: Kaspa address to query
        
    Returns:
        List of UTXO entries
    """
    try:
        response = rpc_request(client, "getUtxosByAddressesRequest", {
            "addresses": [address]
        })
        utxos = response.get("getUtxosByAddressesResponse", {}).get("entries", [])
        return utxos
    except Exception as e:
        LOG.error(f"Failed to get UTXOs: {e}")
        return []


def get_utxo_script_pubkey(utxo: dict) -> tuple[int, str]:
    """Extract (script_version, script_hex) from a kaspad UTXO entry.

    Different RPC clients / versions may expose the script hex under either:
    - utxoEntry.scriptPublicKey.script
    - utxoEntry.scriptPublicKey.scriptPublicKey
    """
    spk = (utxo or {}).get("utxoEntry", {}).get("scriptPublicKey", {}) or {}
    version = int(spk.get("version", 0) or 0)
    script_hex = spk.get("script") or spk.get("scriptPublicKey") or ""
    if not isinstance(script_hex, str):
        script_hex = ""
    return version, script_hex


def estimate_transaction_fee(client: RPCClient, num_inputs: int, num_outputs: int, 
                            priority: str = "normal") -> int:
    """
    Estimate transaction fee locally (no RPC fee-estimate calls).

    We intentionally avoid `getFeeEstimateRequest` because some kaspy protobuf
    builds do not include that method, which can crash the gRPC request stream.
    
    Args:
        client: Connected RPCClient instance (unused; kept for backward compatibility)
        num_inputs: Number of transaction inputs
        num_outputs: Number of transaction outputs
        priority: Fee priority level ("low", "normal", "high")
        
    Returns:
        Estimated fee in sompi
    """
    # Estimate transaction mass (approximate).
    # The real mass depends on script types and signature sizes; keep this
    # deliberately conservative to avoid mempool "not standard" rejections.
    # These constants intentionally err on the high side.
    base_mass = 600
    mass_per_input = 1600
    mass_per_output = 900
    estimated_mass = base_mass + (int(num_inputs) * mass_per_input) + (int(num_outputs) * mass_per_output)

    # Fixed fee rates (sompi/gram). Keep conservative defaults.
    if priority == "high":
        fee_rate = 10.0
    elif priority == "low":
        fee_rate = 1.0
    else:  # normal
        fee_rate = 1.0
    
    safety_multiplier = float(CONFIG.get("FEE_SAFETY_MULTIPLIER", 2.0) or 2.0)
    extra_fee = int(CONFIG.get("FEE_EXTRA_SOMPI", 0) or 0)

    # Calculate fee: mass * feerate * safety + buffer
    fee_sompi = int(estimated_mass * fee_rate * safety_multiplier) + extra_fee
    
    # Ensure minimum fee
    min_fee = int(CONFIG.get("MIN_TX_FEE_SOMPI", 2000))
    fee_sompi = max(fee_sompi, min_fee)
    
    LOG.debug(f"Estimated fee: {fee_sompi} sompi (mass: {estimated_mass}g, rate: {fee_rate} sompi/g)")
    
    return fee_sompi


# ============================================================================
# TRANSACTION SIGNING & BROADCASTING
# ============================================================================

SIG_HASH_ALL = 0b00000001
SIG_HASH_NONE = 0b00000010
SIG_HASH_SINGLE = 0b00000100
SIG_HASH_ANY_ONE_CAN_PAY = 0b10000000


def _tx_signing_hasher() -> "hashlib._Hash":
    # Matches rusty-kaspa: blake2b(key=b"TransactionSigningHash", hash_length=32)
    return hashlib.blake2b(digest_size=32, key=b"TransactionSigningHash")


def _write_u8(h, v: int) -> None:
    h.update(int(v).to_bytes(1, "little", signed=False))


def _write_u16(h, v: int) -> None:
    h.update(int(v).to_bytes(2, "little", signed=False))


def _write_u32(h, v: int) -> None:
    h.update(int(v).to_bytes(4, "little", signed=False))


def _write_u64(h, v: int) -> None:
    h.update(int(v).to_bytes(8, "little", signed=False))


def _write_len(h, n: int) -> None:
    # Matches HasherExtensions::write_len (u64 little-endian)
    _write_u64(h, n)


def _write_var_bytes(h, b: bytes) -> None:
    _write_len(h, len(b))
    h.update(b)


def _is_sighash_anyone_can_pay(t: int) -> bool:
    return (t & SIG_HASH_ANY_ONE_CAN_PAY) == SIG_HASH_ANY_ONE_CAN_PAY


def _is_sighash_single(t: int) -> bool:
    return (t & 0b00000111) == SIG_HASH_SINGLE


def _is_sighash_none(t: int) -> bool:
    return (t & 0b00000111) == SIG_HASH_NONE


def _hash_script_public_key_into(h, version: int, script: bytes) -> None:
    _write_u16(h, version)
    _write_var_bytes(h, script)


def _hash_output_into(h, output: dict) -> None:
    spk = output.get("scriptPublicKey", {})
    version = int(spk.get("version", 0))
    script_hex = spk.get("scriptPublicKey", spk.get("script", ""))
    script = bytes.fromhex(script_hex) if script_hex else b""
    amount_sompi = output.get("amount", output.get("value", 0))
    _write_u64(h, int(amount_sompi))
    _hash_script_public_key_into(h, version, script)


def _previous_outputs_hash(tx: dict, sighash_type: int) -> bytes:
    if _is_sighash_anyone_can_pay(sighash_type):
        return b"\x00" * 32
    h = _tx_signing_hasher()
    for inp in tx.get("inputs", []):
        prev = inp.get("previousOutpoint", {})
        txid_hex = prev.get("transactionId", "0" * 64)
        h.update(bytes.fromhex(txid_hex))
        _write_u32(h, int(prev.get("index", 0)))
    return h.digest()


def _sequences_hash(tx: dict, sighash_type: int) -> bytes:
    if _is_sighash_single(sighash_type) or _is_sighash_anyone_can_pay(sighash_type) or _is_sighash_none(sighash_type):
        return b"\x00" * 32
    h = _tx_signing_hasher()
    for inp in tx.get("inputs", []):
        _write_u64(h, int(inp.get("sequence", 0)))
    return h.digest()


def _sig_op_counts_hash(tx: dict, sighash_type: int) -> bytes:
    if _is_sighash_anyone_can_pay(sighash_type):
        return b"\x00" * 32
    h = _tx_signing_hasher()
    for inp in tx.get("inputs", []):
        _write_u8(h, int(inp.get("sigOpCount", 0)))
    return h.digest()


def _payload_hash(tx: dict) -> bytes:
    subnetwork_hex = tx.get("subnetworkId", "0" * 40)
    payload_hex = tx.get("payload", "")
    payload = bytes.fromhex(payload_hex) if payload_hex else b""
    if subnetwork_hex == "0" * 40 and len(payload) == 0:
        return b"\x00" * 32
    h = _tx_signing_hasher()
    _write_var_bytes(h, payload)
    return h.digest()


def _outputs_hash(tx: dict, sighash_type: int, input_index: int) -> bytes:
    if _is_sighash_none(sighash_type):
        return b"\x00" * 32
    outputs = tx.get("outputs", [])
    if _is_sighash_single(sighash_type):
        if input_index >= len(outputs):
            return b"\x00" * 32
        h = _tx_signing_hasher()
        _hash_output_into(h, outputs[input_index])
        return h.digest()

    h = _tx_signing_hasher()
    for out in outputs:
        _hash_output_into(h, out)
    return h.digest()


def calc_kaspa_schnorr_signature_hash(
    tx: dict,
    input_index: int,
    prev_utxo_amount: int,
    prev_script_pubkey_hex: str,
    prev_script_pubkey_version: int = 0,
    sighash_type: int = SIG_HASH_ALL,
) -> bytes:
    """Consensus sighash for Schnorr signatures (matches `rusty-kaspa`)."""
    h = _tx_signing_hasher()

    _write_u16(h, int(tx.get("version", 0)))
    h.update(_previous_outputs_hash(tx, sighash_type))
    h.update(_sequences_hash(tx, sighash_type))
    h.update(_sig_op_counts_hash(tx, sighash_type))

    inp = tx.get("inputs", [])[input_index]
    prev = inp.get("previousOutpoint", {})
    h.update(bytes.fromhex(prev.get("transactionId", "0" * 64)))
    _write_u32(h, int(prev.get("index", 0)))

    prev_script = bytes.fromhex(prev_script_pubkey_hex) if prev_script_pubkey_hex else b""
    _write_u16(h, int(prev_script_pubkey_version))
    _write_var_bytes(h, prev_script)

    _write_u64(h, int(prev_utxo_amount))
    _write_u64(h, int(inp.get("sequence", 0)))
    _write_u8(h, int(inp.get("sigOpCount", 0)))

    h.update(_outputs_hash(tx, sighash_type, input_index))
    _write_u64(h, int(tx.get("lockTime", 0)))

    subnetwork_hex = tx.get("subnetworkId", "0" * 40)
    h.update(bytes.fromhex(subnetwork_hex))

    _write_u64(h, int(tx.get("gas", 0)))
    h.update(_payload_hash(tx))
    _write_u8(h, int(sighash_type))

    return h.digest()


def sign_kaspa_transaction_input(tx: dict, input_index: int, private_key: bytes, 
                                   utxo_amount: int, script_pubkey: str, sighash_type: int = SIG_HASH_ALL, script_pubkey_version: int = 0) -> dict:
    """
    Sign a Kaspa transaction input using Schnorr signatures (secp256k1).
    
    Implements BIP340-style Schnorr signatures used by Kaspa.
    
    Args:
        tx: Transaction dictionary
        input_index: Index of input to sign
        private_key: 32-byte private key
        utxo_amount: Amount of UTXO being spent in sompi
        script_pubkey: Hex string of script public key of the UTXO
        sighash_type: Signature hash type (0=All, 1=None, 2=Single, 3=AllAnyOneCanPay, etc.)
        
    Returns:
        Transaction dict with signature added to specified input
    """
    import copy
    
    # Create a copy to avoid modifying original
    signed_tx = copy.deepcopy(tx)
    
    # Kaspa uses 1/2/4 (+0x80) sighash types. Historically this code used 0; treat it as ALL.
    if sighash_type == 0:
        sighash_type = SIG_HASH_ALL

    sig_hash = calc_kaspa_schnorr_signature_hash(
        tx=signed_tx,
        input_index=input_index,
        prev_utxo_amount=utxo_amount,
        prev_script_pubkey_hex=script_pubkey,
        prev_script_pubkey_version=int(script_pubkey_version),
        sighash_type=sighash_type,
    )

    signature = schnorr_sign(private_key, sig_hash)

    # signature_script is OP_DATA_65 <64-byte-sig || 1-byte-sighash>
    sig_script_bytes = bytes([65]) + signature + bytes([sighash_type])
    sig_script = sig_script_bytes.hex()
    
    # Add signature to transaction
    signed_tx["inputs"][input_index]["signatureScript"] = sig_script
    
    LOG.debug(f"Signed input #{input_index} with Schnorr signature")
    
    return signed_tx


def schnorr_sign(private_key: bytes, message: bytes) -> bytes:
    """
    Create a Schnorr signature (BIP340-style) over secp256k1.
    
    Args:
        private_key: 32-byte private key
        message: 32-byte message hash to sign
        
    Returns:
        64-byte Schnorr signature (r || s)
    """
    if len(private_key) != 32:
        raise ValueError("private_key must be 32 bytes")
    if len(message) != 32:
        raise ValueError("message must be 32 bytes")

    # Fast path: use coincurve if present (libsecp256k1), but do not require it.
    try:
        import importlib

        coincurve = importlib.import_module("coincurve")
        _CCPrivateKey = getattr(coincurve, "PrivateKey")
        sig = _CCPrivateKey(private_key).sign_schnorr(message)
        if len(sig) != 64:
            raise RuntimeError(f"Unexpected Schnorr signature length: {len(sig)}")
        return sig
    except Exception:
        pass

    # Pure-Python BIP340 signing (spec-correct) using `ecdsa` point arithmetic.
    # This avoids native dependencies (important for Python 3.14 wheels availability).
    n = SECP256k1.order
    d0 = int.from_bytes(private_key, "big")
    if not (1 <= d0 < n):
        raise ValueError("Invalid private key")

    G = SECP256k1.generator

    def tagged_hash(tag: str, data: bytes) -> bytes:
        th = hashlib.sha256(tag.encode("ascii")).digest()
        return hashlib.sha256(th + th + data).digest()

    # Compute public key point and enforce even Y by negating secret if needed
    P0 = d0 * G
    if P0.y() & 1:
        d = n - d0
        P = d * G
    else:
        d = d0
        P = P0

    px = int(P.x()).to_bytes(32, "big")

    # Auxiliary randomness (BIP340). Randomness is not required for validity, only side-channel hardening.
    aux = os.urandom(32)
    t = bytes(a ^ b for a, b in zip(d.to_bytes(32, "big"), tagged_hash("BIP0340/aux", aux)))

    k0 = int.from_bytes(tagged_hash("BIP0340/nonce", t + px + message), "big") % n
    if k0 == 0:
        raise RuntimeError("Nonce generation failed")

    R = k0 * G
    rx = int(R.x()).to_bytes(32, "big")

    k = n - k0 if (R.y() & 1) else k0

    e = int.from_bytes(tagged_hash("BIP0340/challenge", rx + px + message), "big") % n
    s = (k + e * d) % n

    return rx + int(s).to_bytes(32, "big")


def broadcast_transaction(client: RPCClient, tx: dict) -> Optional[str]:
    """
    Broadcast a signed transaction to the Kaspa network.
    
    Args:
        client: Connected RPCClient instance
        tx: Fully signed transaction dictionary
        
    Returns:
        Transaction ID if successful, None otherwise
    """
    try:
        LOG.info("Broadcasting transaction to Kaspa network...")
        
        # Submit transaction via RPC
        response = rpc_request(client, "submitTransactionRequest", {
            "transaction": tx,
            "allowOrphan": False
        })
        
        # Extract transaction ID / error. kaspy versions differ in whether the
        # response is wrapped under "submitTransactionResponse".
        submit_resp = None
        if isinstance(response, dict):
            submit_resp = response.get("submitTransactionResponse")
            if submit_resp is None:
                submit_resp = response

        tx_id = None
        err = None
        if isinstance(submit_resp, dict):
            tx_id = submit_resp.get("transactionId") or submit_resp.get("transactionID")
            err = submit_resp.get("error")

        if tx_id:
            LOG.info("Success: Transaction broadcast successful!")
            LOG.info(f"  Transaction ID: {tx_id}")
            return str(tx_id)

        if err:
            # Best-effort pretty-print for RPCError
            try:
                if isinstance(err, dict):
                    msg = err.get("message") or err.get("msg") or str(err)
                    code = err.get("code")
                    if code is not None:
                        LOG.error("Transaction rejected by kaspad (code=%s): %s", str(code), str(msg))
                    else:
                        LOG.error("Transaction rejected by kaspad: %s", str(msg))
                else:
                    LOG.error("Transaction rejected by kaspad: %s", str(err))
            except Exception:
                LOG.error("Transaction rejected by kaspad (could not format error)")
            return None

        # No txid and no explicit error; log minimal shape for debugging.
        try:
            if isinstance(response, dict):
                LOG.error(
                    "Transaction submission failed - no transaction ID returned (keys=%s)",
                    sorted(list(response.keys())),
                )
            else:
                LOG.error("Transaction submission failed - no transaction ID returned")
        except Exception:
            LOG.error("Transaction submission failed - no transaction ID returned")
        return None
            
    except Exception as e:
        LOG.error(f"Failed to broadcast transaction: {e}")
        return None


# ============================================================================
# TRANSACTION CONSTRUCTION (Helper for Sender)
# ============================================================================

def kpp_tx_construct(sender_utxo: dict, sender_change: str, 
                     receiver_utxo: dict, rec_1: str, rec_2: str,
                     amount: float, dust_addr: str, fee_sompi: int = 1000) -> dict:
    """
    Construct a KPP 2-input, 4-output transaction template.
    
    This is a helper function that returns the transaction structure.
    The SENDER creates and broadcasts this transaction, not the node.
    The node only facilitates the handshake and provides the dust address.
    
    Transaction structure:
    Inputs:
        - Sender's UTXO
        - Receiver's contributed UTXO
    
    Outputs (randomized order):
        - rec_1: First receiver address (random split of amount)
        - rec_2: Second receiver address (remaining of amount)
        - sender_change: Sender's change address
        - dust_addr: Node dust collection (rounded remainder)
    
    Args:
        sender_utxo: Sender's UTXO dictionary
        sender_change: Sender's change address
        receiver_utxo: Receiver's contributed UTXO
        rec_1: First receiver address
        rec_2: Second receiver address
        amount: Payment amount in KAS
        dust_addr: Node's dust collection address
        
    Returns:
        Transaction dictionary ready for signing
    """
    LOG.info("Building KPP transaction template...")

    # NOTE: This function MUST use integer sompi math. Floats can create invalid tx totals.
    SOMPI_PER_KAS = 100_000_000
    DUST_GRANULARITY_SOMPI = 10_000_000  # 0.1 KAS

    # Input validation (lightweight sanity)
    if amount <= 0:
        raise ValueError(f"Invalid amount: {amount} (must be positive)")
    if amount > 100_000_000:
        raise ValueError(f"Amount too large: {amount} KAS (exceeds 100M)")
    if fee_sompi < 0:
        raise ValueError(f"Invalid fee_sompi: {fee_sompi}")

    # Extract UTXO amounts (sompi)
    sender_input_sompi = int(sender_utxo.get("utxoEntry", {}).get("amount", 0) or 0)
    receiver_input_sompi = int(receiver_utxo.get("utxoEntry", {}).get("amount", 0) or 0)

    if sender_input_sompi <= 0:
        raise ValueError("Sender UTXO has zero amount")
    if receiver_input_sompi <= 0:
        raise ValueError("Receiver UTXO has zero amount")

    # Convert requested amount to sompi with rounding to nearest sompi
    payment_sompi = int(round(float(amount) * SOMPI_PER_KAS))
    if payment_sompi <= 0:
        raise ValueError("Payment amount is too small")

    # Round *down* to nearest 0.1 KAS so dust is non-negative
    rounded_payment_sompi = (payment_sompi // DUST_GRANULARITY_SOMPI) * DUST_GRANULARITY_SOMPI
    dust_sompi = payment_sompi - rounded_payment_sompi

    # Keep 4 outputs even when dust is exactly 0
    if dust_sompi == 0:
        dust_sompi = 1

    # Receiver outputs must include BOTH:
    #  - the payment amount
    #  - the receiver's contributed input amount (payjoin accounting)
    receiver_total_out_sompi = rounded_payment_sompi + receiver_input_sompi

    # Sender pays payment + dust + fee via reduced change
    sender_change_sompi = sender_input_sompi - rounded_payment_sompi - dust_sompi - fee_sompi
    if sender_change_sompi <= 0:
        raise ValueError("Sender change is non-positive; insufficient sender input for payment+fee+dust")

    # Split receiver total across two outputs (integer sompi)
    # Keep both outputs >= 1 sompi.
    min_each = 1
    if receiver_total_out_sompi < (2 * min_each):
        raise ValueError("Receiver total output too small to split")

    # Choose split in [30%, 70%]
    lo = int(receiver_total_out_sompi * 0.30)
    hi = int(receiver_total_out_sompi * 0.70)
    lo = max(lo, min_each)
    hi = min(hi, receiver_total_out_sompi - min_each)
    if lo > hi:
        # Fallback to near-even split
        rec_1_sompi = receiver_total_out_sompi // 2
    else:
        rec_1_sompi = lo + secrets.randbelow(hi - lo + 1)
    rec_2_sompi = receiver_total_out_sompi - rec_1_sompi
    
    # Convert addresses to script public keys
    rec_1_script = address_to_script_public_key(rec_1)
    rec_2_script = address_to_script_public_key(rec_2)
    sender_change_script = address_to_script_public_key(sender_change)
    dust_script = address_to_script_public_key(dust_addr)
    
    # Build outputs list (will be randomized for privacy)
    outputs = [
        {
            "amount": int(rec_1_sompi),
            "scriptPublicKey": {
                "version": 0,
                "scriptPublicKey": rec_1_script.hex()
            },
            "_label": "receiver_1"  # For logging only, removed before returning
        },
        {
            "amount": int(rec_2_sompi),
            "scriptPublicKey": {
                "version": 0,
                "scriptPublicKey": rec_2_script.hex()
            },
            "_label": "receiver_2"
        },
        {
            "amount": int(sender_change_sompi),
            "scriptPublicKey": {
                "version": 0,
                "scriptPublicKey": sender_change_script.hex()
            },
            "_label": "sender_change"
        },
        {
            "amount": int(dust_sompi),
            "scriptPublicKey": {
                "version": 0,
                "scriptPublicKey": dust_script.hex()
            },
            "_label": "dust_collection"
        }
    ]
    
    # Randomly shuffle outputs to prevent order-based analysis
    secrets.SystemRandom().shuffle(outputs)
    
    # Log randomized order (for debugging)
    output_order = [out["_label"] for out in outputs]
    LOG.debug(f"  Output order (randomized): {output_order}")
    
    # Remove labels before building transaction
    for output in outputs:
        del output["_label"]
    
    # Build transaction structure using Kaspa RPC format
    tx = {
        "version": 0,
        "inputs": [
            {
                "previousOutpoint": {
                    "transactionId": sender_utxo.get("outpoint", {}).get("transactionId", ""),
                    "index": sender_utxo.get("outpoint", {}).get("index", 0)
                },
                "signatureScript": "",  # Sender will fill this
                "sequence": 0,
                "sigOpCount": 1
            },
            {
                "previousOutpoint": {
                    "transactionId": receiver_utxo.get("outpoint", {}).get("transactionId", ""),
                    "index": receiver_utxo.get("outpoint", {}).get("index", 0)
                },
                "signatureScript": "",  # Receiver will fill this
                "sequence": 0,
                "sigOpCount": 1
            }
        ],
        "outputs": outputs,
        "lockTime": 0,
        "subnetworkId": "0000000000000000000000000000000000000000",
        "gas": 0,
        "payload": ""
    }
    
    LOG.info("Success: Transaction template built: 2 inputs, 4 outputs")
    LOG.info(f"  Payment (rounded down): {rounded_payment_sompi / SOMPI_PER_KAS:.8f} KAS")
    LOG.info(f"  Receiver contributed input: {receiver_input_sompi / SOMPI_PER_KAS:.8f} KAS")
    LOG.info(f"  Receiver total out: {receiver_total_out_sompi / SOMPI_PER_KAS:.8f} KAS")
    LOG.info(f"  Sender change: {sender_change_sompi / SOMPI_PER_KAS:.8f} KAS")
    LOG.info(f"  Fee (assumed): {fee_sompi / SOMPI_PER_KAS:.8f} KAS")
    LOG.info(f"  Dust to node: {dust_sompi / SOMPI_PER_KAS:.8f} KAS")
    
    return tx


# ============================================================================
# NODE OPERATIONS
# ============================================================================

def node_pulse(client: RPCClient, wallet: KloakWallet, websocket_url: str = None):
    """
    Broadcast pulse transaction to Kaspa network to indicate node presence.
    
    Each pulse uses a different address for privacy. The pulse contains metadata
    in the transaction payload including the node's WebSocket URL for discovery.
    
    Args:
        client: Connected RPCClient instance
        wallet: KloakWallet instance for funding the pulse
        websocket_url: Node WebSocket URL (auto-detected if not provided)
        
    Returns:
        Pulse transaction dict or None if failed
    """
    LOG.info("Broadcasting node pulse...")
    
    try:
        # Pulse funding model:
        # - Each pulse spends from the *previous pulse destination* address (pulse_source_index)
        # - And sends to a fresh new pulse address (no reuse)
        def _utxo_amount_sompi(u: dict) -> int:
            try:
                return int((u or {}).get("utxoEntry", {}).get("amount", 0) or 0)
            except Exception:
                return 0

        def _pick_smallest(utxos: list) -> Optional[dict]:
            if not utxos:
                return None
            return sorted(utxos, key=_utxo_amount_sompi)[0]

        def _select_pulse_source_utxo() -> Tuple[Optional[int], Optional[dict]]:
            # Candidate indices, in priority order.
            candidates: list[int] = []
            try:
                idx = int(getattr(wallet, "pulse_source_index", 0) or 0)
            except Exception:
                idx = 0
            if 0 <= idx < len(wallet.addresses):
                candidates.append(idx)
            if 0 not in candidates and 0 < len(wallet.addresses):
                candidates.append(0)

            # Recovery: search recent pulse addresses that have been used.
            # This is a slow-path used only if the stored index has no UTXO.
            try:
                for entry in reversed(wallet.addresses):
                    if entry.get("purpose") == "pulse" and entry.get("used"):
                        entry_idx = int(entry.get("index", -1))
                        if 0 <= entry_idx < len(wallet.addresses):
                            candidates.append(entry_idx)
                        if len(candidates) >= 30:
                            break
            except Exception:
                pass

            seen: set[int] = set()
            uniq: list[int] = []
            for i in candidates:
                if i not in seen:
                    seen.add(i)
                    uniq.append(i)

            for i in uniq:
                addr = wallet.addresses[i].get("address")
                if not addr:
                    continue
                utxos = get_utxos_by_address(client, addr)
                utxo = _pick_smallest(utxos)
                if utxo is not None:
                    return i, utxo
            return None, None

        source_index, pulse_utxo = _select_pulse_source_utxo()
        if pulse_utxo is None or source_index is None:
            LOG.error("No UTXOs available for pulse. Node needs funding.")
            return False

        source_addr = wallet.addresses[source_index].get("address")
        if not source_addr:
            LOG.error("Pulse failed: missing source address")
            return None
        
        input_amount = _utxo_amount_sompi(pulse_utxo)  # in sompi
        
        # Pulse metadata: node info in payload
        if websocket_url is None:
            websocket_url = get_websocket_url()  # Auto-detect public IP
        
        pulse_metadata = {
            "protocol": "kloak",
            "version": CONFIG["VERSION"],
            "ws_url": websocket_url,
            "timestamp": int(time.time())
        }
        
        # Encode metadata as hex
        payload_hex = json.dumps(pulse_metadata).encode().hex()
        
        # Get next unused address for this pulse (privacy: never reuse)
        pulse_index, pulse_addr = wallet.get_next_unused_address(purpose="pulse")
        wallet.mark_address_used(pulse_index, purpose="pulse")
        LOG.info(f"Pulse will be sent to fresh address: {pulse_addr}")
        
        # Get the script public key for the pulse address
        # For Kaspa P2PK, we need to create the locking script from the public key
        pulse_priv_key = bytes.fromhex(wallet.addresses[pulse_index]["private_key"])
        pulse_pubkey = private_key_to_public_key(pulse_priv_key)
        
        # Build P2PK script using helper function
        pulse_script = pubkey_to_script_public_key(pulse_pubkey)
        
        # Estimate fee using network fee estimates
        fee = estimate_transaction_fee(client, num_inputs=1, num_outputs=1, priority="normal")
        if input_amount <= fee:
            LOG.error(
                "Pulse failed: input too small for fee (input=%s sompi, fee=%s sompi)",
                str(input_amount),
                str(fee),
            )
            return None
        output_amount = int(input_amount) - int(fee)
        
        # Build pulse transaction (tx to fresh address with metadata)
        # Note: Kaspa uses camelCase for JSON serialization
        pulse_tx = {
            "version": 0,
            "inputs": [
                {
                    "previousOutpoint": {
                        "transactionId": pulse_utxo.get("outpoint", {}).get("transactionId", ""),
                        "index": pulse_utxo.get("outpoint", {}).get("index", 0)
                    },
                    "signatureScript": "",  # Will be filled by signing
                    "sequence": 0,
                    "sigOpCount": 1
                }
            ],
            "outputs": [
                {
                    "amount": int(output_amount),
                    "scriptPublicKey": {
                        "version": 0,
                        "scriptPublicKey": pulse_script.hex()  # P2PK script for the pulse address
                    }
                }
            ],
            "lockTime": 0,
            "subnetworkId": "0000000000000000000000000000000000000000",
            "gas": 0,
            "payload": payload_hex
        }
        
        # Sign transaction with the source address private key
        source_priv_key = bytes.fromhex(wallet.addresses[source_index]["private_key"])
        spk_version, script_pubkey = get_utxo_script_pubkey(pulse_utxo)
        
        LOG.info("Signing pulse transaction...")
        signed_tx = sign_kaspa_transaction_input(
            pulse_tx,
            input_index=0,
            private_key=source_priv_key,
            utxo_amount=input_amount,
            script_pubkey=script_pubkey,
            script_pubkey_version=spk_version,
        )
        
        LOG.info(f"Success: Pulse transaction signed")
        LOG.info(f"  From: {source_addr}")
        LOG.info(f"  To: {pulse_addr}")
        LOG.info(f"  Amount: {output_amount/100000000:.8f} KAS")
        LOG.info(f"  Fee: {fee/100000000:.8f} KAS")
        LOG.info(f"  Metadata: {websocket_url}")
        
        # Broadcast the transaction
        tx_id = broadcast_transaction(client, signed_tx)
        
        if tx_id:
            LOG.info(f"Success: Pulse broadcast successful!")
            LOG.info(f"  Transaction ID: {tx_id}")
            LOG.info(f"  Next pulse in {CONFIG['PULSE_INTERVAL_SECONDS']/3600:.1f} hours")

            # Advance the pulse chain: next pulse will spend from this new address.
            try:
                wallet.pulse_source_index = int(pulse_index)
            except Exception:
                wallet.pulse_source_index = pulse_index

            # Persist wallet state so the node can resume the chain after restart.
            try:
                if wallet_passphrase:
                    try:
                        loop = asyncio.get_running_loop()

                        async def _autosave() -> None:
                            global wallet_lock
                            if wallet_lock is None:
                                wallet_lock = asyncio.Lock()
                            try:
                                async with wallet_lock:
                                    await asyncio.to_thread(save_wallet, wallet, wallet_passphrase)
                            except Exception as save_exc:
                                LOG.warning(f"Wallet auto-save failed: {save_exc}")

                        loop.create_task(_autosave())
                    except RuntimeError:
                        threading.Thread(
                            target=save_wallet,
                            args=(wallet, wallet_passphrase),
                            daemon=True,
                        ).start()
            except Exception:
                pass

            return tx_id
        else:
            LOG.error("Pulse broadcast failed")
            return None
        
    except Exception as e:
        LOG.error(f"Pulse failed: {e}")
        return None


def node_fund(client: RPCClient, wallet: KloakWallet) -> str:
    """
    Get funding address for the node.
    
    Args:
        client: Connected RPCClient instance (unused but kept for consistency)
        wallet: KloakWallet instance
        
    Returns:
        Primary funding address (first address in wallet)
    """
    # Fund the *current pulse source* so the next pulse can spend it.
    idx = int(getattr(wallet, "pulse_source_index", 0) or 0)
    if idx < 0 or idx >= len(wallet.addresses):
        idx = 0
    funding_addr = wallet.addresses[idx]["address"]
    LOG.info(f"Node funding address: {funding_addr}")
    LOG.info(f"Please send at least {CONFIG['FUND_AMOUNT_KAS']} KAS to this address")
    return funding_addr


def node_sweep(client: RPCClient, wallet: KloakWallet, dest_addr: str, amount: float):
    """
    Construct transaction to withdraw node funds while maintaining minimum reserve.
    
    Creates a transaction to sweep accumulated funds to an external address while
    leaving behind FUND_AMOUNT_KAS to keep the node operational.
    
    Args:
        client: Connected RPCClient instance
        wallet: KloakWallet instance
        dest_addr: Destination Kaspa address
        amount: Amount to sweep in KAS
        
    Returns:
        Sweep transaction dict or None if failed
    """
    LOG.info(f"Constructing sweep transaction: {amount} KAS to {dest_addr}...")
    
    try:
        # Sweep from the current pulse source address (where the node's funds sit).
        idx = int(getattr(wallet, "pulse_source_index", 0) or 0)
        if idx < 0 or idx >= len(wallet.addresses):
            idx = 0
        node_addr = wallet.addresses[idx]["address"]
        balance = get_address_balance(client, node_addr)
        utxos = get_utxos_by_address(client, node_addr)
        
        if balance < CONFIG["FUND_AMOUNT_KAS"] + amount:
            LOG.error(f"Insufficient funds. Balance: {balance} KAS, need {CONFIG['FUND_AMOUNT_KAS'] + amount} KAS")
            return None
        
        # Select UTXOs to cover amount (simple selection - use all)
        selected_utxos = []
        total_input = 0
        amount_sompi = int(amount * 100000000)
        
        for utxo in utxos:
            try:
                utxo_amount = int(utxo.get("utxoEntry", {}).get("amount", 0) or 0)
            except Exception:
                utxo_amount = 0
            selected_utxos.append(utxo)
            total_input += utxo_amount
            
            if total_input >= amount_sompi:
                break
        
        if total_input < amount_sompi:
            LOG.error(f"Insufficient UTXOs to cover {amount} KAS")
            return None
        
        # Build inputs
        inputs = []
        for utxo in selected_utxos:
            inputs.append({
                "previousOutpoint": {
                    "transactionId": utxo.get("outpoint", {}).get("transactionId", ""),
                    "index": utxo.get("outpoint", {}).get("index", 0)
                },
                "signatureScript": "",  # Would sign with wallet private key
                "sequence": 0,
                "sigOpCount": 1
            })
        
        # Calculate outputs using network fee estimates
        fee_sompi = estimate_transaction_fee(client, num_inputs=len(inputs), num_outputs=2, priority="normal")
        
        # Output to destination
        output_to_dest = amount_sompi
        
        # Change back to node (keep reserve)
        change_sompi = total_input - amount_sompi - fee_sompi
        reserve_sompi = int(CONFIG["FUND_AMOUNT_KAS"] * 100000000)
        
        if change_sompi < reserve_sompi:
            LOG.error(f"Would leave less than reserve amount. Aborting.")
            return None
        
        # Convert addresses to script public keys
        dest_script = address_to_script_public_key(dest_addr)
        node_script = address_to_script_public_key(node_addr)
        
        # Build outputs
        outputs = [
            {
                "amount": int(output_to_dest),
                "scriptPublicKey": {
                    "version": 0,
                    "scriptPublicKey": dest_script.hex()
                }
            },
            {
                "amount": int(change_sompi),
                "scriptPublicKey": {
                    "version": 0,
                    "scriptPublicKey": node_script.hex()
                }
            }
        ]
        
        # Build sweep transaction
        sweep_tx = {
            "version": 0,
            "inputs": inputs,
            "outputs": outputs,
            "lockTime": 0,
            "subnetworkId": "0000000000000000000000000000000000000000",
            "gas": 0,
            "payload": ""
        }
        
        LOG.info(f"Signing sweep transaction with {len(inputs)} input(s)...")
        
        # Sign all inputs with node private key
        node_priv_key = bytes.fromhex(wallet.addresses[idx]["private_key"])
        
        for i, utxo in enumerate(selected_utxos):
            try:
                utxo_amount = int(utxo.get("utxoEntry", {}).get("amount", 0) or 0)
            except Exception:
                utxo_amount = 0
            spk_version, script_pubkey = get_utxo_script_pubkey(utxo)
            
            sweep_tx = sign_kaspa_transaction_input(
                sweep_tx,
                input_index=i,
                private_key=node_priv_key,
                utxo_amount=utxo_amount,
                script_pubkey=script_pubkey,
                script_pubkey_version=spk_version,
            )
        
        LOG.info(f"Success: Sweep transaction signed")
        LOG.info(f"  Sweeping: {amount} KAS to {dest_addr}")
        LOG.info(f"  Change: {change_sompi/100000000:.4f} KAS (reserve: {CONFIG['FUND_AMOUNT_KAS']} KAS)")
        LOG.info(f"  Using {len(inputs)} input(s), fee: {fee_sompi/100000000:.4f} KAS")
        
        # Broadcast the transaction
        tx_id = broadcast_transaction(client, sweep_tx)
        
        if tx_id:
            LOG.info(f"Success: Sweep broadcast successful!")
            LOG.info(f"  Transaction ID: {tx_id}")
            return tx_id
        else:
            LOG.error("Sweep broadcast failed")
            return None
        
    except Exception as e:
        LOG.error(f"Sweep failed: {e}")
        return None


def node_sweep_drain(client: RPCClient, wallet: KloakWallet, dest_addr: str):
    """Drain node funds to destination, leaving only the minimum reserve.

    Sweeps ALL UTXOs from the node's current pulse source address, leaving
    `CONFIG['FUND_AMOUNT_KAS']` behind (plus the required fee).
    """
    try:
        idx = int(getattr(wallet, "pulse_source_index", 0) or 0)
        if idx < 0 or idx >= len(wallet.addresses):
            idx = 0
        node_addr = wallet.addresses[idx]["address"]
        utxos = get_utxos_by_address(client, node_addr)
        if not utxos:
            LOG.error("Sweep failed: no UTXOs")
            return None

        # Spend *all* UTXOs so the wallet is drained (except reserve).
        inputs = []
        selected_utxos = []
        total_input = 0
        for utxo in utxos:
            try:
                utxo_amount = int(utxo.get("utxoEntry", {}).get("amount", 0) or 0)
            except Exception:
                utxo_amount = 0
            if utxo_amount <= 0:
                continue
            selected_utxos.append(utxo)
            total_input += utxo_amount
            inputs.append({
                "previousOutpoint": {
                    "transactionId": utxo.get("outpoint", {}).get("transactionId", ""),
                    "index": utxo.get("outpoint", {}).get("index", 0)
                },
                "signatureScript": "",
                "sequence": 0,
                "sigOpCount": 1
            })

        if not inputs or total_input <= 0:
            LOG.error("Sweep failed: no spendable UTXOs")
            return None

        reserve_sompi = int(CONFIG["FUND_AMOUNT_KAS"] * SOMPI_PER_KAS)
        fee_sompi = estimate_transaction_fee(client, num_inputs=len(inputs), num_outputs=2, priority="normal")

        # Destination gets everything except reserve + fee.
        output_to_dest = int(total_input) - int(reserve_sompi) - int(fee_sompi)
        if output_to_dest <= 0:
            LOG.error(
                "Sweep failed: insufficient funds after reserve+fee (in=%s, reserve=%s, fee=%s)",
                str(total_input),
                str(reserve_sompi),
                str(fee_sompi),
            )
            return None

        dest_script = address_to_script_public_key(dest_addr)
        node_script = address_to_script_public_key(node_addr)

        outputs = [
            {
                "amount": int(output_to_dest),
                "scriptPublicKey": {
                    "version": 0,
                    "scriptPublicKey": dest_script.hex()
                }
            },
            {
                "amount": int(reserve_sompi),
                "scriptPublicKey": {
                    "version": 0,
                    "scriptPublicKey": node_script.hex()
                }
            }
        ]

        sweep_tx = {
            "version": 0,
            "inputs": inputs,
            "outputs": outputs,
            "lockTime": 0,
            "subnetworkId": "0000000000000000000000000000000000000000",
            "gas": 0,
            "payload": ""
        }

        LOG.info(f"Signing drain-sweep transaction with {len(inputs)} input(s)...")
        node_priv_key = bytes.fromhex(wallet.addresses[idx]["private_key"])
        for i, utxo in enumerate(selected_utxos):
            try:
                utxo_amount = int(utxo.get("utxoEntry", {}).get("amount", 0) or 0)
            except Exception:
                utxo_amount = 0
            spk_version, script_pubkey = get_utxo_script_pubkey(utxo)
            sweep_tx = sign_kaspa_transaction_input(
                sweep_tx,
                input_index=i,
                private_key=node_priv_key,
                utxo_amount=utxo_amount,
                script_pubkey=script_pubkey,
                script_pubkey_version=spk_version,
            )

        LOG.info("Success: Drain-sweep transaction signed")
        LOG.info(f"  To: {dest_addr}")
        LOG.info(f"  Reserve kept: {reserve_sompi / SOMPI_PER_KAS:.8f} KAS")
        LOG.info(f"  Swept: {output_to_dest / SOMPI_PER_KAS:.8f} KAS")
        LOG.info(f"  Fee: {fee_sompi / SOMPI_PER_KAS:.8f} KAS")

        tx_id = broadcast_transaction(client, sweep_tx)
        if tx_id:
            LOG.info("Success: Drain-sweep broadcast successful!")
            LOG.info(f"  Transaction ID: {tx_id}")
            return tx_id

        LOG.error("Drain-sweep broadcast failed")
        return None
    except Exception as e:
        LOG.error(f"Drain-sweep failed: {e}")
        return None


def dust_injection(wallet: KloakWallet) -> Tuple[int, str]:
    """
    Derive a unique dust collection address for a KPP transaction.
    
    Each connection gets a unique address that is never reused, ensuring
    privacy and proper tracking of dust collection revenue.
    
    IMPORTANT: Wallet is automatically saved after dust generation to prevent
    revenue loss if node crashes before next manual save.
    
    Args:
        wallet: KloakWallet instance
        
    Returns:
        Tuple of (address_index, address_string)
    """
    # Get next unused address
    index, dust_addr = wallet.get_next_unused_address(purpose="dust_collection")
    
    # Mark it as used immediately
    wallet.mark_address_used(index, purpose="dust_collection")
    
    LOG.info(f"Dust address #{index}: {dust_addr}")
    LOG.debug(f"  Used addresses: {wallet.highest_used_index + 1}/{len(wallet.addresses)}")
    
    # Auto-save wallet to persist dust address (prevent revenue loss on crash)
    # Note: This requires access to passphrase, which is stored in memory during node operation
    # Wallet auto-save is handled by the caller (ws_handshake) to avoid blocking
    
    return index, dust_addr


async def websocket_connect(ws_url: str) -> websockets.WebSocketClientProtocol:
    """Connect to WebSocket (direct) with conservative safety limits."""
    normalized = _normalize_ws_url(ws_url)
    url = normalized or (ws_url.strip() if isinstance(ws_url, str) else "")
    if not url:
        raise ValueError("ws_url is required")

    connect_timeout = float(WS_HANDSHAKE_TIMEOUT_SECONDS)
    LOG.info(f"Connecting to {url} (direct)...")
    try:
        return await asyncio.wait_for(
            websockets.connect(
                url,
                max_size=WS_MAX_MESSAGE_BYTES,
                max_queue=32,
                ping_interval=20,
                ping_timeout=20,
                open_timeout=connect_timeout,
                close_timeout=10,
            ),
            timeout=connect_timeout + 5.0,
        )
    except Exception as e:
        raise ConnectionError(f"Failed to connect to {url}: {e}") from e


# ============================================================================
# E2EE ENCRYPTION
# ============================================================================

def new_e2ee_key() -> Tuple[str, bytes]:
    """
    Generate a new single-use end-to-end encryption key for KPP handshake.
    
    Returns:
        Tuple of (key_id, raw_key_bytes)
    """
    key = ChaCha20Poly1305.generate_key()
    key_id = secrets.token_urlsafe(16)
    return key_id, key


def encrypt_message(key: bytes, message: dict) -> str:
    """
    Encrypt a message using ChaCha20-Poly1305 AEAD.
    
    Args:
        key: 32-byte encryption key
        message: Message dict to encrypt
        
    Returns:
        Base64-encoded encrypted message (nonce + ciphertext)
    """
    cipher = ChaCha20Poly1305(key)
    nonce = secrets.token_bytes(12)
    
    plaintext = json.dumps(message).encode()
    ciphertext = cipher.encrypt(nonce, plaintext, None)
    
    # Combine nonce + ciphertext and encode
    encrypted = base64.b64encode(nonce + ciphertext).decode()
    return encrypted


def decrypt_message(key: bytes, encrypted: str) -> dict:
    """
    Decrypt a message using ChaCha20-Poly1305 AEAD.
    
    Args:
        key: 32-byte decryption key
        encrypted: Base64-encoded encrypted message
        
    Returns:
        Decrypted message dict
    """
    cipher = ChaCha20Poly1305(key)
    
    data = base64.b64decode(encrypted)
    nonce = data[:12]
    ciphertext = data[12:]
    
    plaintext = cipher.decrypt(nonce, ciphertext, None)
    message = json.loads(plaintext.decode())
    return message


# ============================================================================
# WEBSOCKET SERVER
# ============================================================================

async def ws_handshake(websocket: ServerConnection):
    """
    Handle incoming WebSocket connections from senders and receivers.
    
    Implements E2EE handshake and transaction coordination between sender and receiver.
    Manages session state, dust address generation, and message relay.
    
    Improved flow:
    1. Receiver connects, gets dust address, provides UTXO
    2. Receiver added to pending_receivers pool
    3. Sender connects, finds available receiver
    4. Node builds transaction, sends to both parties
    5. Receiver signs first, sends signature to sender (via node relay)
    6. Sender signs second, broadcasts transaction
    7. Sender notifies receiver of broadcast result
    
    Args:
        websocket: WebSocket connection from client
    """
    global session_lock, wallet_lock
    if session_lock is None:
        session_lock = asyncio.Lock()
    if wallet_lock is None:
        wallet_lock = asyncio.Lock()
    
    session_id = secrets.token_hex(8)
    path = getattr(getattr(websocket, "request", None), "path", None)
    LOG.info(f"[{session_id}] New WebSocket connection from {websocket.remote_address} path={path}")
    
    try:
        # Receive initial handshake (bounded)
        init_msg = await asyncio.wait_for(websocket.recv(), timeout=WS_HANDSHAKE_TIMEOUT_SECONDS)
        init_data = json.loads(init_msg)
        
        role = init_data.get("role")  # 'sender' or 'receiver'
        matching_session_id = init_data.get("session_id")
        
        if not matching_session_id:
            await websocket.send(json.dumps({"error": "Missing session_id"}))
            return
        
        LOG.info(f"[{session_id}] Role: {role}, Matching session: {matching_session_id[:8]}...")
        
        # NOTE: Node NEVER receives the E2EE key!
        # Wallets encrypt messages to each other with E2EE key
        # Node just relays encrypted messages it cannot decrypt
        
        async def _relay(src_ws: ServerConnection, dst_ws: ServerConnection, tag: str):
            try:
                async for msg in src_ws:
                    await dst_ws.send(msg)
            except websockets.exceptions.ConnectionClosed:
                LOG.debug(f"[{session_id}] Relay closed ({tag})")
            except Exception as e:
                LOG.debug(f"[{session_id}] Relay error ({tag}): {e}")

        async def _bridge(sender_ws: ServerConnection, receiver_ws: ServerConnection):
            t1 = asyncio.create_task(_relay(sender_ws, receiver_ws, "sender->receiver"))
            t2 = asyncio.create_task(_relay(receiver_ws, sender_ws, "receiver->sender"))
            done, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
            for p in pending:
                p.cancel()
            try:
                await sender_ws.close()
            except Exception:
                pass
            try:
                await receiver_ws.close()
            except Exception:
                pass

        if role == "receiver":
            # Generate unique dust address for this session (never reused)
            async with wallet_lock:
                dust_index, dust_addr = dust_injection(wallet_data)

            # Persist immediately so a crash doesn't lose the allocation.
            # Serialize saves under wallet_lock to avoid concurrent writes.
            if wallet_passphrase:
                async def _autosave() -> None:
                    global wallet_lock
                    if wallet_lock is None:
                        wallet_lock = asyncio.Lock()
                    try:
                        async with wallet_lock:
                            await asyncio.to_thread(save_wallet, wallet_data, wallet_passphrase)
                    except Exception as save_exc:
                        LOG.warning(f"Wallet auto-save failed: {save_exc}")

                asyncio.create_task(_autosave())
            
            # Don't send dust address to receiver - they don't need it!
            # Only sender needs it to build the transaction
            
            # Wait for receiver's UTXO and addresses (encrypted wallet→wallet data)
            encrypted_data = await asyncio.wait_for(websocket.recv(), timeout=WS_RECV_TIMEOUT_SECONDS)
            # Node stores encrypted data as-is, doesn't decrypt it
            receiver_encrypted_data = encrypted_data
            
            LOG.info(f"[{session_id}] Received encrypted receiver data")
            
            # Store receiver in pending pool, KEYED BY SESSION_ID
            # Node never sees E2EE key, just matches by session_id
            paired_event = asyncio.Event()
            async with session_lock:
                # Defensive: Check for collision (astronomically unlikely with 256-bit random)
                if matching_session_id in pending_receivers:
                    LOG.error(f"[{session_id}] CRITICAL: Session ID collision detected! {matching_session_id[:8]}...")
                    # This should never happen - if it does, reject to prevent security breach
                    error_response = json.dumps({
                        "error": "Session collision",
                        "message": "Please regenerate QR code and try again"
                    })
                    await websocket.send(error_response)
                    return

                # Keep a local reference to this dict so we can await the bridge task
                # even after the sender pops the entry from pending_receivers.
                receiver_entry = {
                    "session_id": session_id,
                    "role": "receiver",
                    "websocket": websocket,
                    "encrypted_data": receiver_encrypted_data,  # Node can't decrypt this
                    "dust_addr": dust_addr,
                    "dust_index": dust_index,
                    "timestamp": time.time(),
                    "paired": paired_event,
                    "sender_ws": None,
                    "bridge_task": None,
                }

                pending_receivers[matching_session_id] = receiver_entry
            
            LOG.info(f"[{session_id}] Receiver in pending pool (session: {matching_session_id[:8]}..., {len(pending_receivers)} waiting)")
            
            # Wait for sender to pair, then hold connection open while bridge runs.
            try:
                await asyncio.wait_for(paired_event.wait(), timeout=PENDING_SESSION_TTL_SECONDS)
            except asyncio.TimeoutError:
                LOG.info(f"[{session_id}] Receiver session timed out waiting for sender")
                await websocket.close()
                return

            # Sender handler owns the bridge task; receiver handler just waits for it.
            bridge_task = None
            try:
                bridge_task = receiver_entry.get("bridge_task")
            except Exception:
                bridge_task = None

            if bridge_task is not None:
                await bridge_task
            return
            
        elif role == "sender":
            # Find the MATCHING receiver using session_id from QR code
            receiver_session = None
            
            async with session_lock:
                # Look up receiver by session_id
                if matching_session_id in pending_receivers:
                    receiver_session = pending_receivers.pop(matching_session_id)
                    receiver_sid = receiver_session["session_id"]
                    LOG.info(f"[{session_id}] Matched with receiver [{receiver_sid}] via session_id: {matching_session_id[:8]}...")
                else:
                    LOG.warning(f"[{session_id}] No matching receiver for session_id: {matching_session_id[:8]}...")
            
            if not receiver_session:
                error_msg = json.dumps({
                    "error": "No matching receiver waiting",
                    "message": "The receiver may have disconnected or the QR code is invalid. Please ask the receiver to reconnect and try again."
                })
                await websocket.send(error_msg)
                LOG.warning(f"[{session_id}] No receiver found for session {matching_session_id[:8]}...")
                return
            
            # Send dust address to sender (plain JSON - sender needs this to build tx)
            dust_msg = json.dumps({
                "type": "dust_address",
                "address": receiver_session["dust_addr"]
            })
            await websocket.send(dust_msg)
            LOG.info(f"[{session_id}] Sent dust address to sender")
            
            # Forward receiver's encrypted data to sender (node can't decrypt it)
            await websocket.send(receiver_session["encrypted_data"])
            LOG.info(f"[{session_id}] Forwarded receiver's encrypted data to sender")

            # Start transparent relay for the rest of the protocol.
            receiver_ws = receiver_session["websocket"]
            bridge_task = asyncio.create_task(_bridge(websocket, receiver_ws))

            # Signal receiver handler that pairing is complete.
            paired_event = receiver_session.get("paired")
            if paired_event:
                receiver_session["sender_ws"] = websocket
                receiver_session["bridge_task"] = bridge_task
                paired_event.set()

            LOG.info(f"[{session_id}] Bridge active; relaying encrypted messages")
            await bridge_task
            return
    
    except websockets.exceptions.ConnectionClosed:
        LOG.info(f"[{session_id}] Connection closed")
    except Exception as e:
        LOG.error(f"[{session_id}] Error in handshake: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Clean up sessions - use try/except to handle cleanup failures gracefully
        try:
            async with session_lock:
                # Remove from pending_receivers if still there (by session_id)
                # We need to search for it since we might not have matching_session_id in scope
                to_remove = [k for k, v in pending_receivers.items() if v.get("session_id") == session_id]
                for k in to_remove:
                    del pending_receivers[k]
                    LOG.debug(f"[{session_id}] Removed from pending receivers")

                try:
                    if session_id in active_sessions:
                        del active_sessions[session_id]
                        LOG.debug(f"[{session_id}] Removed from active sessions")
                except Exception as cleanup_error:
                    LOG.error(f"[{session_id}] Error cleaning active sessions: {cleanup_error}")
        except Exception as cleanup_error:
            LOG.error(f"[{session_id}] Error during session cleanup: {cleanup_error}")


async def start_websocket_server(port: int = None):
    """
    Start the WebSocket server for KPP handshakes.
    
    Args:
        port: Port to listen on (defaults to CONFIG["WEBSOCKET_PORT"])
    """
    if port is None:
        port = CONFIG["WEBSOCKET_PORT"]

    bind_host = CONFIG.get("WEBSOCKET_BIND") or "0.0.0.0"
    
    LOG.info(f"Starting WebSocket server on port {port}...")

    try:
        async with serve(
            ws_handshake,
            bind_host,
            port,
            max_size=WS_MAX_MESSAGE_BYTES,
            max_queue=32,
            ping_interval=20,
            ping_timeout=20,
        ):
            LOG.info(f"Success: WebSocket server running on ws://{bind_host}:{port}")
            await asyncio.Future()  # Run forever
    except OSError as e:
        # Windows: WinError 10048 (address already in use)
        msg = str(e)
        if "10048" in msg or "Address already in use" in msg:
            LOG.error(
                f"WebSocket port {port} is already in use. "
                "Another KloakNode instance may already be running, or another app is using the port. "
                "Stop the other process or change CONFIG['WEBSOCKET_PORT']."
            )
        raise


async def run_node_server(wallet: KloakWallet, client: RPCClient):
    """
    Run the Kloak node server with WebSocket and periodic pulse.
    
    Starts the WebSocket server for handling KPP connections and begins
    periodic pulse transmission to announce node presence on the network.
    
    Args:
        wallet: KloakWallet instance for node operations
        client: Connected RPCClient instance
    """
    LOG.info("="*60)
    LOG.info("KLOAK NODE STARTING")
    LOG.info("="*60)
    LOG.info(f"Version: {CONFIG['VERSION']}")
    LOG.info(f"WebSocket: ws://{CONFIG.get('WEBSOCKET_BIND','0.0.0.0')}:{CONFIG['WEBSOCKET_PORT']}")
    LOG.info(f"Pulse interval: {CONFIG['PULSE_INTERVAL_SECONDS']/3600:.1f} hours")
    LOG.info(f"Primary address: {wallet.addresses[0]['address']}")
    try:
        idx = int(getattr(wallet, "pulse_source_index", 0) or 0)
    except Exception:
        idx = 0
    if 0 <= idx < len(wallet.addresses):
        LOG.info(f"Pulse source address: {wallet.addresses[idx]['address']}")
    LOG.info("="*60)

    # Create the pulse trigger event eagerly so ws_handshake can request an
    # immediate pulse even if a wallet connects extremely quickly at startup.
    global _pulse_trigger_event
    if _pulse_trigger_event is None:
        _pulse_trigger_event = asyncio.Event()

    # Ensure wallet_lock exists for background tasks (pulse + operator commands).
    global wallet_lock
    if wallet_lock is None:
        wallet_lock = asyncio.Lock()

    # Request the first pulse immediately on node start (after wallet is unlocked
    # and RPC client exists). The pulse loop will skip if not funded.
    _request_immediate_pulse(reason="node_startup")

    async def websocket_server_supervisor() -> None:
        """Keep the WebSocket server running; restart on failure."""
        backoff = 1.0
        max_backoff = 30.0
        while True:
            try:
                await start_websocket_server()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                msg = str(e)
                delay = backoff
                # If we can't bind (port in use), don't hot-loop; keep trying.
                if isinstance(e, OSError) and ("10048" in msg or "Address already in use" in msg):
                    delay = max(delay, 10.0)
                LOG.error(f"WebSocket server crashed: {e}. Restarting in {delay:.1f}s")
                await asyncio.sleep(delay)
                backoff = min(max_backoff, delay * 1.7)
    
    # Start periodic pulse task
    async def pulse_loop():
        # Keep global rpc_client in sync for reconnect logic.
        global rpc_client, _pulse_trigger_event, _pulse_last_sent_ts, _pulse_next_periodic_ts
        rpc_client = client
        if _pulse_trigger_event is None:
            _pulse_trigger_event = asyncio.Event()

        # Debounce to avoid spamming pulses if multiple wallets initiate at once.
        min_gap_seconds = 30.0
        next_periodic_ts = time.time() + float(CONFIG['PULSE_INTERVAL_SECONDS'])
        _pulse_next_periodic_ts = float(next_periodic_ts)
        while True:
            try:
                # Wait until the next periodic pulse time, unless an immediate pulse is requested.
                now = time.time()
                timeout = max(0.0, next_periodic_ts - now)
                immediate = False
                try:
                    await asyncio.wait_for(_pulse_trigger_event.wait(), timeout=timeout)
                    _pulse_trigger_event.clear()
                    immediate = True
                except asyncio.TimeoutError:
                    immediate = False

                if immediate:
                    LOG.info("Sending immediate pulse...")
                else:
                    LOG.info("Sending periodic pulse...")
                    next_periodic_ts = time.time() + float(CONFIG['PULSE_INTERVAL_SECONDS'])
                    _pulse_next_periodic_ts = float(next_periodic_ts)

                # Rate-limit pulses.
                now = time.time()
                if (now - _pulse_last_sent_ts) < min_gap_seconds:
                    LOG.info("Pulse skipped: too soon since last pulse")
                    continue

                if _ensure_rpc_connected() and rpc_client is not None:
                    async with wallet_lock:
                        txid = node_pulse(rpc_client, wallet)
                    if txid:
                        _pulse_last_sent_ts = time.time()
                else:
                    LOG.error("Pulse skipped: Kaspa RPC not connected")
            except Exception as e:
                LOG.error(f"Pulse error: {e}")

    async def prune_pending_loop():
        """Periodically prune stale receiver sessions to prevent resource leaks."""
        global session_lock
        if session_lock is None:
            session_lock = asyncio.Lock()
        while True:
            await asyncio.sleep(30)
            stale: list[tuple[str, ServerConnection]] = []
            now = time.time()
            try:
                async with session_lock:
                    for sid, entry in list(pending_receivers.items()):
                        ts = float(entry.get("timestamp", 0) or 0)
                        paired = entry.get("paired")
                        is_paired = bool(getattr(paired, "is_set", lambda: False)()) if paired else False
                        if (not is_paired) and (now - ts > PENDING_SESSION_TTL_SECONDS):
                            ws = entry.get("websocket")
                            if ws:
                                stale.append((sid, ws))
                            del pending_receivers[sid]
                for sid, ws in stale:
                    try:
                        await ws.close()
                    except Exception:
                        pass
                    LOG.info(f"Pruned stale pending receiver: {sid[:8]}...")
            except Exception as e:
                LOG.debug(f"Prune loop error: {e}")

    def _readline(prompt: str = "> ") -> str:
        """Blocking readline for operator commands.

        We intentionally do not support single-key exits (e.g. ESC) so the node
        won't stop due to accidental console input.
        """
        try:
            sys.stdout.write(prompt)
            sys.stdout.flush()
            line = sys.stdin.readline()
            return line.rstrip("\r\n") if line else ""
        except Exception:
            return ""

    async def operator_command_loop():
        """Read operator commands from stdin without blocking the server.

        This loop is intentionally resilient: it should never stop the node.
        """
        announced = False
        warned_notty = False

        while True:
            try:
                is_tty = bool(getattr(sys.stdin, "isatty", lambda: False)())
            except Exception:
                is_tty = False

            if not is_tty:
                if not warned_notty:
                    LOG.info("Operator command loop disabled (stdin not a TTY)")
                    warned_notty = True
                await asyncio.sleep(5.0)
                continue

            if not announced:
                print("\nOperator commands enabled. Type 'help' for commands.\n")
                announced = True

            try:
                raw_line = await asyncio.to_thread(_readline, "> ")
            except Exception:
                await asyncio.sleep(0.2)
                continue

            # If stdin is closed (EOF), keep the node running.
            if raw_line == "":
                await asyncio.sleep(0.5)
                continue

            raw = str(raw_line).strip()
            if not raw:
                continue

            try:
                parts = shlex.split(raw)
            except Exception:
                parts = raw.split()

            cmd = (parts[0].lower() if parts else "")
            args = parts[1:]

            if cmd in {"help", "?"}:
                print(
                    "Commands:\n"
                    "  help                         Show this message\n"
                    "  pulse                        Trigger an immediate pulse\n"
                    "  sweep <address>               Drain all funds to address (keeps minimum reserve)\n"
                    "  status                       Show node + wallet status\n"
                    "  balance                      Show wallet balance summary\n"
                    "  fundaddr                      Show the current funding address\n"
                    "\nStop the node with Ctrl+C.\n"
                )
                continue

            if cmd == "pulse":
                _request_immediate_pulse(reason="operator_cmd")
                print("Pulse requested.")
                continue

            if cmd == "fundaddr":
                try:
                    async with wallet_lock:
                        addr = node_fund(client, wallet)
                    print(f"Fund address: {addr}")

                    qr_payload = _funding_qr_payload(addr)
                    print("\nScan to fund (Kaspa address):")
                    if not _print_ascii_qr(qr_payload):
                        print("(QR unavailable: install optional dependency 'qrcode')")
                        print(qr_payload)
                except Exception as e:
                    print(f"Error: {e}")
                continue

            if cmd == "balance":
                try:
                    info = await asyncio.to_thread(get_wallet_total_balance, client, wallet)
                    print(f"Total Balance: {info.get('total', 0.0):.8f} KAS")
                    print(f"Addresses with funds: {info.get('address_count', 0)}")
                except Exception as e:
                    print(f"Error: {e}")
                continue

            if cmd == "status":
                try:
                    bind = str(CONFIG.get("WEBSOCKET_BIND") or "0.0.0.0")
                    port = int(CONFIG.get("WEBSOCKET_PORT"))
                    pulse_hours = float(CONFIG.get("PULSE_INTERVAL_SECONDS", 0)) / 3600.0

                    try:
                        idx = int(getattr(wallet, "pulse_source_index", 0) or 0)
                    except Exception:
                        idx = 0
                    if idx < 0 or idx >= len(wallet.addresses):
                        idx = 0
                    pulse_addr = wallet.addresses[idx].get("address", "")

                    last_ts = float(_pulse_last_sent_ts or 0.0)
                    next_ts = float(_pulse_next_periodic_ts or 0.0)

                    print("=" * 60)
                    print("KLOAK NODE STATUS")
                    print("=" * 60)
                    print(f"Version: {CONFIG.get('VERSION')}")
                    print(f"WebSocket: ws://{bind}:{port}")
                    print(f"Pulse interval: {pulse_hours:.2f} hours")
                    print(f"Pulse source [{idx}]: {pulse_addr}")

                    if last_ts > 0:
                        print(f"Last pulse: {datetime.fromtimestamp(last_ts).isoformat(sep=' ', timespec='seconds')}")
                    else:
                        print("Last pulse: (none yet)")
                    if next_ts > 0:
                        print(f"Next periodic pulse: {datetime.fromtimestamp(next_ts).isoformat(sep=' ', timespec='seconds')}")

                    # Wallet balance (can take a moment)
                    info = await asyncio.to_thread(get_wallet_total_balance, client, wallet)
                    print(f"Total Balance: {info.get('total', 0.0):.8f} KAS")
                    print(f"Addresses with funds: {info.get('address_count', 0)}")
                    print("=" * 60)
                except Exception as e:
                    print(f"Error: {e}")
                continue

            if cmd == "sweep":
                # New default: sweep <address> drains everything except reserve.
                # Back-compat: sweep <amount> <address>
                if len(args) < 1:
                    print("Usage: sweep <destination_address>")
                    continue

                amount_kas = None
                dest_addr = ""
                if len(args) >= 2:
                    try:
                        amount_kas = float(args[0])
                        dest_addr = str(args[1])
                    except Exception:
                        amount_kas = None
                        dest_addr = str(args[0])
                else:
                    dest_addr = str(args[0])

                try:
                    async with wallet_lock:
                        if amount_kas is None:
                            txid = await asyncio.to_thread(node_sweep_drain, client, wallet, dest_addr)
                        else:
                            txid = await asyncio.to_thread(node_sweep, client, wallet, dest_addr, amount_kas)
                    if txid:
                        print(f"Sweep broadcast: {txid}")
                    else:
                        print("Sweep failed (see logs).")
                except Exception as e:
                    print(f"Error: {e}")
                continue

            print("Unknown command. Type 'help'.")
    
    # Start background tasks (supervised where needed) and keep running.
    tasks = [
        asyncio.create_task(websocket_server_supervisor(), name="kloak.websocket"),
        asyncio.create_task(pulse_loop(), name="kloak.pulse"),
        asyncio.create_task(prune_pending_loop(), name="kloak.prune"),
        asyncio.create_task(operator_command_loop(), name="kloak.cmd"),
    ]
    await asyncio.gather(*tasks)


# ============================================================================
# NODE DISCOVERY (for wallet clients)
# ============================================================================

def _normalize_ws_url(ws_url: str) -> str:
    """Normalize a node WebSocket URL.

    - Ensures it starts with ws:// or wss://
    - Ensures it ends with /kpp (default path used by this node)
    """
    if not isinstance(ws_url, str):
        return ""
    s = ws_url.strip()
    if not s:
        return ""
    if not (s.startswith("ws://") or s.startswith("wss://")):
        # Be conservative: if missing scheme, assume ws://
        s = "ws://" + s
    if "/kpp" not in s:
        s = s.rstrip("/") + "/kpp"
    return s


def _kloak_cache_dir() -> Path:
    """Return an OS-appropriate *persistent* directory for client-side state.

    This is used by wallet-side helpers to store the last known-good node ws URL.
    Prefer a stable app-data location (not a temporary cache) so it survives reboots
    and is more likely to work on mobile sandboxes.

    Override:
      - Set `KLOAK_NODE_CACHE_DIR` (or `KLOAK_CACHE_DIR`) to force a directory.
    """
    override = os.getenv("KLOAK_NODE_CACHE_DIR") or os.getenv("KLOAK_CACHE_DIR")
    if override:
        return Path(override)

    # Preferred: platformdirs (works well across desktop + mobile-ish runtimes when available).
    try:
        from platformdirs import user_data_dir  # type: ignore

        return Path(user_data_dir("KloakNode", appauthor=False))
    except Exception:
        pass

    # Windows fallback
    base = os.getenv("LOCALAPPDATA") or os.getenv("APPDATA")
    if base:
        return Path(base) / "KloakNode"

    # XDG / *nix fallback
    xdg_data = os.getenv("XDG_DATA_HOME")
    if xdg_data:
        return Path(xdg_data) / "kloaknode"

    return Path.home() / ".local" / "share" / "kloaknode"


def _node_cache_path(cache_path: Optional[Path] = None) -> Path:
    if cache_path is not None:
        return Path(cache_path)
    override = os.getenv("KLOAK_NODE_CACHE_PATH")
    if override:
        return Path(override)
    return _kloak_cache_dir() / "node_cache.json"


def load_cached_node_ws_url(*, cache_path: Optional[Path] = None) -> Optional[str]:
    """Load the last cached node WebSocket URL from disk."""
    try:
        p = _node_cache_path(cache_path)
        if not p.exists():
            return None
        data = json.loads(p.read_text(encoding="utf-8"))
        ws_url = _normalize_ws_url(str((data or {}).get("ws_url", "")))
        return ws_url or None
    except Exception:
        return None


def save_cached_node_ws_url(ws_url: str, *, cache_path: Optional[Path] = None) -> None:
    """Persist a node WebSocket URL to disk (best-effort)."""
    try:
        normalized = _normalize_ws_url(ws_url)
        if not normalized:
            return
        p = _node_cache_path(cache_path)
        d = p.parent
        d.mkdir(parents=True, exist_ok=True)
        payload = {
            "ws_url": normalized,
            "saved_at": int(time.time()),
            "version": CONFIG.get("VERSION"),
        }
        p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except Exception:
        # Cache must never break wallet flow.
        return

async def measure_node_latency(ws_url: str, timeout: float = 3.0) -> Optional[float]:
    """
    Measure latency to a Kloak node by attempting WebSocket connection.
    
    Args:
        ws_url: WebSocket URL of the node
        timeout: Connection timeout in seconds
        
    Returns:
        Latency in seconds, or None if unreachable
    """
    try:
        start_time = time.time()

        ws_url = _normalize_ws_url(ws_url) or ws_url

        # Try to connect to the WebSocket with a timeout.
        websocket = await asyncio.wait_for(
            websockets.connect(
                ws_url,
                open_timeout=timeout,
                ping_interval=20,
                ping_timeout=timeout,
                close_timeout=1,
                max_size=WS_MAX_MESSAGE_BYTES,
                max_queue=8,
            ),
            timeout=timeout + 1.0,
        )
        try:
            latency = time.time() - start_time
            return latency
        finally:
            try:
                await websocket.close()
            except Exception:
                pass
            
    except (asyncio.TimeoutError, websockets.exceptions.WebSocketException, OSError) as e:
        LOG.debug(f"Node {ws_url} unreachable: {e}")
        return None
    except Exception as e:
        LOG.debug(f"Error measuring latency to {ws_url}: {e}")
        return None


def find_best_node(client: RPCClient, max_blocks: int = 1000, max_nodes: int = 3) -> str:
    """
    Wallet utility: Find the most recent and lowest latency Kloak node.
    
    Scans recent Kaspa blocks for transactions with "kloak" protocol identifier in payload,
    identifies the N most recently pulsed nodes, then selects the one with lowest latency.
    
    Args:
        client: Connected RPCClient instance
        max_blocks: Maximum number of recent blocks to scan
        max_nodes: Number of most recent nodes to test for latency
        
    Returns:
        WebSocket URL of the best available node
    """
    LOG.info("Scanning Kaspa DAG for active Kloak nodes...")
    
    try:
        # Get current DAG info
        dag_info = rpc_request(client, "getBlockDagInfoRequest", {})
        tip_hashes = dag_info.get("getBlockDagInfoResponse", {}).get("tipHashes", [])
        
        if not tip_hashes:
            cached = load_cached_node_ws_url()
            if cached:
                LOG.warning("Could not get DAG tip - using cached node")
                return cached
            LOG.warning("Could not get DAG tip - using localhost fallback")
            return _normalize_ws_url(f"ws://localhost:{CONFIG['WEBSOCKET_PORT']}")
        
        # Use the first tip as starting point
        current_hash = tip_hashes[0]
        
        # Track discovered nodes: {ws_url: (timestamp, block_hash)}
        discovered_nodes = {}
        blocks_scanned = 0
        
        # Scan backwards through the DAG
        visited_hashes = set()
        to_visit = [current_hash]
        
        while to_visit and blocks_scanned < max_blocks:
            block_hash = to_visit.pop(0)
            
            if block_hash in visited_hashes:
                continue
            
            visited_hashes.add(block_hash)
            blocks_scanned += 1
            
            try:
                # Get block information
                block_response = rpc_request(client, "getBlockRequest", {
                    "hash": block_hash,
                    "includeTransactions": True
                })
                
                block_data = block_response.get("getBlockResponse", {}).get("block", {})
                
                # Check each transaction in the block
                transactions = block_data.get("transactions", [])
                block_time = block_data.get("header", {}).get("timestamp", 0)
                
                for tx in transactions:
                    payload_hex = tx.get("payload", "")
                    
                    if not payload_hex:
                        continue
                    
                    try:
                        # Decode hex payload to string
                        payload_bytes = bytes.fromhex(payload_hex)
                        payload_str = payload_bytes.decode('utf-8', errors='ignore')
                        
                        # Check if this is a Kloak pulse
                        if "kloak" in payload_str.lower():
                            # Try to parse as JSON
                            try:
                                pulse_data = json.loads(payload_str)
                                
                                if pulse_data.get("protocol") == "kloak":
                                    ws_url = pulse_data.get("ws_url")
                                    timestamp = pulse_data.get("timestamp", block_time)
                                    
                                    if ws_url:
                                        # Store this node (keep most recent pulse per URL)
                                        if ws_url not in discovered_nodes or timestamp > discovered_nodes[ws_url][0]:
                                            discovered_nodes[ws_url] = (timestamp, block_hash)
                                            LOG.info(f"Found Kloak node: {ws_url} (pulsed at {timestamp})")
                                            
                            except json.JSONDecodeError:
                                # Payload contains "kloak" but isn't valid JSON
                                LOG.debug(f"Found 'kloak' in payload but not valid JSON: {payload_str[:100]}")
                                
                    except Exception as e:
                        LOG.debug(f"Error decoding payload: {e}")
                
                # Add parent blocks to visit queue
                parent_hashes = block_data.get("header", {}).get("parentHashes", [])
                for parent_hash in parent_hashes:
                    if parent_hash not in visited_hashes:
                        to_visit.append(parent_hash)
                        
            except Exception as e:
                LOG.debug(f"Error processing block {block_hash}: {e}")
                continue
        
        LOG.info(f"Scanned {blocks_scanned} blocks, found {len(discovered_nodes)} Kloak nodes")
        
        if not discovered_nodes:
            cached = load_cached_node_ws_url()
            if cached:
                LOG.warning("No Kloak nodes found in recent blocks - using cached node")
                return cached
            LOG.warning("No Kloak nodes found in recent blocks - using localhost fallback")
            return _normalize_ws_url(f"ws://localhost:{CONFIG['WEBSOCKET_PORT']}")
        
        # Sort nodes by timestamp (most recent first)
        sorted_nodes = sorted(
            discovered_nodes.items(),
            key=lambda x: x[1][0],  # Sort by timestamp
            reverse=True
        )
        
        # Take the N most recent nodes
        recent_nodes = sorted_nodes[:max_nodes]
        LOG.info(f"Testing latency to {len(recent_nodes)} most recent nodes...")
        
        # Measure latency to each node (using sync approach for simplicity)
        best_node = None
        best_latency = float('inf')
        
        for ws_url, (timestamp, block_hash) in recent_nodes:
            try:
                # Simple TCP connection test as proxy for latency
                # (In production, would use async WebSocket ping)
                import urllib.parse
                parsed = urllib.parse.urlparse(ws_url)
                host = parsed.hostname or "localhost"
                port = parsed.port or 8765
                
                start = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                
                result = sock.connect_ex((host, port))
                latency = time.time() - start
                sock.close()
                
                if result == 0:  # Connection successful
                    LOG.info(f"  {ws_url}: {latency*1000:.1f}ms")
                    
                    if latency < best_latency:
                        best_latency = latency
                        best_node = ws_url
                else:
                    LOG.debug(f"  {ws_url}: unreachable")
                    
            except Exception as e:
                LOG.debug(f"  {ws_url}: error - {e}")
        
        if best_node:
            best_node = _normalize_ws_url(best_node)
            LOG.info(f"Success: Best node found: {best_node} ({best_latency*1000:.1f}ms)")
            # Best-effort cache of the last discovered node.
            save_cached_node_ws_url(best_node)
            return best_node
        else:
            # All nodes unreachable, return most recent one anyway
            most_recent_url = _normalize_ws_url(sorted_nodes[0][0])
            cached = load_cached_node_ws_url()
            if cached:
                LOG.warning(f"All nodes unreachable, using cached node: {cached}")
                return cached
            LOG.warning(f"All nodes unreachable, returning most recent: {most_recent_url}")
            save_cached_node_ws_url(most_recent_url)
            return most_recent_url
            
    except Exception as e:
        LOG.error(f"Error during node discovery: {e}")
        cached = load_cached_node_ws_url()
        if cached:
            LOG.warning("Falling back to cached node")
            return cached
        LOG.warning("Falling back to localhost")
        return _normalize_ws_url(f"ws://localhost:{CONFIG['WEBSOCKET_PORT']}")


async def get_best_node(
    client: RPCClient,
    *,
    max_blocks: int = 1000,
    max_nodes: int = 3,
    connect_timeout: float = 2.5,
) -> str:
    """Return a node WebSocket URL with local device caching.

    Goal: even if wallets call this frequently, they always get a usable ws URL string.

    Strategy:
    1) Try discovery via find_best_node()
    2) If the discovered URL is reachable, cache and return it
    3) Otherwise fall back to cached URL (if present)
    4) Otherwise return the discovered URL (even if not reachable)
    5) Otherwise localhost
    """
    discovered = ""
    try:
        discovered = _normalize_ws_url(find_best_node(client, max_blocks=max_blocks, max_nodes=max_nodes))
    except Exception:
        discovered = ""

    if discovered:
        try:
            latency = await measure_node_latency(discovered, timeout=connect_timeout)
            if latency is not None:
                save_cached_node_ws_url(discovered)
                return discovered
        except Exception:
            pass

    cached = load_cached_node_ws_url()
    if cached:
        return cached

    if discovered:
        return discovered

    return _normalize_ws_url(f"ws://localhost:{CONFIG['WEBSOCKET_PORT']}")


# ============================================================================
# CLIENT-SIDE FUNCTIONS (for wallet integration)
# ============================================================================

class SenderWalletAPI:
    """Minimal wallet adapter used by `sender_prepare_kpp_transaction()`.

    Sender wallets typically know how to:
    - select a UTXO to spend
    - provide a fresh change address

    This adapter lets the kloak client flow remain fully automated while keeping
    the wallet-side integration as small as possible.
    """

    def select_utxo(self, amount_kas: float) -> dict:  # pragma: no cover
        raise NotImplementedError

    def get_change_address(self) -> str:  # pragma: no cover
        raise NotImplementedError

    def estimate_fee_sompi(self, num_inputs: int, num_outputs: int) -> int:  # optional
        raise NotImplementedError


_SENDER_WALLET_API: Optional[SenderWalletAPI] = None


def set_sender_wallet_api(api: SenderWalletAPI) -> None:
    """Register a default SenderWalletAPI for minimal-call integrations."""
    global _SENDER_WALLET_API
    _SENDER_WALLET_API = api


class ReceiverWalletAPI:
    """Minimal wallet adapter used by `receiver_initiate_kpp()`.

    Receiver wallets typically know how to select a contributed UTXO. This keeps
    the receiver integration to a single call-site.
    """

    def select_utxo(self, amount_kas: Optional[float] = None) -> dict:  # pragma: no cover
        raise NotImplementedError


_RECEIVER_WALLET_API: Optional[ReceiverWalletAPI] = None


def set_receiver_wallet_api(api: ReceiverWalletAPI) -> None:
    global _RECEIVER_WALLET_API
    _RECEIVER_WALLET_API = api


async def _maybe_await(value):
    if asyncio.iscoroutine(value):
        return await value
    return value


async def sender_finalize_receiver(
    websocket,
    e2ee_key: bytes,
    *,
    transaction_id: Optional[str] = None,
    error: Optional[str] = None,
) -> None:
    """Notify the receiver of broadcast success/failure and close the socket."""
    try:
        if transaction_id:
            msg = encrypt_message(e2ee_key, {"type": "broadcast_success", "transaction_id": transaction_id})
        else:
            msg = encrypt_message(e2ee_key, {"type": "broadcast_error", "error": error or "broadcast_failed"})
        await websocket.send(msg)
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


async def sender_prepare_kpp_transaction(
    amount: float,
    ws_url: str,
    e2ee_key: bytes,
    *,
    wallet_api: Optional[SenderWalletAPI] = None,
    fee_sompi: Optional[int] = None,
    receiver_signature_timeout: float = 300.0,
) -> dict:
    """Single-call sender flow: return a receiver-signed KPP tx ready for sender signing.

    Wallet integration goal:
    - The wallet developer only needs to call THIS function with (amount, ws_url, e2ee_key).
    - UTXO selection + change address are obtained via `SenderWalletAPI`.
    - The function returns the partially-signed transaction (receiver already signed input #1).
    - The wallet then signs input #0, broadcasts, and calls the returned `finalize()` coroutine
      to notify the receiver.

    Returns:
        {
          "transaction": <receiver-signed tx>,
          "sender_input_index": 0,
          "sender_utxo": <selected utxo>,
          "change_address": <used change address>,
          "finalize": <async callable finalize(transaction_id=..., error=...)>,
        }
    """
    if wallet_api is None:
        wallet_api = _SENDER_WALLET_API
    if wallet_api is None:
        raise ValueError(
            "sender_prepare_kpp_transaction requires a SenderWalletAPI. "
            "Pass wallet_api=... or call set_sender_wallet_api(...) once at startup."
        )

    if not isinstance(e2ee_key, (bytes, bytearray)) or len(e2ee_key) != 32:
        raise ValueError("e2ee_key must be 32 bytes")
    if not ws_url:
        raise ValueError("ws_url is required")
    if amount <= 0:
        raise ValueError("amount must be positive")

    sender_utxo = await _maybe_await(wallet_api.select_utxo(amount))
    change_addr = await _maybe_await(wallet_api.get_change_address())

    if fee_sompi is None and hasattr(wallet_api, "estimate_fee_sompi"):
        try:
            fee_sompi = int(await _maybe_await(wallet_api.estimate_fee_sompi(2, 4)))
        except Exception:
            fee_sompi = None

    session_id = hashlib.sha256(bytes(e2ee_key)).hexdigest()
    websocket = await websocket_connect(ws_url)

    async def _finalize(*, transaction_id: Optional[str] = None, error: Optional[str] = None) -> None:
        await sender_finalize_receiver(websocket, bytes(e2ee_key), transaction_id=transaction_id, error=error)

    try:
        await websocket.send(json.dumps({"role": "sender", "session_id": session_id}))

        dust_msg = await asyncio.wait_for(websocket.recv(), timeout=WS_HANDSHAKE_TIMEOUT_SECONDS)
        dust_data = json.loads(dust_msg)
        if dust_data.get("type") != "dust_address":
            raise ValueError(f"Expected dust_address, got {dust_data.get('type')}")
        dust_addr = dust_data.get("address")
        if not dust_addr:
            raise ValueError("Node returned empty dust address")

        encrypted_receiver_data = await asyncio.wait_for(websocket.recv(), timeout=WS_RECV_TIMEOUT_SECONDS)
        receiver_data = decrypt_message(bytes(e2ee_key), encrypted_receiver_data)

        encrypted_sender_data = encrypt_message(bytes(e2ee_key), {
            "utxo": sender_utxo,
            "change_address": change_addr,
            "amount": amount,
        })
        await websocket.send(encrypted_sender_data)

        tx = kpp_tx_construct(
            sender_utxo=sender_utxo,
            sender_change=change_addr,
            receiver_utxo=receiver_data.get("utxo"),
            rec_1=receiver_data.get("address_1"),
            rec_2=receiver_data.get("address_2"),
            amount=amount,
            dust_addr=dust_addr,
            fee_sompi=int(fee_sompi) if fee_sompi is not None else 1000,
        )

        await websocket.send(encrypt_message(bytes(e2ee_key), {
            "type": "transaction",
            "tx": tx,
            "your_input_index": 1,
            "sender_input_index": 0,
        }))

        partial_tx_msg = await asyncio.wait_for(websocket.recv(), timeout=receiver_signature_timeout)
        partial_tx_data = decrypt_message(bytes(e2ee_key), partial_tx_msg)
        if partial_tx_data.get("type") != "receiver_signature":
            raise ValueError("Expected receiver_signature")
        receiver_signed_tx = partial_tx_data.get("tx")
        if not isinstance(receiver_signed_tx, dict):
            raise ValueError("Receiver did not provide a transaction")

        return {
            "transaction": receiver_signed_tx,
            "sender_input_index": 0,
            "sender_utxo": sender_utxo,
            "change_address": change_addr,
            "finalize": _finalize,
        }
    except Exception:
        try:
            await websocket.close()
        except Exception:
            pass
        raise


def kpp_payment_uri(
    *,
    address: str,
    amount: float,
    payload: str,
    ws_url: str,
    e2ee_key: bytes,
) -> str:
    """Build a QR-ready Kaspa payment URI including KPP parameters.

    Format (Kaspa-URI style):
      kaspa:{address}?amount={amount}&payload={payload}&ws_url={ws_url}&e2ee_key={e2ee_key}

    Note: `payload` here is a free-form string per wallet UX; we URL-encode it.
    The e2ee_key is encoded as URL-safe base64 (no padding).
    """
    import urllib.parse

    if not isinstance(e2ee_key, (bytes, bytearray)) or len(e2ee_key) != 32:
        raise ValueError("e2ee_key must be 32 bytes")
    if not address:
        raise ValueError("address is required")
    if not ws_url:
        raise ValueError("ws_url is required")

    # Kaspa addresses are typically formatted like "kaspa:qq...".
    # The URI scheme is also "kaspa:", so we must avoid "kaspa:kaspa:...".
    address_part = address.split(":", 1)[1] if ":" in address else address

    e2ee_b64 = base64.urlsafe_b64encode(bytes(e2ee_key)).decode("ascii").rstrip("=")
    query = urllib.parse.urlencode(
        {
            "amount": str(amount),
            "payload": payload,
            "ws_url": ws_url,
            "e2ee_key": e2ee_b64,
        },
        quote_via=urllib.parse.quote,
        safe=":/",
    )
    return f"kaspa:{address_part}?{query}"


async def receiver_initiate_kpp(
    addr1: str,
    addr2: str,
    amount: float,
    ws_url: str,
    *,
    receiver_utxo: Optional[dict] = None,
    e2ee_key: Optional[bytes] = None,
    payload: str = "kpp",
    wallet_api: Optional[ReceiverWalletAPI] = None,
) -> dict:
    """Single-call receiver flow to generate QR/URI and wait for tx.

    Inputs expected from the wallet integration point:
    - 2 unique receiver output addresses (addr1, addr2)
    - requested amount
    - best node websocket URL (from get_best_node(); cached locally)
    - an E2EE key (optional; generated if not provided)

    Returns a dict containing:
    - qr_uri: Kaspa URI string suitable for QR encoding
    - e2ee_key: raw 32-byte key
    - session_id: SHA256(e2ee_key) hex (what the node matches on)
    - receiver_utxo: the receiver contributed UTXO (sent via websocket, not in QR)
    - result: receiver_connect_to_node() result (includes tx + websocket)
    """
    if e2ee_key is None:
        e2ee_key = ChaCha20Poly1305.generate_key()
    if not isinstance(e2ee_key, (bytes, bytearray)) or len(e2ee_key) != 32:
        raise ValueError("e2ee_key must be 32 bytes")
    if amount <= 0:
        raise ValueError("amount must be positive")
    if not addr1 or not addr2:
        raise ValueError("addr1 and addr2 are required")
    if addr1 == addr2:
        raise ValueError("addr1 and addr2 must be different")

    if wallet_api is None:
        wallet_api = _RECEIVER_WALLET_API
    if wallet_api is None:
        raise ValueError(
            "receiver_initiate_kpp requires a ReceiverWalletAPI to supply the contributed UTXO. "
            "Pass wallet_api=... or call set_receiver_wallet_api(...) once at startup."
        )

    if receiver_utxo is None:
        # Allow wallet APIs to optionally use amount-aware selection.
        try:
            receiver_utxo = await _maybe_await(wallet_api.select_utxo(amount))
        except TypeError:
            receiver_utxo = await _maybe_await(wallet_api.select_utxo())

    if not isinstance(receiver_utxo, dict):
        raise ValueError("receiver_utxo must be a dict")

    session_id = hashlib.sha256(bytes(e2ee_key)).hexdigest()

    qr_uri = kpp_payment_uri(
        address=addr1,
        amount=amount,
        payload=payload,
        ws_url=ws_url,
        e2ee_key=bytes(e2ee_key),
    )

    result = await receiver_connect_to_node(
        addr1=addr1,
        addr2=addr2,
        utxo=receiver_utxo,
        amount=amount,
        ws_url=ws_url,
        e2ee_key=bytes(e2ee_key),
    )

    return {
        "qr_uri": qr_uri,
        "e2ee_key": bytes(e2ee_key),
        "session_id": session_id,
        "receiver_utxo": receiver_utxo,
        "result": result,
    }

def receiver_kpp_init(addr1: str, addr2: str, utxo: dict, amount: float, ws_url: str, e2ee_key: bytes):
    """
    Generate QR/NFC data for receiver to share with sender.
    
    Args:
        addr1: First receiving address
        addr2: Second receiving address
        utxo: Receiver's UTXO to contribute
        amount: Payment amount in KAS
        ws_url: Kloak node WebSocket URL
        e2ee_key: End-to-end encryption key (NEVER sent to node)
        
    Returns:
        JSON string for QR code encoding
    """
    # No need for separate session_id - we derive it from e2ee_key
    # Both wallets will hash e2ee_key to get session_id for node matching
    # Node sees session_id (hash) but can't reverse it to get e2ee_key
    
    qr_data = {
        "protocol": "kpp",
        "version": CONFIG["VERSION"],
        "ws_url": ws_url,
        "e2ee_key": base64.b64encode(e2ee_key).decode(),  # Wallets encrypt with this, node never sees it
        "amount": amount
    }
    
    qr_json = json.dumps(qr_data)
    LOG.info(f"Receiver QR data generated ({len(qr_json)} bytes)")
    
    return qr_json


def parse_kpp_payment_request(data: str) -> dict:
    """Parse either legacy JSON QR or a kaspa: URI KPP request.

    Supported formats:
    - Legacy JSON (current receiver_kpp_init):
        {"protocol":"kpp","ws_url":...,"e2ee_key":<b64>,"amount":...}
    - Kaspa URI (recommended):
        kaspa:<addr>?amount=...&payload=...&ws_url=...&e2ee_key=...
      (We also accept the non-standard variant using '&' without '?'.)
    """
    if not isinstance(data, str) or not data.strip():
        raise ValueError("Empty payment request")

    s = data.strip()

    # URI path
    if s.lower().startswith("kaspa:"):
        import urllib.parse

        # Accept non-standard: kaspa:<addr>&k=v... by converting first '&' to '?'
        if "?" not in s and "&" in s:
            head, tail = s.split("&", 1)
            s = head + "?" + tail

        parsed = urllib.parse.urlparse(s)
        address_part = (parsed.path or "").strip()
        qs = urllib.parse.parse_qs(parsed.query)

        amount_s = (qs.get("amount", [""])[0] or "").strip()
        ws_url = (qs.get("ws_url", [""])[0] or "").strip()
        payload = (qs.get("payload", [""])[0] or "").strip()
        e2ee_s = (qs.get("e2ee_key", [""])[0] or "").strip()

        if not (amount_s and ws_url and e2ee_s):
            raise ValueError("Incomplete kaspa: KPP URI")

        # urlsafe b64 may be unpadded
        pad = "=" * ((4 - (len(e2ee_s) % 4)) % 4)
        e2ee_key = base64.urlsafe_b64decode(e2ee_s + pad)
        if len(e2ee_key) != 32:
            raise ValueError("Invalid e2ee_key length")

        return {
            "format": "kaspa_uri",
            "address": ("kaspa:" + address_part) if address_part and ":" not in address_part else address_part,
            "amount": float(amount_s),
            "ws_url": ws_url,
            "payload": payload,
            "e2ee_key": e2ee_key,
        }

    # Legacy JSON path
    try:
        parsed = json.loads(s)
        if not isinstance(parsed, dict):
            raise ValueError("QR JSON must be an object")
        if parsed.get("protocol") != "kpp":
            raise ValueError("Not a KPP request")
        ws_url = parsed.get("ws_url")
        e2ee_key_b64 = parsed.get("e2ee_key")
        amount = parsed.get("amount")
        if not all([ws_url, e2ee_key_b64, amount]):
            raise ValueError("Incomplete legacy KPP request")
        e2ee_key = base64.b64decode(e2ee_key_b64)
        if len(e2ee_key) != 32:
            raise ValueError("Invalid e2ee_key length")
        return {
            "format": "legacy_json",
            "amount": float(amount),
            "ws_url": ws_url,
            "e2ee_key": e2ee_key,
            "payload": "",
            "address": "",
        }
    except json.JSONDecodeError as e:
        raise ValueError("Unsupported payment request format") from e


async def receiver_connect_to_node(addr1: str, addr2: str, utxo: dict, amount: float, ws_url: str, e2ee_key: bytes):
    """
    Receiver connects to Kloak node WebSocket and waits for transaction.
    
    Called by receiver's wallet after generating QR code for sender to scan.
    Node never sees the E2EE key - it only gets session_id (derived from hash of e2ee_key).
    All messages between wallets are encrypted with E2EE key that node cannot decrypt.
    
    Args:
        addr1: First receiving address
        addr2: Second receiving address
        utxo: Receiver's UTXO to contribute
        amount: Payment amount in KAS
        ws_url: Kloak node WebSocket URL
        e2ee_key: End-to-end encryption key (NEVER sent to node)
    
    Returns:
        Dict containing transaction template, input_index, dust_address, websocket, and e2ee_key
        
    Raises:
        ValueError: If node sends unexpected response
        ConnectionError: If WebSocket connection fails
    """
    LOG.info(f"Receiver connecting to Kloak node: {ws_url}")
    
    # Derive session_id from e2ee_key (both wallets do this)
    # Node only sees the hash, not the actual e2ee_key
    session_id = hashlib.sha256(e2ee_key).hexdigest()
    
    try:
        websocket = await websocket_connect(ws_url)
        
        try:
            # Send initial handshake with session_id (NOT e2ee_key)
            init_msg = {
                "role": "receiver",
                "session_id": session_id  # Derived hash, node uses this for matching
            }
            await websocket.send(json.dumps(init_msg))
            LOG.info("Sent receiver handshake")
            
            # Encrypt receiver's UTXO and addresses with E2EE key
            receiver_data = {
                "utxo": utxo,
                "address_1": addr1,
                "address_2": addr2,
                "amount": amount
            }
            encrypted_data = encrypt_message(e2ee_key, receiver_data)
            await websocket.send(encrypted_data)
            LOG.info("Sent encrypted receiver data")
            
            # Receive sender's encrypted data (forwarded by node)
            LOG.info("Waiting for sender to connect...")
            try:
                sender_encrypted_msg = await asyncio.wait_for(websocket.recv(), timeout=300.0)  # 5 min timeout
            except asyncio.TimeoutError:
                raise ConnectionError("Timeout waiting for sender to connect (5 minutes)")
            sender_data = decrypt_message(e2ee_key, sender_encrypted_msg)
            LOG.info("Received sender's encrypted data")
            
            # Receive transaction from sender (encrypted, built by sender's wallet)
            LOG.info("Waiting for transaction from sender...")
            try:
                tx_msg = await asyncio.wait_for(websocket.recv(), timeout=60.0)  # 1 min timeout
            except asyncio.TimeoutError:
                raise ConnectionError("Timeout waiting for transaction from sender (1 minute)")
            tx_data = decrypt_message(e2ee_key, tx_msg)
            
            if tx_data.get("type") == "transaction":
                transaction = tx_data.get("tx")
                input_index = tx_data.get("your_input_index")
                
                LOG.info(f"Success: Received transaction template from sender")
                LOG.info(f"  Your input index: {input_index}")
                LOG.info(f"  Ready to sign (receiver signs first)")
                
                return {
                    "transaction": transaction,
                    "input_index": input_index,
                    "websocket": websocket,
                    "e2ee_key": e2ee_key,
                    "utxo": utxo  # Need this for signing
                }
            else:
                raise ValueError("Expected transaction from sender")
        
        finally:
            # Keep websocket open - caller is responsible for closing
            pass
                
    except Exception as e:
        LOG.error(f"Receiver connection error: {e}")
        raise


async def receiver_sign_and_return(result: dict, private_key: bytes) -> dict:
    """
    Receiver signs their input immediately and sends to sender.
    
    Args:
        result: Result dictionary from receiver_connect_to_node
        private_key: Receiver's private key for signing
        
    Returns:
        Dict with:
            - success: True if broadcast successful
            - transaction_id: Transaction ID (if successful)
            - transaction: Fully signed transaction
            - error: Error message (if failed)
            
    Raises:
        Exception: If signing or communication fails
    """
    websocket = result["websocket"]
    e2ee_key = result["e2ee_key"]
    transaction = result["transaction"]
    input_index = result["input_index"]
    utxo = result["utxo"]
    
    try:
        # Get UTXO amount and script pubkey
        utxo_amount = utxo.get("utxoEntry", {}).get("amount", 0)
        spk_version, script_pubkey = get_utxo_script_pubkey(utxo)
        
        LOG.info(f"Signing input #{input_index} as receiver (first signature)...")
        
        # Sign the transaction
        partially_signed_tx = sign_kaspa_transaction_input(
            transaction,
            input_index,
            private_key,
            utxo_amount,
            script_pubkey,
            script_pubkey_version=spk_version,
        )
        
        LOG.info(f"Success: Receiver signature complete")
        LOG.info(f"  Sending partially-signed transaction to sender...")
        
        # Send partially-signed transaction to sender
        partial_tx_msg = encrypt_message(e2ee_key, {
            "type": "receiver_signature",
            "tx": partially_signed_tx
        })
        await websocket.send(partial_tx_msg)
        
        # Wait for broadcast confirmation from sender
        LOG.info("Waiting for sender to broadcast...")
        confirm_msg = await websocket.recv()
        confirm_data = decrypt_message(e2ee_key, confirm_msg)
        
        if confirm_data.get("type") == "broadcast_success":
            tx_id = confirm_data.get("transaction_id")
            LOG.info(f"Success: Transaction broadcast successful!")
            LOG.info(f"  Transaction ID: {tx_id}")
            
            await websocket.close()
            
            return {
                "success": True,
                "transaction_id": tx_id,
                "transaction": partially_signed_tx
            }
        elif confirm_data.get("type") == "broadcast_error":
            error = confirm_data.get("error")
            LOG.error(f"Broadcast failed: {error}")
            await websocket.close()
            return {
                "success": False,
                "error": error
            }
        else:
            raise ValueError("Unexpected response from sender")
            
    except Exception as e:
        LOG.error(f"Error in receiver signing: {e}")
        try:
            await websocket.close()
        except Exception as close_error:
            LOG.debug(f"Error closing websocket: {close_error}")
        raise


async def sender_connect_to_kloak_node(qr_data: str, sender_utxo: dict, change_addr: str):
    """
    Sender wallet function: Connect to Kloak node via WebSocket.
    
    This is the main entry point for sender wallets to initiate a KPP payment.
    Call this when the user scans a Kloak QR code or receives a payment request.
    
    Args:
        qr_data: JSON string from QR code (contains ws_url, e2ee_key, amount)
        sender_utxo: Sender's UTXO to use as input
        change_addr: Sender's change address
        
    Returns:
        Dict containing:
            - transaction: Transaction template ready for signing
            - input_index: Which input index sender should sign
            - amount: Payment amount in KAS
            - websocket: Open WebSocket connection (for signature exchange)
            - e2ee_key: Encryption key for further communication
            - utxo: Sender's UTXO (needed for signing)
            
    Raises:
        ValueError: If QR code format is invalid or incomplete
        ConnectionError: If WebSocket connection fails
    """
    parsed_req = parse_kpp_payment_request(qr_data)
    ws_url = parsed_req.get("ws_url")
    e2ee_key = parsed_req.get("e2ee_key")
    amount = parsed_req.get("amount")
    version = CONFIG["VERSION"]

    if not all([ws_url, e2ee_key, amount]):
        raise ValueError("Incomplete Kloak payment request")
    
    # Derive session_id from e2ee_key (same as receiver did)
    # Node only sees the hash, not the actual e2ee_key
    session_id = hashlib.sha256(e2ee_key).hexdigest()
    
    LOG.info(f"Sender initiating KPP payment of {amount} KAS")
    LOG.info(f"Connecting to Kloak node: {ws_url}")
    LOG.info(f"Protocol version: {version}")
    
    try:
        websocket = await websocket_connect(ws_url)
        
        try:
            # Send initial handshake with session_id (NOT e2ee_key)
            init_msg = {
                "role": "sender",
                "session_id": session_id  # Derived hash, node uses this for matching
            }
            await websocket.send(json.dumps(init_msg))
            LOG.info("Sent sender handshake")
            
            # Receive dust address from node (plain JSON, unencrypted)
            dust_msg = await websocket.recv()
            dust_data = json.loads(dust_msg)
            
            if dust_data.get("type") != "dust_address":
                raise ValueError(f"Expected dust address, got: {dust_data.get('type')}")
            
            dust_addr = dust_data.get("address")
            LOG.info(f"Received dust address: {dust_addr}")
            
            # Receive encrypted receiver data from node
            encrypted_receiver_data = await websocket.recv()
            LOG.info("Received encrypted receiver data")
            
            # Decrypt receiver's data using E2EE key
            receiver_data = decrypt_message(e2ee_key, encrypted_receiver_data)
            LOG.info("Decrypted receiver data")
            
            # Encrypt and send sender's UTXO and change address
            sender_data = {
                "utxo": sender_utxo,
                "change_address": change_addr,
                "amount": amount
            }
            encrypted_sender_data = encrypt_message(e2ee_key, sender_data)
            await websocket.send(encrypted_sender_data)
            LOG.info("Sent encrypted sender data to receiver")
            
            # Now BUILD THE TRANSACTION locally (node can't do this anymore)
            LOG.info("Building KPP transaction locally...")
            
            tx = kpp_tx_construct(
                sender_utxo=sender_utxo,
                sender_change=change_addr,
                receiver_utxo=receiver_data.get("utxo"),
                rec_1=receiver_data.get("address_1"),
                rec_2=receiver_data.get("address_2"),
                amount=amount,
                dust_addr=dust_addr
            )
            
            LOG.info(f"Success: Built KPP transaction locally")
            LOG.info(f"  Transaction type: 2-in, 4-out payjoin")
            LOG.info(f"  Payment amount: {amount} KAS")
            LOG.info(f"  Privacy enhancement: Active")
            
            # Validate transaction structure
            if len(tx.get("inputs", [])) != 2:
                raise ValueError("Invalid KPP transaction: Expected 2 inputs")
            if len(tx.get("outputs", [])) != 4:
                raise ValueError("Invalid KPP transaction: Expected 4 outputs")
            
            # Send transaction to receiver (encrypted) for them to sign first
            tx_to_receiver = {
                "type": "transaction",
                "tx": tx,
                "your_input_index": 1,  # Receiver is input 1
                "sender_input_index": 0
            }
            encrypted_tx = encrypt_message(e2ee_key, tx_to_receiver)
            await websocket.send(encrypted_tx)
            LOG.info("Sent transaction to receiver for signing")
            
            LOG.info("\n" + "="*60)
            LOG.info("TRANSACTION READY FOR SIGNING")
            LOG.info("="*60)
            LOG.info(f"1. Receiver will sign input #1 first")
            LOG.info(f"2. Sender will sign input #0 second")
            LOG.info(f"3. Sender broadcasts to Kaspa network")
            LOG.info("="*60)
            
            return {
                "transaction": tx,
                "input_index": 0,  # Sender is input 0
                "amount": amount,
                "websocket": websocket,
                "e2ee_key": e2ee_key,
                "utxo": sender_utxo  # Need for signing
            }
        
        finally:
            # Keep websocket open - caller is responsible for closing
            pass
                
    except websockets.exceptions.WebSocketException as e:
        LOG.error(f"WebSocket connection error: {e}")
        raise ConnectionError(f"Could not connect to Kloak node: {e}")
    except Exception as e:
        LOG.error(f"Sender connection error: {e}")
        raise


async def sender_sign_and_broadcast(result: dict, private_key: bytes, rpc_client: RPCClient) -> dict:
    """
    Sender waits for receiver signature, then signs and broadcasts.
    
    Complete flow:
    1. Wait for receiver to sign their input
    2. Sign sender's input
    3. Broadcast fully-signed transaction to Kaspa network
    4. Notify receiver of broadcast result
    
    Args:
        result: Result dictionary from sender_connect_to_kloak_node
        private_key: Sender's private key for signing
        rpc_client: RPCClient for broadcasting transaction
        
    Returns:
        Dict with:
            - success: True if broadcast successful
            - transaction_id: Transaction ID (if successful)
            - transaction: Fully signed transaction
            - error: Error message (if failed)
            
    Raises:
        Exception: If signing, communication, or broadcast fails
    """
    websocket = result["websocket"]
    e2ee_key = result["e2ee_key"]
    transaction = result["transaction"]
    input_index = result["input_index"]
    utxo = result["utxo"]
    
    try:
        # Wait for receiver to sign their input first
        LOG.info("Waiting for receiver to sign their input...")
        partial_tx_msg = await websocket.recv()
        partial_tx_data = decrypt_message(e2ee_key, partial_tx_msg)
        
        if partial_tx_data.get("type") == "receiver_signature":
            partially_signed_tx = partial_tx_data.get("tx")
            LOG.info(f"Success: Received partially-signed transaction from receiver")
        else:
            raise ValueError("Expected receiver signature")
        
        # Get UTXO amount and script pubkey for signing
        utxo_amount = utxo.get("utxoEntry", {}).get("amount", 0)
        spk_version, script_pubkey = get_utxo_script_pubkey(utxo)
        
        LOG.info(f"Signing input #{input_index} as sender (final signature)...")
        
        # Sign the transaction (sender's input)
        fully_signed_tx = sign_kaspa_transaction_input(
            partially_signed_tx,
            input_index,
            private_key,
            utxo_amount,
            script_pubkey,
            script_pubkey_version=spk_version,
        )
        
        LOG.info(f"Success: Sender signature complete")
        
        # Broadcast to Kaspa network
        LOG.info("Broadcasting transaction to Kaspa network...")
        tx_id = broadcast_transaction(rpc_client, fully_signed_tx)
        
        if tx_id:
            # Send success confirmation to receiver
            success_msg = encrypt_message(e2ee_key, {
                "type": "broadcast_success",
                "transaction_id": tx_id
            })
            await websocket.send(success_msg)
            
            await websocket.close()
            
            LOG.info(f"Success: KPP Payment Complete!")
            LOG.info(f"  Transaction ID: {tx_id}")
            
            return {
                "success": True,
                "transaction_id": tx_id,
                "transaction": fully_signed_tx
            }
        else:
            # Send error to receiver
            error_msg = encrypt_message(e2ee_key, {
                "type": "broadcast_error",
                "error": "Failed to broadcast transaction"
            })
            await websocket.send(error_msg)
            await websocket.close()
            
            return {
                "success": False,
                "error": "Broadcast failed"
            }
            
    except Exception as e:
        LOG.error(f"Error in sender signing/broadcasting: {e}")
        try:
            # Notify receiver of error
            error_msg = encrypt_message(e2ee_key, {
                "type": "error",
                "message": str(e)
            })
            await websocket.send(error_msg)
            await websocket.close()
        except Exception as notify_error:
            LOG.debug(f"Error notifying receiver of failure: {notify_error}")
        raise


def is_kloak_payment_request(data: str) -> bool:
    """
    Check if a payment request is a Kloak KPP request.
    
    Wallet integration helper: Call this to detect if a QR code or payment request
    should be handled by Kloak instead of standard Kaspa payment flow.
    
    Args:
        data: Payment request data (JSON string, URI, etc.)
        
    Returns:
        True if this is a Kloak payment request, False otherwise
    """
    try:
        parsed = parse_kpp_payment_request(data)
        return bool(parsed.get("ws_url") and parsed.get("e2ee_key") and parsed.get("amount") is not None)
    except Exception:
        return False


# Legacy function (kept for backward compatibility)
def sender_kpp_init(qr_data: str, sender_utxo: dict, change_addr: str):
    """
    DEPRECATED: Use sender_connect_to_kloak_node() instead.
    
    Legacy synchronous function that parses QR data.
    Kept for backward compatibility only.
    
    Args:
        qr_data: JSON string from QR code
        sender_utxo: Sender's UTXO (unused)
        change_addr: Sender's change address (unused)
        
    Returns:
        Dict with ws_url, e2ee_key, and amount
    """
    data = json.loads(qr_data)
    
    ws_url = data["ws_url"]
    e2ee_key = base64.b64decode(data["e2ee_key"])
    amount = data["amount"]
    
    LOG.warning("sender_kpp_init is deprecated - use sender_connect_to_kloak_node() instead")
    
    return {
        "ws_url": ws_url,
        "e2ee_key": e2ee_key,
        "amount": amount
    }


# ============================================================================
# CLI INTERFACE
# ============================================================================

def print_banner():
    """
    Display Kloak Node ASCII art banner.
    """
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██╗  ██╗██╗      ██████╗  █████╗ ██╗  ██╗                   ║
║   ██║ ██╔╝██║     ██╔═══██╗██╔══██╗██║ ██╔╝                   ║
║   █████╔╝ ██║     ██║   ██║███████║█████╔╝                    ║
║   ██╔═██╗ ██║     ██║   ██║██╔══██║██╔═██╗                    ║
║   ██║  ██╗███████╗╚██████╔╝██║  ██║██║  ██╗                   ║
║   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝                   ║
║                                                               ║
║              Payment Protocol Node                            ║
║                   Version """ + CONFIG["VERSION"] + """                               ║
║                                                               ║
║   "liberty, when it begins to take root, is a plant of        ║
║                    rapid growth"                              ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def _apply_runtime_overrides(args: argparse.Namespace) -> None:
    """Apply runtime configuration overrides from CLI args and environment variables."""
    env_ws_port = os.getenv("KLOAK_WS_PORT")
    env_ws_bind = os.getenv("KLOAK_WS_BIND")
    env_wallet_file = os.getenv("KLOAK_WALLET_FILE")

    wallet_overridden = False

    if args.ws_port is not None:
        CONFIG["WEBSOCKET_PORT"] = int(args.ws_port)
    elif env_ws_port and env_ws_port.isdigit():
        CONFIG["WEBSOCKET_PORT"] = int(env_ws_port)

    if args.ws_bind is not None:
        CONFIG["WEBSOCKET_BIND"] = str(args.ws_bind)
    elif env_ws_bind:
        CONFIG["WEBSOCKET_BIND"] = env_ws_bind

    if args.wallet_file is not None:
        CONFIG["WALLET_FILE"] = str(args.wallet_file)
        wallet_overridden = True
    elif env_wallet_file:
        CONFIG["WALLET_FILE"] = env_wallet_file
        wallet_overridden = True

    # Default wallet path: use persistent user-data dir so source/exe share state.
    # Only apply when the wallet path wasn't explicitly overridden.
    if not wallet_overridden:
        default_path = _default_wallet_path()
        _maybe_migrate_legacy_wallet(dest_path=default_path)
        CONFIG["WALLET_FILE"] = str(default_path)


def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="KloakNode", add_help=True)
    parser.add_argument("--version", action="store_true", help="Print version and exit")
    parser.add_argument("--ws-port", type=int, default=None, help="WebSocket port (or set KLOAK_WS_PORT)")
    parser.add_argument("--ws-bind", type=str, default=None, help="WebSocket bind host (or set KLOAK_WS_BIND)")
    parser.add_argument(
        "--wallet-file",
        type=str,
        default=None,
        help="Wallet file path (or set KLOAK_WALLET_FILE). Default: persistent app-data location.",
    )
    return parser.parse_args(argv)


def _prompt_and_load_wallet(*, filename: Optional[str] = None) -> Tuple[KloakWallet, str]:
    """Prompt for passphrase until the wallet decrypts successfully.

    Returns (wallet, passphrase). Ctrl+C aborts.
    """
    while True:
        passphrase = input("Passphrase: ")
        try:
            wallet = load_wallet(passphrase, filename=filename)
            return wallet, passphrase
        except Exception as e:
            # Don't crash the app; just prompt again.
            LOG.warning(f"Incorrect passphrase or wallet load failed: {e}")
            print("Incorrect passphrase. Try again (Ctrl+C to quit).")

async def auto_start_node():
    """
    Automatically start the node server (wallet must exist or will be created).
    """
    global wallet_data, rpc_client, wallet_passphrase
    
    print_banner()
    
    LOG.info("Auto-starting Kloak Node...")
    
    # Initialize RPC client
    try:
        rpc_client = init_rpc_client()
    except Exception as e:
        LOG.error(f"Failed to connect to Kaspa node: {e}")
        LOG.error("Please check your Kaspa node configuration")
        sys.exit(1)
    
    # Check if wallet exists
    wallet_file = CONFIG["WALLET_FILE"]
    
    if not os.path.exists(wallet_file):
        LOG.error(f"No wallet found at {wallet_file}")
        print("\n" + "="*60)
        print("FIRST-TIME SETUP REQUIRED")
        print("="*60)
        print("\nNo wallet found. Creating new wallet...")
        
        passphrase = input("\nEnter encryption passphrase: ")
        confirm = input("Confirm passphrase: ")
        
        if passphrase != confirm:
            LOG.error("Passphrases don't match!")
            sys.exit(1)
        
        wallet_data = create_wallet(passphrase)
        save_wallet(wallet_data, passphrase)
        wallet_passphrase = passphrase
        
        print(f"\nSuccess: Wallet created successfully!")
        print(f"\nCRITICAL: Write down your 12-word recovery phrase:")
        print(f"\n{'='*60}")
        print(f"{wallet_data.mnemonic}")
        print(f"{'='*60}\n")
        print("Store this in a safe place. You'll need it to recover your wallet.")
        
        funding_addr = node_fund(rpc_client, wallet_data)
        print(f"\nFUND YOUR NODE:")
        print(f"Send at least {CONFIG['FUND_AMOUNT_KAS']} KAS to:")
        print(f"{funding_addr}\n")

        kaspa_uri = f"kaspa:{funding_addr}"
        qr_payload = _funding_qr_payload(funding_addr)
        print("Scan to fund (Kaspa address):")
        if not _print_ascii_qr(qr_payload):
            print("(QR unavailable: install optional dependency 'qrcode')")
            print(qr_payload)
        print()
        
        input("Press Enter when you have funded the node to continue...")
    else:
        # Load existing wallet
        print("\nWallet found. Enter passphrase to start node.")
        try:
            wallet_data, wallet_passphrase = _prompt_and_load_wallet(filename=wallet_file)
            LOG.info("Success: Wallet loaded successfully")
        except KeyboardInterrupt:
            print("\nCancelled.")
            sys.exit(0)
    
    # Check balance
    balance_info = get_wallet_total_balance(rpc_client, wallet_data)
    
    if balance_info['total'] < CONFIG['FUND_AMOUNT_KAS']:
        LOG.warning(f"Low balance: {balance_info['total']:.4f} KAS")
        LOG.warning(f"Node requires at least {CONFIG['FUND_AMOUNT_KAS']} KAS for operations")
        print(f"\nWARNING: Insufficient funds!")
        print(f"Current balance: {balance_info['total']:.4f} KAS")
        print(f"Required: {CONFIG['FUND_AMOUNT_KAS']} KAS")
        fund_addr = node_fund(rpc_client, wallet_data)
        print(f"\nFund address: {fund_addr}\n")

        qr_payload = _funding_qr_payload(fund_addr)
        print("Scan to fund (Kaspa address):")
        if not _print_ascii_qr(qr_payload):
            print("(QR unavailable: install optional dependency 'qrcode')")
            print(qr_payload)
        print()
        
        print("Continuing anyway (node will operate with limited functionality until funded).")
    else:
        LOG.info(f"Success: Wallet funded: {balance_info['total']:.4f} KAS")
    
    # Start node
    LOG.info("Starting node server...")
    await run_node_server(wallet_data, rpc_client)


def main():
    """
    Main entry point.

    Default behavior: auto-start the node.
    Supports --help/--version without starting the node.
    """
    try:
        args = _parse_args()

        if args.version:
            print(CONFIG["VERSION"])
            return

        _apply_runtime_overrides(args)

        asyncio.run(auto_start_node())
    except KeyboardInterrupt:
        print("\n\nKloak Node stopped")
        if rpc_client:
            rpc_client.close()
        LOG.info("Shutdown complete.")
    except Exception as e:
        LOG.error(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
