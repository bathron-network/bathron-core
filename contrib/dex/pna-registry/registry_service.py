#!/usr/bin/env python3
"""
PNA LP Registry Service

Indexes LP registrations from the BATHRON blockchain (OP_RETURN TXs),
verifies MN backing for tier classification, and health-checks LPs.

Endpoints:
  GET /api/registry/lps          - All registered LPs
  GET /api/registry/lps/online   - Online LPs only
  GET /api/registry/status       - Indexer health

Run:
  uvicorn registry_service:app --host 0.0.0.0 --port 3003
"""

import asyncio
import hashlib
import ipaddress
import json
import logging
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

# =============================================================================
# LOGGING
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("pna-registry")

# =============================================================================
# CONFIG
# =============================================================================

PNA_PREFIX = "PNA|LP|01|"
PNA_PREFIX_HEX = PNA_PREFIX.encode("utf-8").hex()
PNA_UNREGISTER = "PNA|LP|01|UNREG"

SCAN_INTERVAL_S = 60        # Scan new blocks every 60s
HEALTH_INTERVAL_S = 30      # Health check every 30s
TIER_REFRESH_S = 300        # Re-verify MN tiers every 5 min
HEALTH_TIMEOUT_S = 10       # HTTP timeout for LP health checks
OFFLINE_THRESHOLD = 50      # Consecutive failures before marking offline (high to tolerate network issues)
BACKOFF_INTERVAL_S = 120    # Poll interval for offline LPs

PERSISTENCE_FILE = Path.home() / ".bathron" / "lp_registry.json"
START_SCAN_HEIGHT = 1       # Start scanning from block 1

CLI_PATHS = [
    Path.home() / "bathron" / "bin" / "bathron-cli",
    Path.home() / "BATHRON" / "src" / "bathron-cli",
    Path.home() / "BATHRON-Core" / "src" / "bathron-cli",
    Path("/usr/local/bin/bathron-cli"),
    Path.home() / "bathron-cli",
]


# =============================================================================
# RPC CLIENT
# =============================================================================

def find_cli() -> Optional[Path]:
    """Find bathron-cli binary."""
    for p in CLI_PATHS:
        if p.exists():
            return p
    return None


CLI_PATH = find_cli()


def rpc_sync(method: str, *args, timeout: int = 30) -> Any:
    """Call bathron-cli RPC (synchronous — use rpc() in async context)."""
    if not CLI_PATH:
        raise RuntimeError("bathron-cli not found")
    cmd = [str(CLI_PATH), "-testnet", method] + [str(a) for a in args]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            log.error(f"RPC error ({method}): {result.stderr.strip()}")
            return None
        output = result.stdout.strip()
        if not output:
            return None
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            return output
    except subprocess.TimeoutExpired:
        log.error(f"RPC timeout: {method}")
        return None


async def rpc(method: str, *args, timeout: int = 30) -> Any:
    """Call bathron-cli RPC (async — runs subprocess in thread pool)."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: rpc_sync(method, *args, timeout=timeout))


# =============================================================================
# ENDPOINT VALIDATION (SSRF protection)
# =============================================================================

# Private/reserved IP ranges that must not be health-checked
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def is_valid_lp_endpoint(url: str) -> bool:
    """Validate that an LP endpoint URL is safe to health-check.

    Rejects non-HTTP schemes, private IPs, and malformed URLs.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        if not parsed.hostname:
            return False
        if not parsed.port and parsed.scheme == "http":
            # Allow default port 80 but require explicit port for clarity
            pass
        # Check if hostname is an IP in a private range
        try:
            ip = ipaddress.ip_address(parsed.hostname)
            for net in _PRIVATE_NETWORKS:
                if ip in net:
                    log.warning(f"Rejected private IP endpoint: {url}")
                    return False
        except ValueError:
            pass  # Hostname is a DNS name, not an IP — allow it
        return True
    except Exception:
        return False


# =============================================================================
# LP REGISTRY DATA
# =============================================================================

class LPEntry:
    """A registered LP."""

    def __init__(self, address: str, endpoint: str, txid: str, height: int,
                 reg_time: float):
        self.address = address
        self.endpoint = endpoint
        self.txid = txid
        self.height = height
        self.reg_time = reg_time
        self.tier = 2               # Default: Tier 2 (no MN)
        self.mn_protx: Optional[str] = None
        self.status = "new"         # new, online, degraded, offline
        self.last_seen: float = 0
        self.last_checked: float = 0  # Last health check attempt time
        self.fail_count = 0
        self.cached_info: Optional[Dict] = None

    def to_dict(self) -> Dict:
        return {
            "address": self.address,
            "endpoint": self.endpoint,
            "txid": self.txid,
            "height": self.height,
            "reg_time": self.reg_time,
            "tier": self.tier,
            "mn_protx": self.mn_protx,
            "status": self.status,
            "last_seen": self.last_seen,
            "last_checked": self.last_checked,
            "fail_count": self.fail_count,
            "cached_info": self.cached_info,
        }

    @classmethod
    def from_dict(cls, d: Dict) -> "LPEntry":
        lp = cls(
            address=d["address"],
            endpoint=d["endpoint"],
            txid=d["txid"],
            height=d["height"],
            reg_time=d.get("reg_time", 0),
        )
        lp.tier = d.get("tier", 2)
        lp.mn_protx = d.get("mn_protx")
        lp.status = d.get("status", "new")
        lp.last_seen = d.get("last_seen", 0)
        lp.last_checked = d.get("last_checked", 0)
        lp.fail_count = d.get("fail_count", 0)
        lp.cached_info = d.get("cached_info")
        return lp


class Registry:
    """In-memory LP registry with JSON persistence."""

    def __init__(self):
        self.lps: Dict[str, LPEntry] = {}  # key = sender address
        self.last_scanned_height = 0
        self.last_scanned_hash: Optional[str] = None
        self.last_scan_time: float = 0
        self.last_tier_check: float = 0
        self._load()

    def _load(self):
        """Load from disk."""
        if PERSISTENCE_FILE.exists():
            try:
                with open(PERSISTENCE_FILE) as f:
                    data = json.load(f)
                self.last_scanned_height = data.get("last_scanned_height", 0)
                self.last_scanned_hash = data.get("last_scanned_hash")
                self.last_scan_time = data.get("last_scan_time", 0)
                for addr, lp_data in data.get("lps", {}).items():
                    lp = LPEntry.from_dict(lp_data)
                    # Reset health state on startup so all LPs get checked immediately
                    lp.fail_count = 0
                    lp.last_checked = 0
                    lp.status = "online"
                    self.lps[addr] = lp
                log.info(f"Loaded {len(self.lps)} LPs from disk, "
                         f"last scanned height: {self.last_scanned_height}")
            except Exception as e:
                log.error(f"Failed to load registry: {e}")

    def save(self):
        """Persist to disk (atomic write via temp file + rename)."""
        PERSISTENCE_FILE.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "last_scanned_height": self.last_scanned_height,
            "last_scanned_hash": self.last_scanned_hash,
            "last_scan_time": self.last_scan_time,
            "lps": {addr: lp.to_dict() for addr, lp in self.lps.items()},
        }
        tmp_file = PERSISTENCE_FILE.with_suffix(".tmp")
        with open(tmp_file, "w") as f:
            json.dump(data, f, indent=2)
        tmp_file.rename(PERSISTENCE_FILE)

    def register(self, address: str, endpoint: str, txid: str, height: int):
        """Register or update an LP.

        One endpoint = one LP entry. If the same endpoint is re-registered
        from a new address (e.g. after re-registration for tier upgrade),
        the old entry is replaced.
        """
        existing = self.lps.get(address)
        if existing and existing.height >= height:
            return  # Older registration, ignore

        # Remove any previous entry for the same endpoint (different address)
        stale = [
            addr for addr, lp in self.lps.items()
            if lp.endpoint == endpoint and addr != address and lp.height < height
        ]
        for addr in stale:
            log.info(f"LP superseded: {addr} -> {endpoint} "
                     f"(replaced by {address} at block {height})")
            del self.lps[addr]

        self.lps[address] = LPEntry(
            address=address, endpoint=endpoint, txid=txid,
            height=height, reg_time=time.time()
        )
        log.info(f"LP registered: {address} -> {endpoint} (block {height})")

    def unregister(self, address: str, height: int):
        """Unregister an LP."""
        existing = self.lps.get(address)
        if existing and existing.height < height:
            del self.lps[address]
            log.info(f"LP unregistered: {address} (block {height})")

    def get_online(self) -> List[Dict]:
        """Get all online LPs, sorted by tier then registration time."""
        result = []
        for lp in self.lps.values():
            if lp.status in ("online", "new"):
                result.append(lp.to_dict())
        result.sort(key=lambda x: (x["tier"], x["reg_time"]))
        return result

    def get_all(self) -> List[Dict]:
        """Get all LPs."""
        result = [lp.to_dict() for lp in self.lps.values()]
        result.sort(key=lambda x: (x["tier"], x["reg_time"]))
        return result


# Global registry
registry = Registry()


# =============================================================================
# WEBSOCKET MANAGER
# =============================================================================

class RegistryWSManager:
    """Manage WebSocket connections for registry push updates."""

    def __init__(self):
        self.connections: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.connections.append(ws)
        log.info(f"Registry WS connected ({len(self.connections)} total)")

    def disconnect(self, ws: WebSocket):
        if ws in self.connections:
            self.connections.remove(ws)

    async def broadcast(self, msg: dict):
        """Send to all connected WS clients."""
        dead = []
        for ws in self.connections:
            try:
                await ws.send_json(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    async def broadcast_lps(self):
        """Broadcast full LP list to all clients."""
        if not self.connections:
            return
        lps_data = registry.get_all()
        await self.broadcast({
            "type": "lps",
            "data": {"lps": lps_data, "count": len(lps_data)}
        })

    async def broadcast_lp_update(self, lp: "LPEntry"):
        """Broadcast a single LP update."""
        if not self.connections:
            return
        await self.broadcast({
            "type": "lp_update",
            "data": lp.to_dict()
        })

registry_ws = RegistryWSManager()


# =============================================================================
# BLOCK SCANNER
# =============================================================================

def decode_op_return_hex(hex_str: str) -> Optional[str]:
    """Decode OP_RETURN scriptPubKey hex to UTF-8 string.

    Script format: 6a <pushdata> <data>
    """
    try:
        raw = bytes.fromhex(hex_str)
        if len(raw) < 2 or raw[0] != 0x6a:
            return None
        pos = 1
        # Read push opcode
        push = raw[pos]
        pos += 1
        if push <= 75:
            data_len = push
        elif push == 0x4c:  # OP_PUSHDATA1
            data_len = raw[pos]
            pos += 1
        elif push == 0x4d:  # OP_PUSHDATA2
            data_len = int.from_bytes(raw[pos:pos+2], 'little')
            pos += 2
        else:
            return None
        data = raw[pos:pos + data_len]
        return data.decode("utf-8")
    except Exception:
        return None


async def get_sender_address(tx: Dict) -> Optional[str]:
    """Extract the sender address from vin[0] of a transaction."""
    vin = tx.get("vin", [])
    if not vin:
        return None
    first_input = vin[0]

    # Coinbase TXs have no sender
    if "coinbase" in first_input:
        return None

    prev_txid = first_input.get("txid")
    prev_vout = first_input.get("vout")
    if prev_txid is None or prev_vout is None:
        return None

    # Look up the previous TX to get the sender address
    prev_tx = await rpc("getrawtransaction", prev_txid, "1")
    if not prev_tx:
        return None

    prev_outputs = prev_tx.get("vout", [])
    for out in prev_outputs:
        if out.get("n") == prev_vout:
            spk = out.get("scriptPubKey", {})
            addresses = spk.get("addresses", [])
            if addresses:
                return addresses[0]
    return None


async def scan_block(height: int) -> int:
    """Scan a single block for PNA LP registrations. Returns 0 on success."""
    block_hash = await rpc("getblockhash", height)
    if not block_hash:
        return -1

    block = await rpc("getblock", block_hash, "2")
    if not block:
        return -1

    for tx in block.get("tx", []):
        for vout in tx.get("vout", []):
            spk = vout.get("scriptPubKey", {})
            if spk.get("type") != "nulldata":
                continue

            hex_data = spk.get("hex", "")
            decoded = decode_op_return_hex(hex_data)
            if not decoded or not decoded.startswith(PNA_PREFIX):
                continue

            # Found a PNA LP TX
            sender = await get_sender_address(tx)
            if not sender:
                log.warning(f"Could not determine sender for TX {tx['txid']}")
                continue

            payload = decoded[len(PNA_PREFIX):]

            if payload == "UNREG":
                registry.unregister(sender, height)
                asyncio.create_task(registry_ws.broadcast_lps())
            else:
                endpoint = payload.strip()
                if endpoint and is_valid_lp_endpoint(endpoint):
                    registry.register(sender, endpoint, tx["txid"], height)
                    asyncio.create_task(registry_ws.broadcast_lps())
                elif endpoint:
                    log.warning(f"Rejected invalid endpoint: {endpoint}")

    return 0


async def block_scanner_loop():
    """Background task: scan new blocks for LP registrations."""
    log.info("Block scanner started")

    while True:
        try:
            chain_height = await rpc("getblockcount")
            if chain_height is None:
                log.warning("Cannot get chain height, retrying...")
                await asyncio.sleep(SCAN_INTERVAL_S)
                continue

            chain_height = int(chain_height)
            start = max(registry.last_scanned_height + 1, START_SCAN_HEIGHT)

            # Check for reorg: verify our last scanned block hash still matches
            if registry.last_scanned_hash and registry.last_scanned_height > 0:
                current_hash = await rpc("getblockhash", registry.last_scanned_height)
                if current_hash and current_hash != registry.last_scanned_hash:
                    log.warning(f"Reorg detected at height {registry.last_scanned_height}!")
                    # Walk back to find fork point (max 100 blocks back)
                    fork_height = registry.last_scanned_height
                    for _ in range(100):
                        fork_height -= 1
                        if fork_height < START_SCAN_HEIGHT:
                            fork_height = START_SCAN_HEIGHT
                            break
                        # We don't store per-block hashes, so rescan from further back
                    # Remove LPs registered in potentially-orphaned blocks
                    registry.lps = {
                        addr: lp for addr, lp in registry.lps.items()
                        if lp.height <= fork_height
                    }
                    registry.last_scanned_height = fork_height
                    registry.last_scanned_hash = await rpc("getblockhash", fork_height)
                    start = fork_height + 1
                    log.info(f"Re-scanning from height {start} "
                             f"({len(registry.lps)} LPs preserved)")

            if start <= chain_height:
                scanned = 0
                for h in range(start, chain_height + 1):
                    if await scan_block(h) != 0:
                        break
                    scanned += 1

                if scanned > 0:
                    registry.last_scanned_height = start + scanned - 1
                    registry.last_scanned_hash = await rpc(
                        "getblockhash", registry.last_scanned_height
                    )
                    registry.last_scan_time = time.time()
                    registry.save()
                    if scanned > 1:
                        log.info(f"Scanned {scanned} blocks "
                                 f"({start} -> {registry.last_scanned_height}), "
                                 f"{len(registry.lps)} LPs")

        except Exception as e:
            log.error(f"Block scanner error: {e}")

        await asyncio.sleep(SCAN_INTERVAL_S)


# =============================================================================
# TIER VERIFIER — Operator Signature Model
#
# Tier 1 = registration TX signed by an MN operator.
# Verification: lp.address == address derived from operatorPubKey.
# One LP per unique operator key (enforced by address-keyed registry).
# =============================================================================

_BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_TESTNET_PUBKEY_VERSION = 139  # base58Prefixes[PUBKEY_ADDRESS] from chainparams.cpp


def _base58_encode(data: bytes) -> str:
    """Base58 encode raw bytes."""
    n = int.from_bytes(data, 'big')
    result = ''
    while n > 0:
        n, r = divmod(n, 58)
        result = _BASE58_ALPHABET[r] + result
    for byte in data:
        if byte == 0:
            result = _BASE58_ALPHABET[0] + result
        else:
            break
    return result


def pubkey_to_address(pubkey_hex: str,
                      version: int = _TESTNET_PUBKEY_VERSION) -> str:
    """Derive P2PKH address from a compressed ECDSA secp256k1 public key.

    Standard Bitcoin derivation: base58check(version || RIPEMD160(SHA256(pubkey)))
    """
    try:
        pubkey_bytes = bytes.fromhex(pubkey_hex)
    except ValueError:
        return ""
    if len(pubkey_bytes) != 33:
        return ""
    sha = hashlib.sha256(pubkey_bytes).digest()
    h160 = hashlib.new('ripemd160', sha).digest()
    versioned = bytes([version]) + h160
    checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
    return _base58_encode(versioned + checksum)


async def get_operator_addresses() -> Dict[str, Dict]:
    """Build a map of operator-derived address -> operator info.

    For each MN, derive a P2PKH address from its operatorPubKey.
    One operator key can manage N MNs, but produces one unique address.

    Returns: {operator_address: {"protx": first_protx, "operator_pubkey": hex}}
    """
    mn_list = await rpc("protx_list")
    if not mn_list or not isinstance(mn_list, list):
        return {}

    operators: Dict[str, Dict] = {}
    seen_pubkeys: set = set()

    for mn in mn_list:
        protx = mn.get("proTxHash", "")
        state = mn.get("dmnstate") or mn.get("state") or {}

        op_pubkey = state.get("operatorPubKey", "")
        if not op_pubkey or len(op_pubkey) != 66:  # 33 bytes = 66 hex chars
            continue

        if op_pubkey in seen_pubkeys:
            continue  # Same operator key managing multiple MNs — one address
        seen_pubkeys.add(op_pubkey)

        addr = pubkey_to_address(op_pubkey)
        if addr:
            operators[addr] = {
                "protx": protx,
                "operator_pubkey": op_pubkey,
            }

    return operators


async def tier_verifier_loop():
    """Verify tier: LP registered from operator-derived address = Tier 1.

    One LP per operator key (the address-keyed registry enforces this
    naturally: one address = one entry).
    """
    log.info("Tier verifier started (operator-signature model)")

    while True:
        try:
            operator_map = await get_operator_addresses()
            if operator_map:
                tier_changed = False
                for lp in registry.lps.values():
                    prev_tier = lp.tier
                    op_info = operator_map.get(lp.address)
                    if op_info:
                        if lp.tier != 1:
                            log.info(
                                f"LP {lp.endpoint} promoted to Tier 1 "
                                f"(operator: {op_info['operator_pubkey'][:16]}...)"
                            )
                        lp.tier = 1
                        lp.mn_protx = op_info["protx"]
                    else:
                        if lp.tier == 1:
                            log.info(
                                f"LP {lp.endpoint} demoted to Tier 2 "
                                f"(not an operator address)"
                            )
                        lp.tier = 2
                        lp.mn_protx = None
                    if lp.tier != prev_tier:
                        tier_changed = True
                registry.save()
                registry.last_tier_check = time.time()
                if tier_changed:
                    asyncio.create_task(registry_ws.broadcast_lps())
        except Exception as e:
            log.error(f"Tier verifier error: {e}")

        await asyncio.sleep(TIER_REFRESH_S)


# =============================================================================
# HEALTH CHECKER
# =============================================================================

async def check_lp_health(client: httpx.AsyncClient, lp: LPEntry):
    """Check a single LP's health."""
    lp.last_checked = time.time()
    prev_status = lp.status
    try:
        resp = await client.get(
            f"{lp.endpoint}/api/status",
            timeout=HEALTH_TIMEOUT_S,
        )
        if resp.status_code == 200:
            lp.fail_count = 0
            lp.last_seen = time.time()
            if lp.status != "online":
                log.info(f"LP {lp.endpoint} is now ONLINE")
            lp.status = "online"

            # Also fetch lp/info for cached data
            try:
                info_resp = await client.get(
                    f"{lp.endpoint}/api/lp/info",
                    timeout=HEALTH_TIMEOUT_S,
                )
                if info_resp.status_code == 200:
                    lp.cached_info = info_resp.json()
            except Exception:
                pass  # Info fetch is best-effort
        else:
            lp.fail_count += 1
    except Exception:
        lp.fail_count += 1

    if lp.fail_count >= OFFLINE_THRESHOLD and lp.status != "offline":
        log.warning(f"LP {lp.endpoint} marked OFFLINE "
                    f"({lp.fail_count} consecutive failures)")
        lp.status = "offline"

    # Broadcast if status changed
    if lp.status != prev_status:
        asyncio.create_task(registry_ws.broadcast_lp_update(lp))


async def health_checker_loop():
    """Background task: periodically health-check all registered LPs."""
    log.info("Health checker started")

    async with httpx.AsyncClient() as client:
        while True:
            try:
                tasks = []
                for lp in list(registry.lps.values()):
                    # Backoff for offline LPs (use last check time, not last seen)
                    if lp.status == "offline":
                        since_check = time.time() - lp.last_checked
                        if since_check < BACKOFF_INTERVAL_S:
                            continue
                    tasks.append(check_lp_health(client, lp))

                if tasks:
                    await asyncio.gather(*tasks)
                    registry.save()

            except Exception as e:
                log.error(f"Health checker error: {e}")

            await asyncio.sleep(HEALTH_INTERVAL_S)


# =============================================================================
# FASTAPI APP
# =============================================================================

app = FastAPI(title="PNA LP Registry", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup():
    """Start background tasks."""
    if not CLI_PATH:
        log.error("bathron-cli not found! Scanner disabled.")
        return
    asyncio.create_task(block_scanner_loop())
    asyncio.create_task(tier_verifier_loop())
    asyncio.create_task(health_checker_loop())
    log.info(f"PNA Registry started — CLI: {CLI_PATH}")


@app.get("/api/registry/lps")
async def get_all_lps():
    """List all registered LPs with tier and status."""
    return {
        "lps": registry.get_all(),
        "count": len(registry.lps),
        "timestamp": time.time(),
    }


@app.get("/api/registry/lps/online")
async def get_online_lps():
    """List only online LPs (for pna-swap consumption)."""
    online = registry.get_online()
    return {
        "lps": online,
        "count": len(online),
        "timestamp": time.time(),
    }


@app.get("/api/registry/status")
async def get_registry_status():
    """Indexer health and stats."""
    chain_height = await rpc("getblockcount") if CLI_PATH else None
    return {
        "cli_found": CLI_PATH is not None,
        "cli_path": str(CLI_PATH) if CLI_PATH else None,
        "chain_height": chain_height,
        "last_scanned_height": registry.last_scanned_height,
        "last_scan_time": registry.last_scan_time,
        "last_tier_check": registry.last_tier_check,
        "lp_count_total": len(registry.lps),
        "lp_count_online": len([lp for lp in registry.lps.values()
                                if lp.status in ("online", "new")]),
        "lp_count_tier1": len([lp for lp in registry.lps.values()
                               if lp.tier == 1]),
        "persistence_file": str(PERSISTENCE_FILE),
        "ws_connections": len(registry_ws.connections),
    }


@app.websocket("/ws")
async def registry_websocket(ws: WebSocket):
    """WebSocket endpoint for real-time LP discovery updates."""
    await registry_ws.connect(ws)

    # Send full LP list on connect
    try:
        lps_data = registry.get_all()
        await ws.send_json({
            "type": "lps",
            "data": {"lps": lps_data, "count": len(lps_data)}
        })
    except Exception:
        registry_ws.disconnect(ws)
        return

    try:
        while True:
            msg = await ws.receive()
            if msg.get("type") == "websocket.disconnect":
                break
            text = msg.get("text")
            if text:
                try:
                    raw = json.loads(text)
                    if raw.get("type") == "ping":
                        await ws.send_json({"type": "pong"})
                except (json.JSONDecodeError, Exception):
                    pass
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        registry_ws.disconnect(ws)
        log.info(f"Registry WS disconnected ({len(registry_ws.connections)} remaining)")


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=3003)
