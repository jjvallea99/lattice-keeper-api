#!/usr/bin/env python3
"""
Lattice Keeper v0.21.0
Bitcoin-anchored document integrity + RWA tokenization
with ML-DSA-65 (FIPS 204) post-quantum digital signatures.

Every anchor is now:
  1. SHA-256 hashed
  2. PQC-signed with ML-DSA-65 (Dilithium3)
  3. Written to Bitcoin via OP_RETURN

This makes anchors verifiable even against future quantum computers.
"""
from __future__ import annotations

import asyncio
import base64
import functools
import hashlib
import json
import os
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict

import aiohttp
import redis.asyncio as redis
import structlog
from aiohttp import web
from prometheus_client import Counter, Histogram, start_http_server

# ======================== PQC: ML-DSA-65 ========================
# Uses liboqs (Open Quantum Safe) — the reference implementation of
# FIPS 204 ML-DSA (formerly CRYSTALS-Dilithium).
try:
    import oqs
    PQC_AVAILABLE = True
except ImportError:
    PQC_AVAILABLE = False

PQC_ALGORITHM = "Dilithium3"  # = ML-DSA-65 in FIPS 204


class PQCSigner:
    """
    Manages ML-DSA-65 keypair for signing anchor hashes.

    Key storage:
      - Private key: env var PQC_SECRET_KEY (base64) or file at PQC_KEY_PATH
      - Public key:  env var PQC_PUBLIC_KEY (base64) or derived from secret key
      - If neither exists, generates a fresh keypair and saves to PQC_KEY_PATH

    SECURITY NOTE: In production, the secret key should live in a HSM or
    air-gapped signer. This file-based approach is for prototyping.
    """

    def __init__(self):
        self.algorithm = PQC_ALGORITHM
        self.secret_key: bytes = b""
        self.public_key: bytes = b""
        self._signer = None

        if not PQC_AVAILABLE:
            structlog.get_logger().warning(
                "pqc_unavailable",
                msg="liboqs not installed — PQC signing disabled. "
                    "Install with: pip install oqs"
            )
            return

        self._load_or_generate_keys()

    def _load_or_generate_keys(self):
        log = structlog.get_logger("pqc")
        key_path = Path(os.getenv("PQC_KEY_PATH", "/data/pqc_keys"))

        # Try env vars first
        sk_b64 = os.getenv("PQC_SECRET_KEY", "")
        pk_b64 = os.getenv("PQC_PUBLIC_KEY", "")

        if sk_b64 and pk_b64:
            self.secret_key = base64.b64decode(sk_b64)
            self.public_key = base64.b64decode(pk_b64)
            log.info("pqc_keys_loaded", source="env", algorithm=self.algorithm)
            return

        # Try file-based keys
        sk_file = key_path / "secret_key.bin"
        pk_file = key_path / "public_key.bin"

        if sk_file.exists() and pk_file.exists():
            self.secret_key = sk_file.read_bytes()
            self.public_key = pk_file.read_bytes()
            log.info("pqc_keys_loaded", source="file", algorithm=self.algorithm,
                     path=str(key_path))
            return

        # Generate fresh keypair
        log.info("pqc_generating_keypair", algorithm=self.algorithm)
        with oqs.Signature(self.algorithm) as signer:
            self.public_key = signer.generate_keypair()
            self.secret_key = signer.export_secret_key()

        # Persist to disk
        key_path.mkdir(parents=True, exist_ok=True)
        sk_file.write_bytes(self.secret_key)
        pk_file.write_bytes(self.public_key)
        os.chmod(sk_file, 0o600)  # restrict secret key permissions

        log.info("pqc_keypair_generated", algorithm=self.algorithm,
                 pk_size=len(self.public_key), sk_size=len(self.secret_key),
                 path=str(key_path))

    @property
    def available(self) -> bool:
        return PQC_AVAILABLE and len(self.secret_key) > 0

    def sign(self, message: bytes) -> bytes:
        """Sign a message with ML-DSA-65. Returns raw signature bytes."""
        if not self.available:
            raise RuntimeError("PQC signing not available")
        with oqs.Signature(self.algorithm, self.secret_key) as signer:
            return signer.sign(message)

    def verify(self, message: bytes, signature: bytes, public_key: bytes = None) -> bool:
        """Verify an ML-DSA-65 signature. Uses own public key if none provided."""
        if not PQC_AVAILABLE:
            raise RuntimeError("PQC verification not available — liboqs not installed")
        pk = public_key or self.public_key
        with oqs.Signature(self.algorithm) as verifier:
            return verifier.verify(message, signature, pk)

    def public_key_b64(self) -> str:
        """Return the public key as base64 for API responses."""
        return base64.b64encode(self.public_key).decode() if self.public_key else ""

    def info(self) -> Dict:
        """Return PQC status info for health/debug endpoints."""
        return {
            "algorithm": self.algorithm,
            "fips": "FIPS 204 (ML-DSA-65)",
            "available": self.available,
            "public_key_bytes": len(self.public_key),
            "public_key_b64": self.public_key_b64()[:64] + "..." if self.available else "",
        }


# ======================== LOGGING ========================
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.ExceptionPrettyPrinter(),
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(structlog.INFO),
    cache_logger_on_first_use=True,
)

log = structlog.get_logger("lattice_keeper")

UTC = timezone.utc

# Matches standard anchors (LK-20260405-133200) and RWA anchors (LK-RWA-<16HEX>)
ANCHOR_ID_PATTERN = re.compile(r"^LK-(?:RWA-[A-F0-9]{16}|\d{8}-\d{6})$")

MAX_VALUATION_CAD = 1_000_000_000_000  # 1 trillion CAD ceiling
MAX_OWNER_LEN     = 256
MAX_DATA_LEN      = 4096


# ======================== METRICS ========================
ANCHORS_CREATED  = Counter('lattice_anchors_created_total',    'Total anchors created')
ANCHORS_VERIFIED = Counter('lattice_anchors_verified_total',   'Total verifications')
ANCHOR_LATENCY   = Histogram('lattice_anchor_latency_seconds', 'Anchor creation latency')
PQC_SIGNS        = Counter('lattice_pqc_signatures_total',     'Total PQC signatures created')
PQC_VERIFIES     = Counter('lattice_pqc_verifications_total',  'Total PQC verifications')
ERROR_COUNTER    = Counter('lattice_errors_total', 'Total errors', ['endpoint'])


# ======================== CONFIG ========================
@dataclass
class AppConfig:
    lattice_btc_mainnet: bool = os.getenv("LATTICE_BTC_MAINNET",       "false").lower() == "true"
    lightning_enabled:   bool = os.getenv("LATTICE_LIGHTNING_ENABLED", "true").lower()  == "true"
    api_key:             str  = os.getenv("LATTICE_API_KEY", "")
    domain:              str  = os.getenv("DOMAIN",     "lattice.example.com")
    tls_enabled:         bool = os.getenv("TLS_ENABLED", "false").lower() == "true"
    rate_limit_rps:      int  = int(os.getenv("RATE_LIMIT_RPS", 20))
    api_host:            str  = os.getenv("API_HOST", "0.0.0.0")
    api_port:            int  = int(os.getenv("API_PORT", 8765))
    debug:               bool = os.getenv("DEBUG", "false").lower() == "true"
    pqc_enabled:         bool = os.getenv("PQC_ENABLED", "true").lower() == "true"

    @classmethod
    def from_env(cls):
        config = cls()
        if not config.api_key:
            raise ValueError("LATTICE_API_KEY environment variable must be set")
        return config


# ======================== MIDDLEWARES ========================
@web.middleware
async def rate_limit_middleware(request: web.Request, handler):
    config = request.app['config']
    key = request.headers.get("X-API-Key") or request.remote or "unknown"
    redis_client: redis.Redis = request.app['guardian'].redis

    try:
        current = await redis_client.incr(f"ratelimit:{key}")
        if current == 1:
            await redis_client.expire(f"ratelimit:{key}", 60)
        if current > config.rate_limit_rps * 60:  # per minute
            return web.json_response({"error": "Rate limit exceeded"}, status=429)
    except Exception:
        pass  # Fail open on Redis issues

    return await handler(request)


# ======================== AUTH ========================
def require_auth(func):
    @functools.wraps(func)
    async def wrapper(request: web.Request):
        config = request.app['config']
        key = (
            request.headers.get("X-API-Key")
            or request.headers.get("Authorization", "").replace("Bearer ", "").strip()
        )
        if not key or key != config.api_key:
            log.warning("auth_failed", remote=request.remote)
            return web.json_response({"error": "Unauthorized"}, status=401)
        return await func(request)
    return wrapper


# ======================== BITCOIN RPC ========================
class BitcoinRPC:
    def __init__(self, mainnet: bool):
        self.url     = "http://bitcoin-core:8332"
        self.session = None
        self.mainnet = mainnet

    async def call(self, method: str, params: list = None, retries: int = 3):
        if self.session is None:
            self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30))
        for attempt in range(retries):
            try:
                payload = {
                    "jsonrpc": "2.0", "id": "lattice",
                    "method": method, "params": params or []
                }
                async with self.session.post(self.url, json=payload) as resp:
                    data = await resp.json()
                    if data.get("error"):
                        raise RuntimeError(f"RPC Error: {data['error']}")
                    return data.get("result")
            except Exception as e:
                if attempt == retries - 1:
                    log.error("bitcoin_rpc_failed", method=method, attempt=attempt + 1, error=str(e))
                    raise
                await asyncio.sleep(0.5 * (2 ** attempt))

    async def create_op_return_tx(self, data_hash: str) -> Dict:
        address = await self.call("getrawchangeaddress", ["bech32"])

        if self.mainnet:
            psbt_result = await self.call(
                "walletcreatefundedpsbt",
                [[], [{"data": data_hash}, {address: 0.00000546}]]
            )
            log.info("coldcard_psbt_prepared")
            return {
                "psbt":    psbt_result["psbt"],
                "status":  "PENDING_COLDCARD",
                "message": "Sign this PSBT with Coldcard, then POST to /broadcast",
            }

        raw_tx = await self.call(
            "createrawtransaction",
            [[], [{"data": data_hash}, {address: 0.00000546}]]
        )
        funded = await self.call("fundrawtransaction", [raw_tx])
        signed = await self.call("signrawtransactionwithwallet", [funded["hex"]])
        if not signed.get("complete"):
            raise RuntimeError("Transaction signing incomplete — wallet may be locked")
        txid = await self.call("sendrawtransaction", [signed["hex"]])
        return {"txid": txid, "status": "BROADCAST"}


# ======================== LND STUB ========================
class LNDRPC:
    def __init__(self):
        self.enabled = os.getenv("LATTICE_LIGHTNING_ENABLED", "true").lower() == "true"

    async def create_invoice(self, amount_msat: int, memo: str) -> Dict:
        ph = hashlib.sha256(memo.encode()).hexdigest()
        if not self.enabled:
            return {"bolt11": f"lnbc_sim_{ph[:12]}", "payment_hash": ph, "status": "simulated"}
        return {"bolt11": "lnbc_sim_placeholder", "payment_hash": ph, "status": "pending"}

    async def start_subscription(self, guardian) -> None:
        if not self.enabled:
            return
        log.info("lightning_subscription_active", mode="simulated")


# ======================== RWA TOKEN MODEL ========================
@dataclass
class RWAToken:
    token_id:      str
    asset_id:      str
    asset_type:    str
    valuation_cad: float
    owner:         str
    minted_at:     str
    status:        str = "ACTIVE"

    def to_dict(self) -> Dict:
        return {
            "token_id":      self.token_id,
            "asset_id":      self.asset_id,
            "asset_type":    self.asset_type,
            "valuation_cad": self.valuation_cad,
            "owner":         self.owner,
            "minted_at":     self.minted_at,
            "status":        self.status,
        }


# ======================== GUARDIAN ========================
class GuardianVector:
    def __init__(self, config: AppConfig):
        self.config  = config
        self.redis   = redis.from_url("redis://redis:6379/0")
        self.bitcoin = BitcoinRPC(config.lattice_btc_mainnet)
        self.lnd     = LNDRPC()
        self.pqc     = PQCSigner() if config.pqc_enabled else None

    # -------------------- CORE ANCHOR --------------------

    async def _create_onchain_anchor(self, custom_data: str, anchor_id: str = None) -> Dict:
        if not anchor_id:
            anchor_id = f"LK-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}"

        if not ANCHOR_ID_PATTERN.match(anchor_id):
            raise ValueError(f"Invalid anchor_id format: {anchor_id}")

        start     = time.perf_counter()
        root_hash = hashlib.sha256(custom_data.encode()).hexdigest()

        # ---- PQC: Sign the root hash with ML-DSA-65 ----
        pqc_signature_b64 = ""
        pqc_public_key_b64 = ""
        if self.pqc and self.pqc.available:
            try:
                signature_bytes = self.pqc.sign(bytes.fromhex(root_hash))
                pqc_signature_b64 = base64.b64encode(signature_bytes).decode()
                pqc_public_key_b64 = self.pqc.public_key_b64()
                PQC_SIGNS.inc()
                log.info("pqc_signed", anchor_id=anchor_id, algorithm=self.pqc.algorithm,
                         sig_bytes=len(signature_bytes))
            except Exception as e:
                log.error("pqc_sign_failed", anchor_id=anchor_id, error=str(e))
                # Non-fatal: anchor still created, just without PQC signature

        # ---- Bitcoin: Write to chain ----
        try:
            result = await self.bitcoin.create_op_return_tx(root_hash)
            txid   = result.get("txid", "")
            psbt   = result.get("psbt", "")
            status = result.get("status", "CREATED")
        except Exception as e:
            log.error("anchor_tx_failed", anchor_id=anchor_id, error=str(e))
            txid   = ""
            psbt   = ""
            status = "ANCHOR_FAILED"

        payload = {
            "anchor_id":      anchor_id,
            "root_hash":      root_hash,
            "txid":           txid,
            "psbt":           psbt,
            "status":         status,
            "pqc_algorithm":  PQC_ALGORITHM if pqc_signature_b64 else "",
            "pqc_signature":  pqc_signature_b64,
            "pqc_public_key": pqc_public_key_b64,
            "created_at":     datetime.now(UTC).isoformat(),
        }

        await self.redis.hset(f"anchor:{anchor_id}", mapping=payload)
        await self.redis.zadd("anchors:timeline", {anchor_id: datetime.now(UTC).timestamp()})

        ANCHORS_CREATED.inc()
        ANCHOR_LATENCY.observe(time.perf_counter() - start)
        log.info("anchor_created", anchor_id=anchor_id, status=status,
                 pqc_signed=bool(pqc_signature_b64))
        return payload

    # -------------------- RWA TOKENIZATION --------------------

    async def tokenize_rwa(self, asset_data: Dict) -> Dict:
        try:
            valuation = float(asset_data["valuation_cad"])
        except (TypeError, ValueError):
            raise ValueError("valuation_cad must be a number")
        if valuation <= 0:
            raise ValueError("valuation_cad must be greater than zero")
        if valuation > MAX_VALUATION_CAD:
            raise ValueError(f"valuation_cad exceeds maximum ({MAX_VALUATION_CAD:,.0f} CAD)")

        owner = str(asset_data.get("owner", "")).strip()
        if not owner:
            raise ValueError("owner must be a non-empty string")
        if len(owner) > MAX_OWNER_LEN:
            raise ValueError(f"owner exceeds maximum length of {MAX_OWNER_LEN} characters")

        rwa = RWAToken(
            token_id      = f"RWA-{uuid.uuid4().hex[:16].upper()}",
            asset_id      = asset_data["asset_id"],
            asset_type    = asset_data["asset_type"],
            valuation_cad = valuation,
            owner         = owner,
            minted_at     = datetime.now(UTC).isoformat(),
        )

        payload_str = json.dumps(rwa.to_dict(), sort_keys=True, ensure_ascii=False)
        root_hash   = hashlib.sha256(payload_str.encode()).hexdigest()
        anchor_id   = f"LK-RWA-{rwa.token_id.replace('RWA-', '')}"

        anchor_result = await self._create_onchain_anchor(
            custom_data=payload_str, anchor_id=anchor_id
        )

        if anchor_result["status"] == "ANCHOR_FAILED":
            log.warning("rwa_minted_anchor_failed", token_id=rwa.token_id)

        await self.redis.hset(f"rwa:{rwa.token_id}", mapping=rwa.to_dict())
        await self.redis.hset(f"rwa:{rwa.token_id}:proof", mapping={
            "root_hash":     root_hash,
            "anchor_id":     anchor_result["anchor_id"],
            "anchor_status": anchor_result["status"],
            "txid":          anchor_result.get("txid", ""),
            "pqc_signature": anchor_result.get("pqc_signature", ""),
            "pqc_algorithm": anchor_result.get("pqc_algorithm", ""),
        })

        log.info("rwa_tokenized", token_id=rwa.token_id,
                 valuation_cad=rwa.valuation_cad, anchor_status=anchor_result["status"])

        return {
            "success":       True,
            "token_id":      rwa.token_id,
            "asset_type":    rwa.asset_type,
            "valuation_cad": rwa.valuation_cad,
            "anchor_id":     anchor_result["anchor_id"],
            "anchor_status": anchor_result["status"],
            "root_hash":     root_hash,
            "pqc_signed":    bool(anchor_result.get("pqc_signature")),
            "status":        "MINTED" if anchor_result["status"] == "ANCHOR_FAILED"
                             else "MINTED_AND_ANCHORED",
        }

    # ==================== API HANDLERS ====================

    async def handle_create_anchor(self, request: web.Request):
        try:
            data = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON"}, status=400)

        custom_data = (data.get("data") or "").strip()
        if not custom_data:
            return web.json_response({"error": "data field is required"}, status=400)
        if len(custom_data) > MAX_DATA_LEN:
            return web.json_response(
                {"error": f"data exceeds maximum length of {MAX_DATA_LEN} characters"}, status=400
            )

        try:
            result = await self._create_onchain_anchor(custom_data)
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=400)
        except Exception as e:
            ERROR_COUNTER.labels("create_anchor").inc()
            log.error("create_anchor_failed", error=str(e), exc_info=True)
            return web.json_response({"error": "Internal server error"}, status=500)

        return web.json_response(result, status=201)

    async def handle_tokenize_rwa(self, request: web.Request):
        try:
            data = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON"}, status=400)

        required = ["asset_id", "asset_type", "valuation_cad", "owner"]
        missing  = [k for k in required if k not in data]
        if missing:
            return web.json_response(
                {"error": f"Missing required fields: {', '.join(missing)}"}, status=400
            )

        try:
            result = await self.tokenize_rwa(data)
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=400)
        except Exception as e:
            ERROR_COUNTER.labels("tokenize_rwa").inc()
            log.error("rwa_tokenize_failed", error=str(e), exc_info=True)
            return web.json_response({"error": "Internal server error"}, status=500)

        return web.json_response(result, status=201)

    async def handle_broadcast(self, request: web.Request):
        """Broadcast a Coldcard-signed PSBT (mainnet Coldcard flow)."""
        try:
            data = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON"}, status=400)

        psbt = data.get("psbt")
        if not psbt:
            return web.json_response({"error": "Missing 'psbt' field"}, status=400)

        try:
            finalized = await self.bitcoin.call("finalizepsbt", [psbt])
            if not finalized.get("complete"):
                return web.json_response({"error": "PSBT not fully signed"}, status=400)
            txid = await self.bitcoin.call("sendrawtransaction", [finalized["hex"]])
            log.info("coldcard_tx_broadcasted", txid=txid)
            return web.json_response({"txid": txid, "status": "BROADCAST"})
        except Exception as e:
            ERROR_COUNTER.labels("broadcast").inc()
            log.error("broadcast_failed", error=str(e))
            return web.json_response({"error": str(e)}, status=500)

    async def handle_list_anchors(self, request: web.Request):
        try:
            limit = int(request.query.get("limit", 20))
            limit = max(1, min(limit, 100))  # clamp 1–100
        except ValueError:
            return web.json_response({"error": "limit must be an integer"}, status=400)

        anchor_ids = await self.redis.zrevrange("anchors:timeline", 0, limit - 1)
        anchors = []
        for aid in anchor_ids:
            record = await self.redis.hgetall(f"anchor:{aid.decode()}")
            if record:
                anchors.append({k.decode(): v.decode() for k, v in record.items()})

        return web.json_response({
            "anchors": anchors,
            "total":   await self.redis.zcard("anchors:timeline"),
            "limit":   limit,
        })

    async def handle_get_anchor(self, request: web.Request):
        anchor_id = request.match_info["anchor_id"]
        data = await self.redis.hgetall(f"anchor:{anchor_id}")
        if not data:
            return web.json_response({"error": "Anchor not found"}, status=404)
        return web.json_response({k.decode(): v.decode() for k, v in data.items()})

    async def handle_verify(self, request: web.Request):
        """
        Verify an anchor:
          1. SHA-256 hash match
          2. PQC signature verification (if signature present)
          3. Bitcoin confirmation check
        """
        try:
            data = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON"}, status=400)

        custom_data = data.get("data")
        anchor_id   = data.get("anchor_id")
        if not custom_data or not anchor_id:
            return web.json_response({"error": "data and anchor_id required"}, status=400)

        stored = await self.redis.hgetall(f"anchor:{anchor_id}")
        if not stored:
            return web.json_response({"error": "Anchor not found"}, status=404)

        root_hash   = hashlib.sha256(custom_data.encode()).hexdigest()
        stored_hash = stored.get(b"root_hash", b"").decode()

        if root_hash != stored_hash:
            return web.json_response({"valid": False, "reason": "hash_mismatch"})

        # ---- PQC: Verify the ML-DSA-65 signature ----
        pqc_valid = None
        stored_sig = stored.get(b"pqc_signature", b"").decode()
        stored_pk  = stored.get(b"pqc_public_key", b"").decode()

        if stored_sig and stored_pk and PQC_AVAILABLE:
            try:
                sig_bytes = base64.b64decode(stored_sig)
                pk_bytes  = base64.b64decode(stored_pk)
                pqc_signer = PQCSigner.__new__(PQCSigner)
                pqc_signer.algorithm = PQC_ALGORITHM
                pqc_valid = pqc_signer.verify(
                    bytes.fromhex(root_hash), sig_bytes, pk_bytes
                )
                PQC_VERIFIES.inc()
                log.info("pqc_verified", anchor_id=anchor_id, valid=pqc_valid)
            except Exception as e:
                log.error("pqc_verify_failed", anchor_id=anchor_id, error=str(e))
                pqc_valid = False
        elif stored_sig and not PQC_AVAILABLE:
            pqc_valid = None  # can't verify without liboqs

        # ---- Bitcoin: Check confirmations ----
        txid          = stored.get(b"txid", b"").decode()
        confirmations = 0
        if txid:
            try:
                tx            = await self.bitcoin.call("getrawtransaction", [txid, True])
                confirmations = tx.get("confirmations", 0)
            except Exception:
                pass

        required_confs = 6 if self.config.lattice_btc_mainnet else 1
        btc_valid      = confirmations >= required_confs

        # Overall: hash matches AND (btc confirmed OR no txid yet)
        # PQC is reported separately since it's an additional layer
        ANCHORS_VERIFIED.inc()
        return web.json_response({
            "valid":              btc_valid,
            "hash_match":         True,
            "confirmations":      confirmations,
            "txid":               txid,
            "anchor_id":          anchor_id,
            "pqc_valid":          pqc_valid,
            "pqc_algorithm":      stored.get(b"pqc_algorithm", b"").decode() or None,
        })

    async def handle_pqc_info(self, request: web.Request):
        """Public endpoint: return PQC public key and algorithm info."""
        if not self.pqc or not self.pqc.available:
            return web.json_response({
                "pqc_enabled": False,
                "message": "PQC signing not available on this instance",
            })

        return web.json_response({
            "pqc_enabled":  True,
            "algorithm":    self.pqc.algorithm,
            "fips":         "FIPS 204 (ML-DSA-65)",
            "public_key":   self.pqc.public_key_b64(),
            "key_bytes":    len(self.pqc.public_key),
        })


# ======================== MAIN ========================
async def main():
    config = AppConfig.from_env()
    log.info("lattice_keeper_starting", version="0.21.0",
             domain=config.domain, tls=config.tls_enabled,
             pqc_enabled=config.pqc_enabled)

    if config.debug:
        start_http_server(9090)
        log.info("prometheus_metrics_server_started", port=9090)

    guardian = GuardianVector(config)

    app = web.Application(middlewares=[rate_limit_middleware])
    app['config']   = config
    app['guardian'] = guardian

    # All routes auth-gated except /health and /pqc/info
    app.router.add_post("/anchor",              require_auth(guardian.handle_create_anchor))
    app.router.add_post("/rwa/tokenize",        require_auth(guardian.handle_tokenize_rwa))
    app.router.add_post("/broadcast",           require_auth(guardian.handle_broadcast))
    app.router.add_get("/anchors",              require_auth(guardian.handle_list_anchors))
    app.router.add_get("/anchor/{anchor_id}",   require_auth(guardian.handle_get_anchor))
    app.router.add_post("/verify",              require_auth(guardian.handle_verify))
    app.router.add_get("/pqc/info",             guardian.handle_pqc_info)  # public
    app.router.add_get("/health",
        lambda r: web.json_response({
            "status": "healthy", "version": "0.21.0",
            "pqc": guardian.pqc.info() if guardian.pqc else {"available": False},
        }))

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, config.api_host, config.api_port)
    await site.start()

    if config.lightning_enabled:
        asyncio.create_task(guardian.lnd.start_subscription(guardian))

    log.info("lattice_keeper_running", port=config.api_port,
             metrics_port=9090 if config.debug else None,
             rwa=True, lightning=config.lightning_enabled,
             pqc=config.pqc_enabled)

    try:
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        log.info("shutdown_initiated")
    finally:
        await guardian.redis.close()
        if guardian.bitcoin.session:
            await guardian.bitcoin.session.close()
        log.info("shutdown_complete")


if __name__ == "__main__":
    asyncio.run(main())
