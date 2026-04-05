#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import os
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict

import aiohttp
import redis.asyncio as redis
import structlog
from aiohttp import web
from prometheus_client import Counter, Histogram, start_http_server

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
            # walletcreatefundedpsbt is the correct RPC for Coldcard PSBT flow —
            # unlike fundrawtransaction it returns a real {"psbt": ...} key.
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

        # Regtest / Testnet: raw tx → fund → sign → broadcast
        # fundrawtransaction returns {"hex": ..., "fee": ..., "changepos": ...} — no psbt key.
        # signrawtransactionwithwallet operates on raw hex, which is correct here.
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

    # -------------------- CORE ANCHOR --------------------

    async def _create_onchain_anchor(self, custom_data: str, anchor_id: str = None) -> Dict:
        if not anchor_id:
            anchor_id = f"LK-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}"

        if not ANCHOR_ID_PATTERN.match(anchor_id):
            raise ValueError(f"Invalid anchor_id format: {anchor_id}")

        start     = time.perf_counter()
        root_hash = hashlib.sha256(custom_data.encode()).hexdigest()

        try:
            result = await self.bitcoin.create_op_return_tx(root_hash)
            txid   = result.get("txid", "")
            psbt   = result.get("psbt", "")
            status = result.get("status", "CREATED")
        except Exception as e:
            log.error("anchor_tx_failed", anchor_id=anchor_id, error=str(e))
            txid   = ""
            psbt   = ""
            status = "ANCHOR_FAILED"  # honest — never silently returns CREATED on crash

        payload = {
            "anchor_id":  anchor_id,
            "root_hash":  root_hash,
            "txid":       txid,
            "psbt":       psbt,
            "status":     status,
            "created_at": datetime.now(UTC).isoformat(),
        }

        await self.redis.hset(f"anchor:{anchor_id}", mapping=payload)
        await self.redis.zadd("anchors:timeline", {anchor_id: datetime.now(UTC).timestamp()})

        ANCHORS_CREATED.inc()
        ANCHOR_LATENCY.observe(time.perf_counter() - start)
        log.info("anchor_created", anchor_id=anchor_id, status=status)
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

        txid          = stored.get(b"txid", b"").decode()
        confirmations = 0
        if txid:
            try:
                tx            = await self.bitcoin.call("getrawtransaction", [txid, True])
                confirmations = tx.get("confirmations", 0)
            except Exception:
                pass

        required_confs = 6 if self.config.lattice_btc_mainnet else 1
        valid          = confirmations >= required_confs

        ANCHORS_VERIFIED.inc()
        return web.json_response({
            "valid":         valid,
            "confirmations": confirmations,
            "txid":          txid,
            "anchor_id":     anchor_id,
        })


# ======================== MAIN ========================
async def main():
    config = AppConfig.from_env()
    log.info("lattice_keeper_starting", version="0.20.0",
             domain=config.domain, tls=config.tls_enabled)

    if config.debug:
        start_http_server(9090)
        log.info("prometheus_metrics_server_started", port=9090)

    guardian = GuardianVector(config)

    app = web.Application(middlewares=[rate_limit_middleware])
    app['config']   = config
    app['guardian'] = guardian

    # All routes auth-gated except /health
    app.router.add_post("/anchor",              require_auth(guardian.handle_create_anchor))
    app.router.add_post("/rwa/tokenize",        require_auth(guardian.handle_tokenize_rwa))
    app.router.add_post("/broadcast",           require_auth(guardian.handle_broadcast))
    app.router.add_get("/anchors",              require_auth(guardian.handle_list_anchors))
    app.router.add_get("/anchor/{anchor_id}",   require_auth(guardian.handle_get_anchor))
    app.router.add_post("/verify",              require_auth(guardian.handle_verify))
    app.router.add_get("/health",
        lambda r: web.json_response({"status": "healthy", "version": "0.20.0"}))

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, config.api_host, config.api_port)
    await site.start()

    if config.lightning_enabled:
        asyncio.create_task(guardian.lnd.start_subscription(guardian))

    log.info("lattice_keeper_running", port=config.api_port,
             metrics_port=9090 if config.debug else None,
             rwa=True, lightning=config.lightning_enabled)

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
