# Lattice Keeper API v0.21.0

**Bitcoin-anchored document integrity + RWA tokenization with ML-DSA-65 post-quantum signatures.**

Every anchor is:
1. **SHA-256 hashed** — deterministic fingerprint of your data
2. **PQC-signed with ML-DSA-65** (FIPS 204) — quantum-resistant digital signature
3. **Written to Bitcoin** via OP_RETURN — immutable, timestamped proof

## What's New in v0.21.0

- **ML-DSA-65 (Dilithium3) post-quantum signing** — every anchor is now PQC-signed
- **`/pqc/info` endpoint** — public key + algorithm info
- **Verification includes PQC check** — `/verify` now returns `pqc_valid` alongside Bitcoin confirmations
- **Auto key generation** — keypair created on first run, persisted to `/data/pqc_keys`
- **`requirements.txt`** — proper dependency management with `liboqs-python`

## Stack

| Component | Role |
|-----------|------|
| Python 3.12 + aiohttp | Async API server |
| Bitcoin Core | OP_RETURN anchoring (testnet/mainnet) |
| Redis | Anchor + RWA token storage |
| liboqs (ML-DSA-65) | Post-quantum signatures (FIPS 204) |
| Prometheus | Metrics (optional, DEBUG=true) |
| Coldcard | Mainnet PSBT signing (air-gapped) |

## Quick Start

```bash
cp .env.example .env
# Edit .env — set LATTICE_API_KEY at minimum
docker compose up --build
```

## API Endpoints

All endpoints except `/health` and `/pqc/info` require authentication via `X-API-Key` header or `Authorization: Bearer <key>`.

### `POST /anchor`
Create a new anchor. Data is hashed, PQC-signed, and written to Bitcoin.

```bash
curl -X POST http://localhost:8765/anchor \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"data": "contract-v2-final.pdf SHA256:abc123..."}'
```

**Response:**
```json
{
  "anchor_id": "LK-20260406-120000",
  "root_hash": "a1b2c3...",
  "txid": "def456...",
  "status": "BROADCAST",
  "pqc_algorithm": "Dilithium3",
  "pqc_signature": "base64...",
  "pqc_public_key": "base64..."
}
```

### `POST /verify`
Verify an anchor — checks hash match, PQC signature, and Bitcoin confirmations.

```bash
curl -X POST http://localhost:8765/verify \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"data": "contract-v2-final.pdf SHA256:abc123...", "anchor_id": "LK-20260406-120000"}'
```

**Response:**
```json
{
  "valid": true,
  "hash_match": true,
  "confirmations": 6,
  "pqc_valid": true,
  "pqc_algorithm": "Dilithium3"
}
```

### `POST /rwa/tokenize`
Tokenize a real-world asset — mints an RWA token, anchors it on-chain with PQC signature.

```bash
curl -X POST http://localhost:8765/rwa/tokenize \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"asset_id": "PROP-001", "asset_type": "real_estate", "valuation_cad": 500000, "owner": "Jay Vallea"}'
```

### `POST /broadcast`
Broadcast a Coldcard-signed PSBT (mainnet flow).

```bash
curl -X POST http://localhost:8765/broadcast \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"psbt": "cHNidP8..."}'
```

### `GET /anchors?limit=20`
List recent anchors (limit 1–100).

### `GET /anchor/{anchor_id}`
Get a specific anchor by ID.

### `GET /pqc/info` *(public — no auth required)*
Returns PQC public key and algorithm info.

```json
{
  "pqc_enabled": true,
  "algorithm": "Dilithium3",
  "fips": "FIPS 204 (ML-DSA-65)",
  "public_key": "base64...",
  "key_bytes": 1952
}
```

### `GET /health` *(public — no auth required)*
Health check with PQC status.

## PQC Key Management

On first startup, Lattice Keeper generates an ML-DSA-65 keypair and saves it to `/data/pqc_keys/`. The keypair persists across restarts via Docker volume.

**Options:**
- **Auto-generate** (default): Keys created on first run
- **File-based**: Mount your own keys at `PQC_KEY_PATH`
- **Env-based**: Set `PQC_SECRET_KEY` and `PQC_PUBLIC_KEY` (base64-encoded)

**Security:** In production, move the secret key to an HSM or air-gapped signer. The public key can be freely distributed for verification.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LATTICE_API_KEY` | *(required)* | API authentication key |
| `LATTICE_BTC_MAINNET` | `false` | Use mainnet (Coldcard PSBT flow) |
| `LATTICE_LIGHTNING_ENABLED` | `false` | Enable Lightning stub |
| `BITCOIN_RPC_USER` | `lattice` | Bitcoin Core RPC username |
| `BITCOIN_RPC_PASS` | `changeme` | Bitcoin Core RPC password |
| `DOMAIN` | `lattice.example.com` | Service domain |
| `RATE_LIMIT_RPS` | `20` | Rate limit (requests/sec) |
| `PQC_ENABLED` | `true` | Enable ML-DSA-65 signing |
| `PQC_KEY_PATH` | `/data/pqc_keys` | Path for PQC keypair storage |
| `DEBUG` | `false` | Enable Prometheus metrics on :9090 |

## License

MIT
