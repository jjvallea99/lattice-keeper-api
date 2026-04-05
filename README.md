# Lattice Keeper v0.20.0

**Bitcoin-anchored Real-World Asset (RWA) tokenization and tamper-evident notarization service.**

Lattice Keeper lets you mint cryptographic proof that a real-world asset — property, contracts, evidence, documents — existed in a specific state at a specific time, with that proof permanently anchored to the Bitcoin blockchain via OP_RETURN.

Designed for CAD-denominated assets, Lightning-ready pay-per-anchor monetization, and post-quantum signing (ML-DSA-65, roadmap). Deployable in under 5 minutes.

---

## What It Does

| Feature | Description |
|---|---|
| **RWA Tokenization** | Mint an immutable token representing any real-world asset with CAD valuation |
| **Bitcoin Anchoring** | SHA-256 hash of asset data written to Bitcoin via OP_RETURN — permanent, unforgeable |
| **Tamper-Evident Proof** | Anyone can verify an asset record was not modified after anchoring |
| **Coldcard / PSBT** | Mainnet mode prepares a PSBT for offline hardware wallet signing — no hot keys |
| **Lightning-Ready** | Invoice flow for pay-per-anchor monetization (stub in dev, real LND in prod) |
| **Testnet / Mainnet** | Single env flag switches between safe testing and live Bitcoin |
| **API Key Auth** | All endpoints protected; health check public |
| **Rate Limiting** | Per-key Redis-backed rate limiting (configurable RPS) |
| **Prometheus Metrics** | Anchor counts, latency histograms, error rates (port 9090, DEBUG mode) |

---

## Use Cases

- **Legal evidence preservation** — Anchor documents, communications, or records to Bitcoin. Prove they existed at a specific time and weren't altered.
- **Real estate & asset registry** — Tokenize property valuations with on-chain proof of record.
- **Journalism & whistleblowing** — Timestamped, tamper-evident proof of information.
- **AI output integrity** — Anchor AI-generated content to prove what was said and when.
- **Compliance logging** — Immutable audit trails for regulated industries.

---

## Quick Start

### Prerequisites
- Docker + Docker Compose
- ~500MB disk (Bitcoin testnet headers: additional 1–2GB over time)

### Run in 5 Minutes

```bash
# 1. Clone the repo
git clone https://github.com/yourname/lattice-keeper.git
cd lattice-keeper

# 2. Configure environment
cp .env.example .env
nano .env   # Set LATTICE_API_KEY=your_strong_random_key
            # Change BITCOIN_RPC_PASS from the default

# 3. Start all services
docker compose up -d

# 4. Check health
curl http://localhost:8765/health
```

> **Note:** Bitcoin Core takes 5–30 minutes on first launch to sync testnet headers. All other services start immediately.

---

## API Reference

All endpoints except `/health` require authentication via header:
```
X-API-Key: your_api_key
```
or
```
Authorization: Bearer your_api_key
```

---

### `POST /anchor`
Anchor arbitrary data to Bitcoin. Returns proof with txid once broadcast.

**Request:**
```json
{
  "data": "any string — document hash, evidence description, contract text"
}
```

**Response:**
```json
{
  "anchor_id": "LK-20260405-133700",
  "root_hash": "a3f1...",
  "txid": "b7c2...",
  "status": "BROADCAST",
  "created_at": "2026-04-05T13:37:00+00:00"
}
```

---

### `POST /rwa/tokenize`
Mint a tokenized record for a real-world asset with Bitcoin-anchored proof.

**Request:**
```json
{
  "asset_id": "PROP-2026-001",
  "asset_type": "real_estate",
  "valuation_cad": 450000,
  "owner": "Jane Smith"
}
```

**Response:**
```json
{
  "success": true,
  "token_id": "RWA-A1B2C3D4E5F60001",
  "asset_type": "real_estate",
  "valuation_cad": 450000,
  "anchor_id": "LK-RWA-A1B2C3D4E5F60001",
  "root_hash": "d4e5...",
  "status": "MINTED_AND_ANCHORED"
}
```

---

### `POST /broadcast`
Broadcast a PSBT that was signed offline (e.g., Coldcard). Mainnet only.

**Request:**
```json
{
  "psbt": "cHNidP8BAH..."
}
```

**Response:**
```json
{
  "txid": "b7c2...",
  "status": "BROADCAST"
}
```

---

### `POST /verify`
Verify that a data string matches a stored anchor and check on-chain confirmations.

**Request:**
```json
{
  "data": "the original string you anchored",
  "anchor_id": "LK-20260405-133700"
}
```

**Response:**
```json
{
  "valid": true,
  "confirmations": 6,
  "txid": "b7c2...",
  "anchor_id": "LK-20260405-133700"
}
```

---

### `GET /anchors?limit=20`
List recent anchors. `limit` accepts 1–100 (default 50).

---

### `GET /anchor/{anchor_id}`
Fetch a single anchor record by ID.

---

### `GET /health`
Public. Returns service version and status.

```json
{"status": "healthy", "version": "0.20.0"}
```

---

## Configuration

All configuration is via environment variables. Copy `.env.example` to `.env`.

| Variable | Default | Description |
|---|---|---|
| `LATTICE_API_KEY` | *(required)* | API authentication key |
| `LATTICE_BTC_MAINNET` | `false` | `true` = mainnet (real Bitcoin), `false` = testnet |
| `BITCOIN_RPC_USER` | `lattice` | Bitcoin Core RPC username |
| `BITCOIN_RPC_PASS` | `changeme` | Bitcoin Core RPC password — **change this** |
| `LATTICE_LIGHTNING_ENABLED` | `false` | Enable real Lightning invoices |
| `DOMAIN` | `lattice.example.com` | Your public domain (used in logs) |
| `RATE_LIMIT_RPS` | `20` | Max requests per second per API key |
| `DEBUG` | `false` | Verbose logging + Prometheus metrics on port 9090 |

---

## Architecture

```
┌─────────────────────────────────────┐
│         Lattice Keeper API          │
│         (aiohttp, port 8765)        │
└────────────┬──────────┬─────────────┘
             │          │
    ┌─────────▼──┐  ┌───▼──────────┐
    │   Redis    │  │ Bitcoin Core  │
    │  (state)   │  │  (testnet/    │
    └────────────┘  │   mainnet)    │
                    └───────────────┘
```

- **Redis** stores anchor metadata, RWA tokens, and timeline index
- **Bitcoin Core** broadcasts OP_RETURN transactions with SHA-256 hashes
- **Testnet**: auto-signs transactions in software
- **Mainnet**: produces PSBTs for Coldcard hardware signing — no hot keys ever touch mainnet funds
- All data hashed before anchoring — raw content never hits the chain

---

## Status Meanings

| Status | Meaning |
|---|---|
| `BROADCAST` | Transaction submitted to Bitcoin network |
| `PENDING_COLDCARD` | Mainnet mode — PSBT ready for hardware wallet signing |
| `ANCHOR_FAILED` | Bitcoin RPC error — anchor not on-chain, check logs |
| `MINTED_AND_ANCHORED` | RWA token created and anchor broadcast |

---

## Security Notes

- Never commit `.env` to version control — it's in `.gitignore`
- Change `BITCOIN_RPC_PASS` from the default before any deployment
- On mainnet, transactions cost real Bitcoin — test thoroughly on testnet first
- API key is transmitted in headers — always run behind HTTPS in production (nginx + certbot recommended)
- Rate limiting fails open on Redis errors — acceptable for availability, review if you need strict limits

---

## Roadmap

- [ ] ML-DSA-65 (post-quantum) signing of RWA tokens
- [ ] Real LND gRPC integration for Lightning payments
- [ ] Webhook notifications on anchor confirmation
- [ ] Multi-owner / quorum tokenization
- [ ] `/invoice` endpoint — Lightning pay-per-anchor flow

---

## License

MIT

---

*Built by Jay Vallea. Self-taught. Bitcoin-native. Post-quantum ready.*
