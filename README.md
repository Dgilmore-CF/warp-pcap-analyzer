# WARP & PCAP Analyzer v2

Professional network capture analysis with a Wireshark-style interface, multi-model AI diagnostics, and Cloudflare Access SSO — deployed as a single Cloudflare Worker.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Deployment](#deployment)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Cloudflare Access SSO](#cloudflare-access-sso)
- [Export Formats](#export-formats)
- [Performance & Limits](#performance--limits)
- [Troubleshooting](#troubleshooting)

---

## Features

### Wireshark-Style Packet Browser

- **Three-pane layout**: Packet list, protocol detail tree, hex dump
- **Protocol coloring**: TCP (blue), UDP (cyan), DNS (sky), TLS (purple), HTTP (green), ICMP (red), ARP (orange), WARP (CF orange)
- **Display filter bar**: Supports `tcp`, `dns`, `ip.addr==192.168.1.1`, `port 443`, `tls.sni contains example.com`
- **Protocol detail tree**: Expandable per-layer field inspection (Ethernet, IP, TCP options, DNS records, TLS handshake, HTTP headers)
- **Hex dump viewer**: Offset + hex bytes + ASCII per 16-byte line
- **Dark theme**: Professional dark UI designed for extended analysis sessions

### Deep PCAP Protocol Decoder

Full binary packet parsing — no external libraries, no server-side tcpdump:

| Layer | Protocols |
|-------|-----------|
| **Data Link** | Ethernet II, 802.1Q VLAN |
| **Network** | IPv4 (full header, flags, fragmentation), IPv6, ARP |
| **Transport** | TCP (flags, options, MSS, window scale, timestamps, SACK), UDP, ICMP/ICMPv6 |
| **Application** | DNS (queries, answers, all record types), TLS (version, SNI, ALPN, cipher suites), HTTP/1.1 (methods, headers, CF-RAY), DHCP (message types, options), SSH (banner detection) |

Additional analysis:
- **TCP flow reconstruction** with state tracking (SYN → ESTABLISHED → FIN/RST)
- **Conversation tracking** with per-flow byte/packet counts and duration
- **Protocol hierarchy** statistics
- **Anomaly detection**: TCP resets, zero windows, low TTL, IP fragmentation, DNS errors, TLS alerts

### Multi-Model AI Analysis

Three Workers AI models, automatically selected based on task:

| Model | Context | Use Case |
|-------|---------|----------|
| **Llama 4 Scout 17B** | 131K tokens | Deep PCAP analysis, WARP diagnostics (large log files) |
| **Llama 3.3 70B Fast** | 24K tokens | Quick security assessments on smaller captures |
| **DeepSeek R1 32B** | 80K tokens | Complex root-cause analysis |

AI produces structured findings with:
- Severity classification (Critical / Warning / Info)
- Security risk assessment
- Performance assessment
- Root cause analysis with evidence (packet numbers, IPs, log lines)
- Numbered remediation steps
- Event timeline with log references

### Statistics Dashboard

- Protocol distribution with percentage bars
- Top talkers by bytes
- Port distribution
- Packet size histogram
- DNS query/response table
- TLS connection inventory (SNI, version, ALPN)
- Warning summary

### Session Persistence

Analysis results stored in Workers KV for 7 days:
- Paginated packet storage (500 packets per KV key)
- Per-user session ownership via Cloudflare Access identity
- Session list on the upload screen — click to reopen previous analyses
- Up to 50 sessions per user

### Cloudflare Access SSO

- JWT verification using the team's JWKS endpoint
- User identity extraction for session ownership
- Automatic dev-mode bypass when Access is not configured
- Supports both `Cf-Access-Jwt-Assertion` header and `CF_Authorization` cookie

### Multi-Format Export

| Format | Description |
|--------|-------------|
| **JSON** | Full analysis data (packets, flows, stats, AI results) |
| **CSV** | Packet table (No., Time, Source, Destination, Protocol, Length, Info, Ports, Flags) |
| **HAR** | HTTP Archive format — HTTP requests/responses + TLS SNI entries |
| **HTML** | Printable report with statistics, issues, recommendations, packet summary |

### File Support

| Format | Support |
|--------|---------|
| WARP diag ZIP | Full extraction and parsing (40+ file types) |
| PCAP (legacy) | Full binary decode with protocol analysis |
| PCAPNG | Full binary decode (Enhanced Packet Blocks, Interface Description) |
| Individual logs | Text parsing and categorisation (.log, .txt, .json) |

---

## Architecture

```
                  Browser                     cURL / API Client
                    │                               │
                    ▼                               ▼
          ┌─────────────────────────────────────────────┐
          │          Cloudflare Access (SSO)             │
          │   JWT verification, user identity extraction │
          └─────────────────┬───────────────────────────┘
                            ▼
          ┌─────────────────────────────────────────────┐
          │         warp-pcap-analyzer Worker            │
          │                                             │
          │  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
          │  │  Router   │→│ PCAP     │→│ AI Engine │  │
          │  │  + Auth   │  │ Decoder  │  │ (3 models)│  │
          │  └──────────┘  └──────────┘  └──────────┘  │
          │        │              │             │        │
          │        ▼              ▼             ▼        │
          │  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
          │  │ Session   │  │ Export   │  │  WARP    │  │
          │  │ Manager   │  │ Engine   │  │ Parsers  │  │
          │  └──────────┘  └──────────┘  └──────────┘  │
          └─────────┬───────────────────────────────────┘
                    │
          ┌─────────┴─────────┐
          │   Workers KV      │     Workers AI
          │   (Sessions)      │   (Llama 4 / 3.3 / DeepSeek)
          └───────────────────┘
```

### Processing Pipeline

```
Upload → ZIP Extract (if .zip) → File Categorisation
    │                                    │
    ├── PCAP/PCAPNG files ──→ Binary Decode → Protocol Analysis → Flow Tracking → Statistics
    │                                                                                │
    ├── Log files ──────────→ Text Parse → Priority Sort → Key Info Extraction       │
    │                                                                                │
    └── Store in KV Session ←────────────────────────────────────────────────────────┘
                │
                ├── AI: PCAP Analysis (security, performance, protocol issues)
                ├── AI: WARP Diagnostics (connectivity, DNS, config, certs)
                └── Return results → Render in Wireshark-style UI
```

---

## Quick Start

### Prerequisites

- **Cloudflare Account** with Workers and Workers AI enabled
- **Node.js** 20+ and npm
- **Wrangler** 4.x (installed automatically via npm)

### Local Development

```bash
# Clone the repository
git clone https://github.com/Dgilmore-CF/warp-pcap-analyzer.git
cd warp-pcap-analyzer

# Install dependencies
npm install

# Start local dev server
npm run dev
```

Open **http://localhost:8787** in your browser. In local dev mode, Cloudflare Access auth is bypassed automatically.

### Test with cURL

```bash
# API info
curl http://localhost:8787

# Upload a PCAP file
curl -X POST http://localhost:8787/api/analyze \
  -F "file=@capture.pcap"

# Upload a WARP diagnostic bundle
curl -X POST http://localhost:8787/api/analyze \
  -F "file=@warp-debugging-info.zip"
```

---

## Deployment

### GitHub Actions (Automatic)

Every push to `main` triggers deployment via `.github/workflows/deploy.yml`.

**Required GitHub Secrets** (Settings > Secrets and variables > Actions):

| Secret | Value |
|--------|-------|
| `CLOUDFLARE_API_TOKEN` | API token with "Edit Cloudflare Workers" permissions |
| `CLOUDFLARE_ACCOUNT_ID` | Your Cloudflare Account ID (32-char hex) |

```bash
git push origin main
# → GitHub Actions installs deps → deploys to Cloudflare Workers
```

### Manual Deployment

```bash
npx wrangler login
npm run deploy
```

### Custom Domain

The worker is configured to serve on `warp-analyzer.dtg-lab.net`. To change this, edit `wrangler.jsonc`:

```jsonc
"routes": [
  {
    "pattern": "your-domain.example.com",
    "custom_domain": true
  }
]
```

---

## Usage

### Web Interface

1. Navigate to your worker URL in a browser
2. Authenticate via Cloudflare Access SSO (if configured)
3. Drop files onto the upload area (or click to browse)
4. View results across six tabs:

| Tab | Content |
|-----|---------|
| **Packets** | Wireshark-style three-pane browser with filter bar |
| **Conversations** | TCP/UDP flow table sorted by bytes |
| **Statistics** | Protocol distribution, top talkers, DNS, TLS, packet sizes |
| **AI Analysis** | Combined PCAP + WARP findings with evidence and remediation |
| **Timeline** | Chronological event visualization with severity markers |
| **WARP Diagnostics** | File inventory and configuration review (when ZIP uploaded) |

### Display Filters

The packet filter bar supports these patterns:

```
tcp                          # Show only TCP packets
dns                          # Show only DNS packets
udp                          # Show only UDP packets
ip.addr==192.168.1.1         # Source or destination IP
ip.dst==10.0.0.1             # Destination IP only
port 443                     # Source or destination port
tcp.port==80                 # TCP port
tls.sni contains cloudflare  # TLS Server Name Indication
http                         # Show HTTP packets
arp                          # Show ARP packets
rst                          # Show packets with RST flag
```

### Previous Sessions

The upload screen shows your saved sessions (stored in KV for 7 days). Click any session to reload its full analysis without re-uploading.

### Exporting

Use the **Export** dropdown in the header bar to download analysis results:

- **JSON**: Machine-readable full analysis data
- **CSV**: Spreadsheet-compatible packet table
- **HAR**: Import into browser DevTools or Charles Proxy
- **HTML**: Printable report for sharing with stakeholders

---

## API Reference

All `/api/*` endpoints require Cloudflare Access authentication (JWT in header or cookie).

### `POST /api/analyze`

Upload files for analysis.

**Request**: `multipart/form-data` with one or more files.

```bash
curl -X POST https://warp-analyzer.dtg-lab.net/api/analyze \
  -H "Cf-Access-Jwt-Assertion: $JWT" \
  -F "file=@capture.pcap"
```

**Response**: JSON with session ID, decoded packets (first page), flows, statistics, and AI analysis.

### `GET /api/sessions`

List the authenticated user's saved sessions.

### `GET /api/sessions/:id`

Get session metadata (file info, packet count, timestamps).

### `GET /api/sessions/:id/packets?page=0`

Get paginated packet data (500 packets per page).

| Parameter | Default | Description |
|-----------|---------|-------------|
| `page` | `0` | Zero-based page number |

### `GET /api/sessions/:id/flows`

Get TCP/UDP conversation data.

### `GET /api/sessions/:id/stats`

Get protocol statistics, top talkers, DNS queries, TLS connections.

### `GET /api/sessions/:id/ai`

Get AI analysis results (PCAP security assessment + WARP diagnostics).

### `GET /api/sessions/:id/warp`

Get WARP diagnostic file data and configuration review.

### `GET /api/sessions/:id/export/:format`

Export session data. Format: `json`, `csv`, `har`, or `html`.

Returns file download with appropriate `Content-Disposition` header.

### `DELETE /api/sessions/:id`

Delete a session and all associated KV data.

### `GET /`

Returns the web UI (HTML) for browser requests, or API info (JSON) for programmatic requests.

---

## Configuration

### `wrangler.jsonc`

Committed configuration — no secrets:

```jsonc
{
  "name": "warp-pcap-analyzer",
  "main": "src/index.js",
  "compatibility_date": "2025-01-01",
  "ai": { "binding": "AI" },
  "kv_namespaces": [
    { "binding": "SESSIONS", "id": "your-kv-namespace-id" }
  ],
  "routes": [
    { "pattern": "your-domain.example.com", "custom_domain": true }
  ],
  "placement": { "mode": "smart" }
}
```

### Secrets (encrypted, not in source)

Sensitive configuration is stored as Worker secrets, set via `wrangler secret put`:

```bash
npx wrangler secret put CF_ACCESS_TEAM_DOMAIN   # e.g. yourteam.cloudflareaccess.com
npx wrangler secret put CF_ACCESS_AUD           # Application AUD tag from Access
```

| Secret | Required | Description |
|--------|----------|-------------|
| `CF_ACCESS_TEAM_DOMAIN` | No | Cloudflare Access team domain. Missing = auth bypassed (dev mode). |
| `CF_ACCESS_AUD` | No | Access Application Audience tag. Missing = auth bypassed (dev mode). |

List existing secrets:

```bash
npx wrangler secret list
```

### Workers KV

Create the namespace:

```bash
npx wrangler kv namespace create SESSIONS
```

Paste the returned ID into `wrangler.jsonc`. **The KV namespace ID is a public identifier, not a credential** — it's safe to commit.

### Smart Placement

Enabled by default. Routes requests to the nearest Cloudflare data centre with GPU capacity for AI inference, reducing latency for Workers AI calls.

---

## Project Structure

```
warp-pcap-analyzer/
├── .github/
│   └── workflows/
│       └── deploy.yml             # GitHub Actions → Cloudflare Workers
├── src/
│   ├── index.js                   # Main Worker: routing, auth, analysis pipeline
│   ├── pcap-decoder.js            # Full PCAP/PCAPNG binary decoder (1,400+ lines)
│   ├── ai-analyzer.js             # Multi-model AI engine with structured prompts
│   ├── parsers.js                 # ZIP extraction, text parsing, WARP file categorisation
│   ├── auth.js                    # Cloudflare Access JWT verification (Web Crypto)
│   ├── session.js                 # KV-based session persistence (chunked storage)
│   ├── export.js                  # Multi-format export (JSON, CSV, HAR, HTML)
│   └── ui.js                      # Embedded Wireshark-style dark-theme SPA
├── test/
│   └── index.spec.js              # Vitest unit tests (Workers pool)
├── wrangler.jsonc                 # Worker configuration (AI, KV, Access, routes)
├── package.json
└── vitest.config.js
```

### Key Modules

**`pcap-decoder.js`** (1,415 lines) — The core decoder. Reads PCAP and PCAPNG binary formats, decodes every packet through Layer 2–7, builds flow tables and statistics. No external dependencies.

**`ai-analyzer.js`** — Routes analysis to the best Workers AI model based on task type and input size. Builds optimised context from decoded packets, flows, and statistics. Includes evidence enrichment that maps AI findings back to specific log lines and packet numbers.

**`session.js`** — Stores decoded packets in KV chunks of 500. Manages per-user session lists with 7-day TTL. Supports paginated retrieval for large captures.

**`auth.js`** — Fetches JWKS from the Access team domain, verifies RS256 JWT signatures using the Web Crypto API, extracts user email for session scoping. Caches JWKS for 10 minutes.

**`ui.js`** — Complete single-page application embedded as an HTML string. Three-pane Wireshark layout, virtual packet list, expandable protocol tree, hex dump, statistics charts, AI analysis cards, timeline, session management, and export controls.

---

## Cloudflare Access SSO

### Setup

1. Go to **Cloudflare Zero Trust Dashboard** > **Access** > **Applications**
2. Create a **Self-hosted Application** for your worker domain
3. Configure your Identity Provider (Okta, Azure AD, Google, GitHub, etc.)
4. Set access policies (e.g., allow your team's email domain)
5. Copy the **Application Audience (AUD)** tag from the application settings
6. Store the values as Worker secrets (encrypted, not in source):
   ```bash
   npx wrangler secret put CF_ACCESS_TEAM_DOMAIN
   # Enter: your-team.cloudflareaccess.com

   npx wrangler secret put CF_ACCESS_AUD
   # Enter: your-aud-tag
   ```
7. No redeploy needed — secrets take effect immediately.

### How It Works

1. Browser request hits Cloudflare's edge
2. Access intercepts and redirects to SSO login (if not authenticated)
3. After authentication, Access injects `Cf-Access-Jwt-Assertion` header
4. The Worker verifies the JWT signature against the team's JWKS
5. User email is extracted and used for session ownership
6. API returns `401` with error message if verification fails

### Dev Mode

When the `CF_ACCESS_TEAM_DOMAIN` and `CF_ACCESS_AUD` secrets are not set, the Worker skips JWT verification and uses a placeholder `dev@localhost` identity. This is the default for local development with `npm run dev`.

---

## Export Formats

### JSON

Complete analysis data suitable for programmatic consumption:

```json
{
  "exportedAt": "2025-01-01T00:00:00Z",
  "session": { "id": "...", "fileName": "capture.pcap" },
  "statistics": { "totalPackets": 1523, "protocols": { "TCP": 1200 } },
  "flows": { "192.168.1.5:443-10.0.0.1:55672-TCP": { ... } },
  "aiAnalysis": { "health_status": "Degraded", "issues": [...] },
  "packets": [{ "number": 1, "protocol": "DNS", "info": "..." }]
}
```

### CSV

One row per packet, importable into Excel, Google Sheets, or pandas:

```
No.,Time,Source,Destination,Protocol,Length,Info,Src Port,Dst Port,TCP Flags,Flow ID,Warnings
1,0.000000,192.168.1.5,1.1.1.1,DNS,75,DNS Query A example.com,54321,53,,192.168.1.5:54321-1.1.1.1:53-UDP,
```

### HAR

HTTP Archive format containing HTTP requests/responses and TLS ClientHello entries (with SNI). Importable into browser DevTools, Charles Proxy, or Fiddler.

### HTML

Printable report with:
- Health status badge
- Capture statistics (packets, bytes, duration, protocols)
- Protocol distribution table
- Detected issues with severity, root cause, and remediation
- Top conversations
- First 100 packets in tabular format

---

## Performance & Limits

### Typical Analysis Metrics

| Metric | Small Capture (<1K pkts) | Medium (1K–10K pkts) | Large (10K+ pkts) |
|--------|--------------------------|----------------------|--------------------|
| PCAP decode | 50–200ms | 200ms–1s | 1–5s |
| AI analysis | 2–5s | 3–8s | 5–15s |
| **Total time** | **3–6s** | **5–10s** | **8–20s** |

### Workers Limits

| Resource | Limit |
|----------|-------|
| Request size | 100 MB |
| Worker memory | 128 MB |
| CPU time (paid) | 30 seconds |
| KV value size | 25 MB per key |
| KV write latency | Eventually consistent (up to 60s globally) |

### Large File Handling

Files over 5 MB trigger a warning banner in the UI. The decoder limits analysis to 10,000 packets by default (50,000 for large files). The full packet count is reported and remaining packets are noted but not decoded, to stay within Worker CPU limits.

### Workers AI Pricing

| Plan | Allowance |
|------|-----------|
| **Free** | 10,000 neurons/day (~14 full analyses) |
| **Paid** | $0.011 per 1,000 neurons |

Typical analysis: 50K input tokens + 3K output tokens = ~800K neurons.

---

## Troubleshooting

### Deployment

**"CLOUDFLARE_API_TOKEN not set"** in GitHub Actions
- Go to repo Settings > Secrets and variables > Actions
- Add `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`

**"KV namespace not found"**
- Run `npx wrangler kv namespace create SESSIONS`
- Update the `id` in `wrangler.jsonc`

### Runtime

**"Authentication required" (401)**
- Cloudflare Access is enabled but no valid JWT was provided
- Open the URL in a browser to trigger SSO login
- For API access, include the `Cf-Access-Jwt-Assertion` header

**"AI binding not configured" (500)**
- Ensure `wrangler.jsonc` has `"ai": { "binding": "AI" }`
- Redeploy with `npm run deploy`

**"Session storage not configured" (500)**
- KV namespace not bound. Run `npx wrangler kv namespace create SESSIONS` and update `wrangler.jsonc`

**AI analysis returns fallback results**
- Workers AI may be temporarily unavailable or rate-limited
- The fallback uses rule-based pattern matching (TCP resets, DNS errors, zero windows)
- Results are marked with a "Rule-based fallback" note

**Large PCAP files time out**
- Worker CPU limit is 30s on paid plans
- Reduce capture size or split into smaller files
- The decoder automatically limits packet count for large files

### Local Development

**"Cannot find module" errors**
- Run `npm install` to install dependencies
- Ensure you're using Node.js 20+

**Auth issues in local dev**
- Don't set the `CF_ACCESS_TEAM_DOMAIN` / `CF_ACCESS_AUD` secrets when running locally
- Local dev uses `wrangler dev` which doesn't access production secrets
- Auth is automatically bypassed in dev mode

---

## Security Model

What lives where:

| Value | Location | Sensitive? |
|-------|----------|------------|
| `CLOUDFLARE_API_TOKEN` | GitHub repository secret | **Yes — credential** |
| `CLOUDFLARE_ACCOUNT_ID` | GitHub repository secret | Semi-sensitive |
| `CF_ACCESS_TEAM_DOMAIN` | Worker secret (encrypted) | Semi-sensitive |
| `CF_ACCESS_AUD` | Worker secret (encrypted) | Semi-sensitive |
| KV namespace ID | `wrangler.jsonc` (public) | **No — identifier only** |
| Custom domain route | `wrangler.jsonc` (public) | No — DNS public |

Nothing in the repository is a credential. Deployment credentials are scoped
GitHub secrets. Runtime configuration is stored as encrypted Worker secrets.
Public identifiers (KV IDs, routes, domains) appear in `wrangler.jsonc` but
cannot be used without the corresponding credentials.

---

## License

MIT

---

Built with Cloudflare Workers AI, Workers KV, and Cloudflare Access.
