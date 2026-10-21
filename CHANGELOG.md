# Changelog

All notable changes to MiniOSINT Platform. Dates in ISO format.

## [v1.0.0] — 2026-10-21 — first public release

### Added
- **IP/Hostname OSINT**: ip-api.com geo/ASN, RDAP registry, AbuseIPDB reputation
  (optional key), Shodan host lookup (optional key)
- **Censys Platform API v3 Lookup APIs** (free tier): `GET /v3/global/asset/host/{ip}`
  and `/v3/global/asset/webproperty/{host}:{port}` — services with TLS cert subjects,
  software stack & WAF detection, cert fingerprints. Works with a free Personal
  Access Token; org ID header optional (free accounts have none)
- **Shodan InternetDB** (keyless): ports, hostnames, tags, CPEs, CVEs per IP
- **Subdomain enumeration**: official DNSDumpster API (`api.dnsdumpster.com`,
  `X-API-Key`) + keyless fallback chain (crt.sh → Cert Spotter → HackerTarget),
  live DNS resolution, NS/MX/TXT records
- **Username OSINT**: 48-platform Sherlock-style existence probing
- **Email OSINT**: Gravatar pivot (verified accounts, photo, name), LeakCheck
  Public API breach check (keyless), optional HIBP (paid) & LeakCheck Pro merging
  with per-source badges, Gmail-aware username derivation, MX records,
  disposable-domain detection, per-source status chips
- **Telegram OSINT**: public channel analytics via Telethon (async),
  one-time `telegram_login.py` interactive setup
- **Link-analysis graph**: force-directed vis-network graph, glowing nodes,
  hover-highlighting, physics freeze toggle, per-type legend, animated zoom-to-fit
- **Search history**: SQLite persistence, IP-vs-Hostname labeling, per-item
  checkboxes, selective bulk delete, clear-all
- **PDF report export** (`/api/report/all|{id}`): only retrieved data (no
  placeholder rows), Censys/InternetDB/subdomain sections, top-connected entities
- **Connection diagnostics**: `GET /api/test` + dashboard "Test connections" panel
- Modern glassmorphism dashboard (Inter/JetBrains Mono, gradient accents)

### Fixed
- **Censys Legacy Search API decommissioned (2026-09-30)**: migrated from dead
  `search.censys.io/api/v2` endpoints to Platform v3 Lookup APIs; `/search` now
  requires a paid org and is no longer used
- **Censys 422 "Invalid organization ID"**: free accounts have no org ID — the
  header is now omitted automatically when absent/invalid, with an explanatory warning
- **LeakCheck "Active plan required"**: free tier moved to a keyless Public API
  (`/api/public?check=`) — used automatically; Pro keys merge only when licensed
- **crt.sh instability/outages**: subdomain module now falls back through Cert Spotter
  and HackerTarget automatically
- **Telethon "Cannot cast coroutine to any kind of Peer"**: sync API was called from
  an anyio worker thread — module rewritten async-native, awaited in the app loop
- **Telegram session path mismatch**: app looked in `app/` while the login script
  saved to project root — paths unified
- **telegram_login.py crash** (`'coroutine' object has no attribute 'first_name'`):
  fully async rewrite
- **`.env` not loading** when uvicorn was started outside the project root:
  dotenv now resolves `.env` by absolute path
- **Graph tooltips showed raw HTML** (`<b>domain</b>`): titles now passed as
  elements, rendered in styled tooltips
- **Domain searches mislabeled "IP"** in history/graph: input is now classified as
  IP vs Hostname everywhere
- **PDF report placeholder rows**: report now includes only data that was retrieved
- Graceful degradation everywhere: every external source failure yields a clear
  status instead of a crash

### Known limitations
- Gravatar/MX lookups can be blocked from some datacenter IPs (works on desktops)
- Instagram/LinkedIn/X username checks may report `unknown` (anti-bot walls)
- DNSDumpster free tier limited to 50 records, 1 req / 2 s
- Telegram: public channels only; user-level tracking is intentionally out of scope
