<div align="center">

# 🕵️ MiniOSINT Platform

**A lightweight, self-hosted OSINT investigation platform — IP & domain intel, username enumeration, email pivots, and Telegram channel analysis, with automatic link-analysis and PDF reporting.**

FastAPI · Telethon · vis-network · reportlab · zero tracking, your data stays local

</div>

---

## Executive summary

MiniOSINT is a focused alternative to bloated commercial OSINT suites. Instead of fifty
half-working tools, it does **four things well** — and automatically connects the dots
between them. Search an IP and get geolocation, ASN, abuse reputation, Censys host data,
Shodan ports and InternetDB CVEs; search an email and pivot from Gravatar to breach
exposure to 48 platform username checks in two clicks. Every result feeds a live
link-analysis graph, and any investigation exports to a clean PDF with one click.

Built for pentesters, journalists, fraud analysts and CTF players who want OSINT
Industries-style pivots without the enterprise price tag — it runs on a laptop,
stores history in local SQLite, and works with **zero paid API keys** (all four
modules return data keyless; optional keys only add depth).

## Features

### 🌐 IP / Hostname OSINT
- Geolocation, ASN, ISP, reverse DNS, VPN/proxy flags (ip-api.com, keyless)
- Registry data via RDAP (keyless)
- AbuseIPDB reputation score & report counts *(optional key)*
- Shodan host lookup: open ports, hostnames, vulns *(optional key)*
- **Censys Platform API v3 — Lookup APIs** (free tier): full service list with TLS cert subjects for IPs; software stack + WAF detection + cert fingerprints for domains *(free PAT)*
- **Shodan InternetDB** (keyless): ports, hostnames, tags, CPEs, CVEs for any IP
- Accepts both IPs and hostnames — history and graph label them correctly

### 🧬 Subdomain enumeration
- **Official DNSDumpster API** (`api.dnsdumpster.com`) with per-record IPs *(free key)*
- Automatic keyless fallbacks: crt.sh → Cert Spotter → HackerTarget (merged & de-duplicated)
- Live DNS resolution of every discovered name, resolved-first sorting
- NS / MX / TXT records included

### 👤 Username OSINT
- Sherlock-style existence probing across **48 platforms** (GitHub, Reddit, Telegram, Steam, npm, Docker Hub, VK…) — concurrent, public pages only, no login walls

### ✉️ Email OSINT
- **Gravatar pivot**: display name, photo, location, *verified linked accounts* (GitHub, Twitter…) *(keyless)*
- **Breach exposure**: LeakCheck **Public API (free, keyless)** — sources, dates, data categories; optional HIBP (paid) and LeakCheck Pro merge with per-source badges
- Gmail-aware username derivation (`j.oe+tag@gmail.com → joe`, dot-stripping)
- MX records, disposable-domain detection (~40 providers)
- Per-source status chips — "no data" is never ambiguous
- One-click pivot from email → username → 48-platform check

### ✈️ Telegram OSINT
- Public channel/group analytics via Telethon: members, activity, forwarded-content ratio, avg views, linked website
- Async-native implementation + one-time `telegram_login.py` setup

### 🔗 Correlation & reporting
- **Link-analysis graph** (vis-network): glowing force-directed graph auto-built from every search — emails → usernames → accounts → breaches → ASNs → subdomains
- **Search history**: persistent SQLite, per-item checkboxes, selective delete or clear-all
- **PDF report export**: whole investigation or single search — only data that was actually retrieved, with Censys/InternetDB/subdomain sections and top-connected-entities summary
- **🔌 Test connections**: one-click diagnostics for every configured API key

## Quickstart

```bash
git clone https://github.com/<you>/mini-osint.git && cd mini-osint
./run.sh            # creates venv, installs deps → http://127.0.0.1:8000
```

Optional — copy `.env.example` → `.env` and fill in what you have:

| Key | Source | Tier |
|---|---|---|
`CENSYS_API_TOKEN` | platform.censys.io → user icon → API Access | **free** (Lookup APIs) |
`DNSDUMPSTER_API_KEY` | dnsdumpster.com → Account Dashboard | free (50 records) |
`LEAKCHECK_API_KEY` | leakcheck.io | optional (free Public API is keyless) |
`SHODAN_API_KEY` / `ABUSEIPDB_API_KEY` / `HIBP_API_KEY` | respective dashboards | optional paid/free tiers |

Telegram module: set `TELEGRAM_API_ID` / `TELEGRAM_API_HASH` (my.telegram.org), then run `python telegram_login.py` once (interactive).

## Architecture

```
dashboard (static/index.html — glassmorphism, vis-network)
    │ REST /api/lookup/{ip,username,email,telegram} · /api/graph · /api/report/{all,id}
    ▼
FastAPI ──► modules/*  (live API adapters, graceful offline degradation)
    │              ├── ip_osint (ip-api, RDAP, AbuseIPDB, Shodan)
    │              ├── censys   (Platform v3 Lookup APIs)
    │              ├── internetdb (Shodan, keyless)
    │              ├── dnsdumpster (official API + CT fallbacks)
    │              ├── username  (48-site checker)
    │              ├── email_osint (Gravatar, LeakCheck, HIBP)
    │              └── telegram  (Telethon, async)
    ▼
SQLite (history) ──► graph.py (entity/edge derivation) ──► report.py (PDF)
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md). Current release: **v1.0.0**.

## Disclaimer

For authorized security research, journalism, and educational use only. Username checks
probe only public, unauthenticated pages; the Telegram module reads only public channels;
subdomain enumeration uses certificate-transparency logs and official APIs. You are
responsible for complying with applicable law and platform ToS (CFAA, GDPR and
equivalents) — do not use this tool to stalk, harass, or access data you have no right to.

## License

MIT — see LICENSE. No warranty; authors assume no liability for misuse.
