"""Subdomain enumeration.
PRIMARY:   official dnsdumpster.com API (https://dnsdumpster.com/developer)
           -> DNSDUMPSTER_API_KEY in .env (free key from your account dashboard)
FALLBACKS (keyless, used when no key or API fails):
           1. crt.sh certificate transparency   (often overloaded/down)
           2. Cert Spotter API                  (free, no key, reliable)
           3. HackerTarget hostsearch           (free, no key, rate-limited)
Every discovered name is then live-resolved via DNS (except DNSDumpster
records, which already ship IPs)."""
import os
from concurrent.futures import ThreadPoolExecutor
import socket
import requests

UA = {"User-Agent": "mini-osint-platform/0.1 (+research)"}
MAX_RESOLVE = 400

def _resolve(host):
    try:
        ips = sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
    except Exception:
        ips = []
    return host, ips

def _from_dnsdumpster_api(domain, out):
    key = os.getenv("DNSDUMPSTER_API_KEY")
    if not key:
        return
    try:
        r = requests.get(f"https://api.dnsdumpster.com/domain/{domain}",
                         headers={"X-API-Key": key, **UA}, timeout=25)
        if r.status_code == 200:
            j = r.json()
            out["sources"].append("dnsdumpster-api")
            out["dns_records"] = {
                "ns":  [rec.get("host") for rec in j.get("ns", [])],
                "mx":  [rec.get("host") for rec in j.get("mx", [])],
                "txt": j.get("txt", []),
            }
            for rec in j.get("a", []):
                host = (rec.get("host") or "").lower()
                if not host:
                    continue
                ips = [ip.get("ip") for ip in rec.get("ips", []) if ip.get("ip")]
                out["subdomains"].append({"host": host, "ips": ips, "source": "dnsdumpster"})
        elif r.status_code == 429:
            out["warnings"].append("dnsdumpster API rate limit (1 req / 2s) — wait a moment")
        elif r.status_code in (401, 403):
            try:
                detail = " — " + str(r.json().get("error", r.text[:100]))
            except Exception:
                detail = " — " + r.text[:100]
            out["warnings"].append("dnsdumpster API key rejected (401/403)" + detail
                                   + " | get the key: dnsdumpster.com → log in → Account Dashboard")
        else:
            out["warnings"].append(f"dnsdumpster API HTTP {r.status_code} — falling back to CT sources")
    except Exception as e:
        out["warnings"].append(f"dnsdumpster API error: {e} — falling back to CT sources")

def _from_crtsh(domain, out):
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json",
                         timeout=25, headers=UA)
        names = set()
        for cert in r.json():
            for n in str(cert.get("name_value", "")).split("\n"):
                n = n.strip().lower().removeprefix("*.")
                if n.endswith("." + domain) and n != domain and ".." not in n:
                    names.add(n)
        if names:
            out["sources"].append("crt.sh")
        return names
    except Exception as e:
        out["warnings"].append(f"crt.sh unavailable ({e.__class__.__name__}) — trying Cert Spotter")
        return set()

def _from_certspotter(domain, out):
    try:
        r = requests.get("https://api.certspotter.com/v1/issuances",
                         params={"domain": domain, "include_subdomains": "true",
                                 "expand": "dns_names"},
                         timeout=20, headers=UA)
        names = set()
        if r.status_code == 200:
            for iss in r.json():
                for n in iss.get("dns_names", []):
                    n = n.lower().removeprefix("*.")
                    if n.endswith(domain) and n != domain and ".." not in n:
                        names.add(n)
        if names:
            out["sources"].append("certspotter")
        return names
    except Exception:
        return set()

def _from_hackertarget(domain, out):
    try:
        r = requests.get("https://api.hackertarget.com/hostsearch/",
                         params={"q": domain}, timeout=15, headers=UA)
        names = set()
        if r.status_code == 200 and "error" not in r.text[:60].lower():
            for line in r.text.splitlines():
                host = line.split(",")[0].strip().lower()
                if host.endswith(domain) and host != domain:
                    names.add(host)
        if names:
            out["sources"].append("hackertarget")
        return names
    except Exception:
        return set()

def subdomains(domain, resolve=True, max_workers=40):
    domain = domain.strip().lower().lstrip("*.")
    out = {"domain": domain, "sources": [], "warnings": [],
           "subdomains": [], "dns_records": {}}

    # 1) official API (if key configured)
    _from_dnsdumpster_api(domain, out)

    # 2) passive CT/host sources, merged & de-duplicated
    have = {s["host"] for s in out["subdomains"]}
    names = set()
    names |= _from_crtsh(domain, out)
    names |= _from_certspotter(domain, out)
    names |= _from_hackertarget(domain, out)
    names = {n for n in names if n not in have}

    # 3) resolve anything that doesn't already have IPs
    if resolve and names:
        todo = sorted(names)[:MAX_RESOLVE]
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            resolved = dict(ex.map(_resolve, todo))
        out["subdomains"] += [
            {"host": h, "ips": ips, "source": "ct+dns"} for h, ips in resolved.items()]
    else:
        out["subdomains"] += [{"host": h, "ips": [], "source": "ct"} for h in sorted(names)]

    out["subdomains"].sort(key=lambda s: (not s["ips"], s["host"]))
    out["resolved"] = sum(1 for s in out["subdomains"] if s["ips"])
    out["method"] = (" + ".join(out["sources"])) or "no data sources reachable"
    return out
