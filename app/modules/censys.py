"""Censys Platform API v3 — Lookup APIs (compatible with the FREE tier).
Legacy Search API was decommissioned 2026-09-30; the /search endpoint now
requires a paid organization ID ("Free users can only access this endpoint
through the Platform UI"). Free accounts CAN use the Lookup APIs:
  Host Lookup:       GET /v3/global/asset/host/{ip}
  Web Property:      GET /v3/global/asset/webproperty/{host}:{port}
Auth: CENSYS_API_TOKEN only (Personal Access Token from platform.censys.io ->
user icon -> API Access -> Create New Token). CENSYS_ORG_ID optional (paid)."""
import os
import requests

UA = {"User-Agent": "mini-osint-platform/0.4 (+research)"}
HOST_URL = "https://api.platform.censys.io/v3/global/asset/host/{}"
WEB_URL = "https://api.platform.censys.io/v3/global/asset/webproperty/{}"

def is_ip(target):
    import ipaddress
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False

def _creds():
    token = os.getenv("CENSYS_API_TOKEN") or os.getenv("CENSYS_PLATFORM_TOKEN")
    org = os.getenv("CENSYS_ORG_ID") or os.getenv("CENSYS_PLATFORM_ORGID") or ""
    return (token or "").strip(), org.strip()

def _valid_org(org):
    return len(org) >= 12 and "-" in org

def _headers(token, org):
    h = {**UA, "Authorization": f"Bearer {token}"}
    if org and _valid_org(org):
        h["X-Organization-ID"] = org
    return h

def _get(url, token, org, timeout=20):
    try:
        r = requests.get(url, headers=_headers(token, org), timeout=timeout)
    except Exception as e:
        return {"error": f"network error: {e}"}
    if r.status_code == 401:
        return {"error": ("HTTP 401: token rejected — regenerate your Personal Access Token at "
                          "platform.censys.io → user icon → API Access (shown only once)")}
    if r.status_code == 403 and "organization" in r.text.lower():
        return {"error": ("HTTP 403: this Censys endpoint requires a paid organization ID — "
                          "free accounts can only use the Lookup APIs (host / web property / "
                          "certificate), which this module already uses")}
    if r.status_code == 404:
        return {"not_found": True}
    if r.status_code != 200:
        return {"error": f"HTTP {r.status_code}: {r.text[:200]}"}
    return r.json()

def lookup(target, timeout=20):
    token, org = _creds()
    if not token:
        return {"skipped": ("set CENSYS_API_TOKEN (Personal Access Token from platform.censys.io → "
                          "user icon → API Access → Create New Token). Free tier works — "
                          "CENSYS_ORG_ID is only needed for paid orgs; leave it empty otherwise.")}
    target = target.strip().lower()
    out = {"target": target, "is_ip": is_ip(target),
           "platform": "censys-platform-v3 (free lookup API)"}
    if org and not _valid_org(org):
        out["warning"] = (f"CENSYS_ORG_ID '{org}' doesn't look like an org UUID — omitting it "
                          f"(free-tier tokens have no org ID)")

    if out["is_ip"]:
        resp = _get(HOST_URL.format(target), token, org, timeout=timeout)
        if "error" in resp:
            return {**out, **resp}
        if resp.get("not_found"):
            out["not_found"] = True
            return out
        j = resp.get("result", {}).get("resource", {})
        svcs = j.get("services") or []
        loc = j.get("location") or {}
        asn = j.get("autonomous_system") or {}
        names = (j.get("dns") or {}).get("names") or []
        out["host"] = {
            "ip": j.get("ip"),
            "country": loc.get("country"),
            "city": loc.get("city"),
            "asn": asn.get("asn"),
            "asn_name": asn.get("name") or asn.get("description"),
            "services": [{"port": s.get("port"),
                          "service_name": s.get("protocol"),
                          "transport": s.get("transport_protocol"),
                          "scan_time": s.get("scan_time")}
                         for s in svcs],
            "hostnames": names[:15],
            "last_updated": max((s.get("scan_time") for s in svcs if s.get("scan_time")),
                                default=None),
        }
    else:
        for port in (443, 80):
            resp = _get(WEB_URL.format(f"{target}:{port}"), token, org, timeout=timeout)
            if "error" in resp or resp.get("not_found"):
                continue
            j = resp.get("result", {}).get("resource", {})
            sw = j.get("software") or []
            cert = j.get("cert") or {}
            sw_bits = []
            for s in sw[:8]:
                label = f"{s.get('vendor') or ''} {s.get('product') or ''}".strip()
                if not label:
                    label = "/".join(s.get("type") or [])
                if label:
                    sw_bits.append(label)
            out.setdefault("hosts", []).append({
                "ip": f"{j.get('hostname') or target}:{j.get('port') or port}",
                "country": "",
                "services": ", ".join(sw_bits) or (j.get("protocol") or ""),
                "last_updated": j.get("last_updated_at"),
            })
            if cert:
                out.setdefault("certificates", []).append({
                    "subject_dn": cert.get("subject_dn") or cert.get("fingerprint_sha256"),
                    "names": j.get("hostname") or target,
                    "issuer": cert.get("issuer_dn"),
                    "sha256": cert.get("fingerprint_sha256"),
                })
        if not out.get("hosts"):
            out["not_found"] = True
    return out
