import os
from dotenv import load_dotenv
# load .env from the PROJECT ROOT regardless of the current working directory
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env"))

import anyio
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app.db import init_db, add_search, list_searches, get_search
from app.modules import ip_osint, username, email_osint, telegram, censys, dnsdumpster, internetdb
from app.graph import build_graph
from app.report import build_report

app = FastAPI(title="MiniOSINT Platform", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
init_db()

KEYS = {
    "shodan": os.getenv("SHODAN_API_KEY"),
    "abuseipdb": os.getenv("ABUSEIPDB_API_KEY"),
    "hibp": os.getenv("HIBP_API_KEY"),
    "censys": bool(os.getenv("CENSYS_API_TOKEN")),
    "dnsdumpster": bool(os.getenv("DNSDUMPSTER_API_KEY")),
    "leakcheck": True,   # Public API is free and keyless (Pro key optional, see LEAKCHECK_API_KEY)
}

class Lookup(BaseModel):
    query: str

@app.get("/api/status")
def status():
    return {"ok": True, "keys": {k: bool(v) for k, v in KEYS.items()}}

@app.get("/api/test")
def test_connections():
    """Minimal authenticated ping per configured service — diagnoses 'key not working'."""
    import requests as req
    UA = {"User-Agent": "mini-osint-platform/0.3 (+research)"}
    out = {}

    key = os.getenv("DNSDUMPSTER_API_KEY")
    if key:
        try:
            r = req.get("https://api.dnsdumpster.com/domain/example.com",
                        headers={"X-API-Key": key, **UA}, timeout=15)
            if r.status_code == 200:
                j = r.json()
                out["dnsdumpster"] = {"ok": True, "http": 200,
                                      "detail": f"auth OK — {j.get('total_a_recs', len(j.get('a', [])))} A records for example.com"}
            elif r.status_code == 429:
                out["dnsdumpster"] = {"ok": False, "http": 429, "detail": "rate limited (1 req / 2s) — wait a few seconds"}
            else:
                try:
                    msg = r.json().get("error", r.text[:100])
                except Exception:
                    msg = r.text[:100]
                out["dnsdumpster"] = {"ok": False, "http": r.status_code, "detail": str(msg)}
        except Exception as e:
            out["dnsdumpster"] = {"ok": False, "http": None, "detail": f"network error: {e}"}

    # internetdb is keyless — always testable
    try:
        r = req.get("https://internetdb.shodan.io/1.1.1.1", headers=UA, timeout=12)
        out["internetdb"] = {"ok": r.status_code == 200, "http": r.status_code,
                             "detail": "keyless API reachable" if r.status_code == 200 else r.text[:80]}
    except Exception as e:
        out["internetdb"] = {"ok": False, "http": None, "detail": f"network error: {e}"}

    from app.modules import censys as cz
    token, _org = cz._creds()
    if token:
        res = cz.lookup("1.1.1.1")
        if res.get("host"):
            out["censys"] = {"ok": True, "http": 200,
                             "detail": f"auth OK — host lookup works ({len(res['host'].get('services') or [])} services for 1.1.1.1)"}
        else:
            out["censys"] = {"ok": False, "http": None,
                             "detail": res.get("error") or res.get("skipped") or "no host data returned"}

    if KEYS.get("shodan"):
        try:
            r = req.get("https://api.shodan.io/shodan/host/1.1.1.1",
                        params={"key": KEYS["shodan"]}, timeout=15, headers=UA)
            out["shodan"] = {"ok": r.status_code == 200, "http": r.status_code,
                             "detail": "auth OK" if r.status_code == 200 else r.text[:120]}
        except Exception as e:
            out["shodan"] = {"ok": False, "http": None, "detail": str(e)}
    if KEYS.get("abuseipdb"):
        try:
            r = req.get("https://api.abuseipdb.com/api/v2/check",
                        params={"ipAddress": "8.8.8.8", "maxAgeInDays": 90},
                        headers={"Key": KEYS["abuseipdb"], "Accept": "application/json"}, timeout=15)
            out["abuseipdb"] = {"ok": r.status_code == 200, "http": r.status_code,
                                "detail": "auth OK" if r.status_code == 200 else r.text[:120]}
        except Exception as e:
            out["abuseipdb"] = {"ok": False, "http": None, "detail": str(e)}
    # LeakCheck Public API is keyless — always test it
    try:
        r = req.get("https://leakcheck.io/api/public?check=nobody@example.com",
                    headers=UA, timeout=15)
        if r.status_code == 200 and r.json().get("success") is not None:
            j = r.json()
            out["leakcheck"] = {"ok": True, "http": 200,
                                "detail": f"public API OK — {j.get('found', 0)} records, "
                                          f"{len(j.get('sources', []))} sources for test account"}
        else:
            out["leakcheck"] = {"ok": False, "http": r.status_code, "detail": r.text[:120]}
    except Exception as e:
        out["leakcheck"] = {"ok": False, "http": None, "detail": str(e)}

    if KEYS.get("hibp"):
        try:
            r = req.get("https://haveibeenpwned.com/api/v3/breachedaccount/nobody@example.com",
                        headers={"hibp-api-key": KEYS["hibp"], "User-Agent": "mini-osint-platform"}, timeout=15)
            out["hibp"] = {"ok": r.status_code in (200, 404), "http": r.status_code,
                           "detail": "auth OK (404 = no breaches for test account, as expected)"
                                     if r.status_code == 404 else ("auth OK" if r.status_code == 200 else r.text[:120])}
        except Exception as e:
            out["hibp"] = {"ok": False, "http": None, "detail": str(e)}

    if not out:
        out["_note"] = "no API keys configured — add them to .env and restart the server"
    return out

@app.post("/api/lookup/ip")
def lookup_ip(l: Lookup):
    q = l.query.strip()
    res = ip_osint.lookup(q, shodan_key=KEYS["shodan"], abuseipdb_key=KEYS["abuseipdb"])
    # Censys host/cert intel (works for both IPs and domains)
    res["sources"]["censys"] = censys.lookup(q)
    if censys.is_ip(q):
        res["sources"]["internetdb"] = internetdb.lookup(q)
    # subdomain enumeration when the target is a domain
    if not censys.is_ip(q):
        dd = dnsdumpster.subdomains(q)
        res["domain"] = dd.get("domain", q)
        res["dns_method"] = dd.get("method")
        res["subdomains"] = dd.get("subdomains", [])
        res["dns_records"] = dd.get("dns_records", {})
        res["dns_warnings"] = dd.get("warnings", [])
        res["dns_sources"] = " + ".join(dd.get("sources", [])) or None
    sid = add_search("ip", q, res)
    return {"id": sid, "type": "ip", "query": q, "result": res}

@app.post("/api/lookup/username")
def lookup_username(l: Lookup):
    q = l.query.strip().lstrip("@")
    res = username.lookup(q)
    sid = add_search("username", q, res)
    return {"id": sid, "type": "username", "query": q, "result": res}

@app.post("/api/lookup/email")
def lookup_email(l: Lookup):
    q = l.query.strip().lower()
    if "@" not in q:
        raise HTTPException(400, "invalid email")
    res = email_osint.lookup(q, hibp_key=KEYS["hibp"])
    sid = add_search("email", q, res)
    return {"id": sid, "type": "email", "query": q, "result": res}

@app.post("/api/lookup/telegram")
async def lookup_telegram(l: Lookup):
    q = l.query.strip().lstrip("@")
    res = await telegram.lookup(q)   # Telethon is async-native: await it in the app's event loop
    sid = add_search("telegram", q, res)
    return {"id": sid, "type": "telegram", "query": q, "result": res}

@app.get("/api/history")
def history():
    items = list_searches(300)
    for it in items:
        it.pop("result", None)   # keep history light
    return {"items": items}

@app.get("/api/result/{sid}")
def result(sid: int):
    s = get_search(sid)
    if not s:
        raise HTTPException(404, "not found")
    return {"id": s["id"], "type": s["type"], "query": s["query"],
            "created_at": s["created_at"], "result": __import__("json").loads(s["result"])}

@app.get("/api/graph")
def graph():
    return build_graph(list_searches(500))

@app.get("/api/report/{scope}")
def report(scope: str):
    searches = list_searches(500) if scope == "all" else [get_search(int(scope))]
    if not searches or searches[0] is None:
        raise HTTPException(404, "no searches yet")
    out = os.path.join("reports", f"report_{scope}.pdf")
    build_report(searches, out)
    return FileResponse(out, media_type="application/pdf", filename=f"osint_report_{scope}.pdf")

class Ids(BaseModel):
    ids: list

@app.post("/api/history/delete")
def delete_selected(body: Ids):
    from app.db import delete_searches
    n = delete_searches(body.ids)
    return {"deleted": n}

@app.delete("/api/history")
def clear_history():
    from app.db import _conn
    with _conn() as c:
        c.execute("DELETE FROM searches")
    return {"cleared": True}

app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static"), html=True), name="static")
