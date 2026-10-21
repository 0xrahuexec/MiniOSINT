"""Email OSINT: Gravatar profile pivot, breach checks (HIBP paid key OR LeakCheck free key),
MX records, username derivation, disposable-domain flag. Every source reports its status
so 'no data' is distinguishable from 'source not configured'."""
import hashlib, os
import requests
from urllib.parse import quote

UA = {"User-Agent": "mini-osint-platform/0.5 (+research)"}
GMAILISH = {"gmail.com", "googlemail.com"}
DISPOSABLE = {
    "mailinator.com", "10minutemail.com", "10minutemail.net", "tempmail.com", "temp-mail.org",
    "guerrillamail.com", "guerrillamail.net", "yopmail.com", "throwawaymail.com",
    "sharklasers.com", "getnada.com", "dispostable.com", "maildrop.cc", "trashmail.com",
    "fakeinbox.com", "mintemail.com", "moakt.com", "emailondeck.com", "tempinbox.com",
    "33mail.com", "mytemp.email", "anonbox.net", "spambog.com", "mailnesia.com",
    "harakirimail.com", "mailcatch.com", "meltmail.com", "jetable.org", "mailforspam.com",
    "tempr.email", "discardmail.com", "spamgourmet.com", "yomail.info", "spamfree24.org",
    "burnermail.io", "mohmal.com", "emailfake.com", "fakemailgenerator.com",
}

def lookup(email, hibp_key=None, timeout=10):
    email = email.strip().lower()
    local, _, domain = email.partition("@")
    out = {"email": email, "possible_usernames": [], "gravatar": {}, "mx": [],
           "breaches": [], "disposable": domain in DISPOSABLE}

    # --- candidate usernames from the local part ---
    cands = {local}
    if "+" in local:
        cands.add(local.split("+")[0])
    if domain in GMAILISH:
        cands.add(local.replace(".", ""))
        if "+" in local:
            cands.add(local.split("+")[0].replace(".", ""))
    out["possible_usernames"] = sorted(cands)

    # --- Gravatar pivot (no key) ---
    h = hashlib.md5(email.encode()).hexdigest()
    out["gravatar_hash"] = h
    out["gravatar_avatar"] = f"https://www.gravatar.com/avatar/{h}?s=200&d=404"
    try:
        r = requests.get(f"https://www.gravatar.com/{h}.json", timeout=timeout, headers=UA)
        if r.status_code == 200:
            entry = r.json().get("entry", [{}])[0]
            out["gravatar"] = {
                "display_name": entry.get("displayName"),
                "about": (entry.get("aboutMe") or "")[:300],
                "location": entry.get("currentLocation"),
                "accounts": [
                    {"name": a.get("name"), "domain": a.get("domain"),
                     "username": a.get("username"), "url": a.get("url")}
                    for a in entry.get("accounts", [])
                ],
                "urls": [u.get("value") for u in entry.get("urls", [])][:10],
                "photo": (entry.get("photos") or [{}])[0].get("value"),
            }
            out["gravatar_status"] = "profile found"
        else:
            out["gravatar_status"] = "no public profile"
            out["gravatar"] = {"info": f"HTTP {r.status_code} — this email has no public Gravatar profile (expected for most emails)"}
    except Exception as e:
        out["gravatar_status"] = "error"
        out["gravatar"] = {"error": str(e)}

    # --- MX records ---
    try:
        import dns.resolver
        out["mx"] = [str(x.exchange).rstrip(".") for x in dns.resolver.resolve(domain, "MX")]
        out["mx_status"] = "ok"
    except Exception as e:
        out["mx"] = []
        out["mx_status"] = f"lookup failed ({e.__class__.__name__})"

    # --- breaches: LeakCheck Public API (FREE, no key) + HIBP (paid key) + optional LeakCheck Pro ---
    hibp_key = hibp_key or os.getenv("HIBP_API_KEY")
    lc_key = os.getenv("LEAKCHECK_API_KEY")   # optional; only adds value if the key has an active Pro plan
    queried = []

    # LeakCheck Public API — free, no auth: sources + data categories only
    try:
        r = requests.get(f"https://leakcheck.io/api/public?check={quote(email)}",
                         timeout=timeout, headers=UA)
        if r.status_code == 200:
            j = r.json()
            if j.get("success"):
                queried.append("LeakCheck")
                out["leakcheck_found_count"] = j.get("found")
                for src_ in j.get("sources", []):
                    name = src_.get("name") if isinstance(src_, dict) else src_
                    date = src_.get("date") if isinstance(src_, dict) else None
                    if name:
                        out["breaches"].append({"name": name,
                                                "date": (date + "-01") if date else None,
                                                "data": j.get("fields", [])[:12],
                                                "via": "LeakCheck"})
        elif r.status_code == 429:
            out["breach_errors"] = (out.get("breach_errors") or []) +                 ["LeakCheck public API rate limit (1 req/s) — retry in a moment"]
        else:
            out["breach_errors"] = (out.get("breach_errors") or []) +                 [f"LeakCheck public API HTTP {r.status_code}"]
    except Exception as e:
        out["breach_errors"] = (out.get("breach_errors") or []) + [f"LeakCheck: {e}"]

    # LeakCheck Pro v2 — only if a key is configured AND licensed; merged (dedup by name)
    if lc_key:
        try:
            r = requests.get(f"https://leakcheck.io/api/v2/query/{quote(email)}",
                             params={"type": "email", "key": lc_key},
                             timeout=timeout, headers=UA)
            if r.status_code == 200 and r.json().get("success"):
                if "LeakCheck" in queried:
                    queried.append("LeakCheck Pro")
                for item in r.json().get("result", []):
                    src_ = item.get("source")
                    name = src_.get("name") if isinstance(src_, dict) else src_
                    date = (src_.get("date") if isinstance(src_, dict) else None)
                    if name and not any(b["name"] == name for b in out["breaches"]):
                        out["breaches"].append({"name": name, "date": date,
                            "data": [k for k, v in (item.get("fields") or {}).items() if v]
                                     or item.get("data") or [], "via": "LeakCheck Pro"})
            elif r.status_code == 403:
                out["leakcheck_pro_note"] = ("LEAKCHECK_API_KEY has no active Pro plan "
                                             "(Pro is from $9.99/mo) — using the free Public API: "
                                             "sources + data categories, no passwords")
        except Exception:
            pass

    # HIBP (paid key)
    if hibp_key:
        queried.append("HIBP")
        try:
            r = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}?truncateResponse=false",
                headers={"hibp-api-key": hibp_key, "User-Agent": "mini-osint-platform"},
                timeout=timeout)
            if r.status_code == 200:
                for b in r.json():
                    if not any(x["name"] == b.get("Name") for x in out["breaches"]):
                        out["breaches"].append({"name": b.get("Name"), "title": b.get("Title"),
                            "date": b.get("BreachDate"), "data": b.get("DataClasses"),
                            "pwn_count": b.get("PwnCount"), "via": "HIBP"})
        except Exception as e:
            out["breach_errors"] = (out.get("breach_errors") or []) + [f"HIBP: {e}"]

    out["breach_sources_queried"] = queried
    out["breaches"].sort(key=lambda b: b.get("date") or "", reverse=True)
    if not queried:
        out["breach_note"] = ("breach sources unreachable and no HIBP key — add HIBP_API_KEY (paid) "
                              "to .env for additional coverage")
    return out
