"""IP OSINT: geolocation, ASN, RDAP, abuse reputation, Shodan (optional keys)."""
import requests

UA = {"User-Agent": "mini-osint-platform/0.1 (+research)"}

def lookup(ip, shodan_key=None, abuseipdb_key=None, timeout=8):
    out = {"ip": ip, "sources": {}}

    # 1) ip-api.com (free, no key)
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,"
            "city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query",
            timeout=timeout, headers=UA)
        j = r.json()
        out["sources"]["ip-api"] = j if j.get("status") == "success" else {"error": j.get("message")}
    except Exception as e:
        out["sources"]["ip-api"] = {"error": str(e)}

    # 2) RDAP (registry data, no key)
    try:
        r = requests.get(f"https://rdap.arin.net/registry/ip/{ip}",
                         timeout=timeout, headers={"Accept": "application/rdap+json", **UA})
        j = r.json()
        out["sources"]["rdap"] = {
            "name": j.get("name"), "handle": j.get("handle"),
            "entities": [e.get("handle") for e in j.get("entities", [])][:5],
            "remarks": [d.get("description") for d in j.get("remarks", [])][:2],
            "link": j.get("links", [{}])[0].get("href"),
        }
    except Exception as e:
        out["sources"]["rdap"] = {"error": str(e)}

    # 3) AbuseIPDB (optional key)
    if abuseipdb_key:
        try:
            r = requests.get("https://api.abuseipdb.com/api/v2/check",
                             params={"ipAddress": ip, "maxAgeInDays": 90},
                             headers={"Key": abuseipdb_key, "Accept": "application/json"},
                             timeout=timeout)
            d = r.json().get("data", {})
            out["sources"]["abuseipdb"] = {
                "abuseConfidenceScore": d.get("abuseConfidenceScore"),
                "totalReports": d.get("totalReports"),
                "lastReportedAt": d.get("lastReportedAt"),
                "usageType": d.get("usageType"),
                "domain": d.get("domain"),
            }
        except Exception as e:
            out["sources"]["abuseipdb"] = {"error": str(e)}
    else:
        out["sources"]["abuseipdb"] = {"skipped": "set ABUSEIPDB_API_KEY"}

    # 4) Shodan host lookup (optional key)
    if shodan_key:
        try:
            r = requests.get(f"https://api.shodan.io/shodan/host/{ip}",
                             params={"key": shodan_key}, timeout=timeout, headers=UA)
            j = r.json()
            out["sources"]["shodan"] = {
                "ports": j.get("ports", []),
                "hostnames": j.get("hostnames", []),
                "vulns": (j.get("vulns") or [])[:10],
                "last_update": j.get("last_update"),
            }
        except Exception as e:
            out["sources"]["shodan"] = {"error": str(e)}
    else:
        out["sources"]["shodan"] = {"skipped": "set SHODAN_API_KEY"}

    return out
