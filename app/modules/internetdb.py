"""Shodan InternetDB — free, keyless IP enrichment.
https://internetdb.shodan.io/{ip} -> open ports, hostnames, tags, CPEs, CVEs.
Updated weekly; intended for non-commercial use. IP addresses only."""
import requests

UA = {"User-Agent": "mini-osint-platform/0.4 (+research)"}

def lookup(ip, timeout=12):
    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}",
                         headers=UA, timeout=timeout)
        if r.status_code == 404:
            return {"not_found": True}
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}: {r.text[:120]}"}
        j = r.json()
        return {"ports": j.get("ports", []), "hostnames": j.get("hostnames", []),
                "tags": j.get("tags", []), "cpes": j.get("cpes", []),
                "vulns": j.get("vulns", [])}
    except Exception as e:
        return {"error": str(e)}
