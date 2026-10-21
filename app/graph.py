"""Link-analysis graph: derives entities/edges from stored searches.
Pure Python (no graph DB needed) -> nodes/edges JSON for vis-network."""
import json

def build_graph(searches):
    nodes, edges = {}, []
    seen_edges = set()

    def node(ntype, value, **extra):
        key = (ntype, str(value))
        if key not in nodes:
            nodes[key] = {"id": len(nodes) + 1, "type": ntype,
                          "label": str(value)[:60], "value": 0, **extra}
        return nodes[key]["id"]

    def link(a, b, label):
        e = (a, b, label)
        if a != b and e not in seen_edges:
            seen_edges.add(e)
            edges.append({"from": a, "to": b, "label": label})

    def _is_ip_local(q):
        import ipaddress
        try:
            ipaddress.ip_address(str(q))
            return True
        except ValueError:
            return False

    for s in searches:
        try:
            res = json.loads(s["result"])
        except Exception:
            continue
        root_type = s["type"]
        if root_type == "ip" and not _is_ip_local(s["query"]):
            root_type = "hostname"      # the IP module also takes domains
        root = node(root_type, s["query"], title=f'{root_type}: {s["query"]}')
        t = s["type"]

        if t == "username":
            for r in res.get("results", []):
                if r.get("status") == "found":
                    n = node("account", f'{r["site"]}: {res.get("username")}', site=r["site"])
                    link(root, n, "has profile")

        elif t == "email":
            for u in res.get("possible_usernames", []):
                n = node("username", u)
                link(root, n, "local-part")
            g = res.get("gravatar") or {}
            if g.get("display_name"):
                n = node("name", g["display_name"])
                link(root, n, "gravatar name")
            for a in g.get("accounts", []):
                n = node("account", f'{a.get("name")}: {a.get("username") or a.get("url")}')
                link(root, n, "verified account")
            for b in res.get("breaches", []):
                n = node("breach", b.get("name") or b.get("title"))
                link(root, n, "exposed in")

        elif t == "ip":
            geo = (res.get("sources") or {}).get("ip-api") or {}
            if geo.get("isp"):
                link(root, node("org", geo["isp"]), "ISP")
            if geo.get("as"):
                link(root, node("asn", geo["as"]), "announced by")
            if geo.get("proxy"):
                link(root, node("flag", "VPN/Proxy/Tor"), "hosting flag")
            rdap = (res.get("sources") or {}).get("rdap") or {}
            if rdap.get("name"):
                link(root, node("netblock", rdap["name"]), "netblock")
            # censys / subdomain enumeration for domains
            if res.get("domain"):
                dn = node("domain", res["domain"])
                link(root, dn, "enumerated")
                for s in (res.get("subdomains") or [])[:12]:
                    link(dn, node("subdomain", s["host"]), "subdomain")

        elif t == "telegram":
            if res.get("title"):
                link(root, node("name", res["title"]), "channel title")
            if res.get("official_site"):
                link(root, node("domain", res["official_site"]), "linked site")

    for e in edges:
        nodes[[k for k, v in nodes.items() if v["id"] == e["from"]][0]]["value"] += 1
    for e in edges:
        for k, v in nodes.items():
            if v["id"] in (e["from"], e["to"]):
                pass
    # degree per node
    deg = {}
    for e in edges:
        deg[e["from"]] = deg.get(e["from"], 0) + 1
        deg[e["to"]] = deg.get(e["to"], 0) + 1
    for v in nodes.values():
        v["value"] = deg.get(v["id"], 0) + 1

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "stats": {"nodes": len(nodes), "edges": len(edges)},
    }
