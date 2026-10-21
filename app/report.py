"""PDF report generation (reportlab) — only includes data that was actually
retrieved (no placeholder rows for unavailable sources)."""
import os, json
from datetime import datetime, timezone
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle, PageBreak)
from app.graph import build_graph

def _s(text):
    return str(text).encode("latin-1", "replace").decode("latin-1")

def _table(rows, widths):
    t = Table([[_s(c) for c in row] for row in rows], colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                           ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                           ("FONTSIZE", (0, 0), (-1, -1), 8),
                           ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    return t

def build_report(searches, out_path):
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(out_path, pagesize=A4,
                            leftMargin=40, rightMargin=40,
                            topMargin=50, bottomMargin=50)
    story = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    story.append(Paragraph(_s("MiniOSINT Investigation Report"), styles["Title"]))
    story.append(Paragraph(_s(f"Generated: {now} | Searches included: {len(searches)}"), styles["Normal"]))
    story.append(Spacer(1, 16))

    g = build_graph(searches)
    summ = [["Entities", g["stats"]["nodes"]], ["Links", g["stats"]["edges"]]]
    for t in ("ip", "hostname", "username", "email", "telegram"):
        n = sum(1 for s in searches if s["type"] == t or (t == "hostname" and s["type"] == "ip" and not _is_ip(s["query"])))
        if n:
            summ.append([f"{t} searches", n])
    story.append(_table(summ, [200, 80]))
    story.append(Spacer(1, 20))

    for s in searches:
        res = json.loads(s["result"])
        kind = s["type"]
        if kind == "ip" and not _is_ip(s["query"]):
            kind = "hostname"
        story.append(Paragraph(_s(f'[{kind.upper()}] {s["query"]}'), styles["Heading2"]))
        story.append(Paragraph(_s(f'Searched at {s["created_at"]}'), styles["Italic"]))
        story.append(Spacer(1, 4))
        blocks = _render(kind, res)
        if blocks:
            story.extend(blocks)
        else:
            story.append(Paragraph(_s("(no data retrieved for this target)"), styles["Normal"]))
        story.append(Spacer(1, 14))

    story.append(PageBreak())
    story.append(Paragraph(_s("Top Connected Entities"), styles["Heading2"]))
    top = sorted(g["nodes"], key=lambda n: -n["value"])[:15]
    story.append(_table([[_s("Entity"), _s("Type"), _s("Links")]] +
                        [[_s(n["label"]), _s(n["type"]), str(n["value"])] for n in top],
                        [300, 120, 80]))

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    doc.build(story)
    return out_path

def _is_ip(q):
    import ipaddress
    try:
        ipaddress.ip_address(str(q))
        return True
    except ValueError:
        return False

def _render(kind, res):
    styles = getSampleStyleSheet()
    blocks = []
    H = lambda txt: Paragraph(_s(txt), styles["Heading3"])

    if kind in ("ip", "hostname"):
        src = res.get("sources", {})
        geo = src.get("ip-api") or {}
        rows = [["Field", "Value"]]
        if geo.get("status") == "success" or geo.get("country"):
            rows.append(["Country / City", f'{geo.get("country", "?")} / {geo.get("city", "?")}'])
            if geo.get("isp") or geo.get("org"):
                rows.append(["ISP / Org", f'{geo.get("isp", "")} / {geo.get("org", "")}'])
            if geo.get("as"):
                rows.append(["ASN", geo.get("as")])
            if geo.get("timezone"):
                rows.append(["Timezone", geo.get("timezone")])
            if geo.get("reverse"):
                rows.append(["Reverse DNS", geo.get("reverse")])
        rdap = src.get("rdap") or {}
        if rdap.get("name"):
            rows.append(["Netblock (RDAP)", rdap["name"]])
        ab = src.get("abuseipdb") or {}
        if ab.get("abuseConfidenceScore") is not None:
            rows.append(["AbuseIPDB score", f'{ab["abuseConfidenceScore"]}% ({ab.get("totalReports", "?")} reports/90d)'])
        sh = src.get("shodan") or {}
        if sh.get("ports"):
            rows.append(["Shodan open ports", ", ".join(map(str, sh["ports"][:20]))])
        idb = src.get("internetdb") or {}
        if idb.get("ports"):
            rows.append(["InternetDB ports", ", ".join(map(str, idb["ports"]))])
            if idb.get("vulns"):
                rows.append(["InternetDB CVEs", ", ".join(idb["vulns"][:10])])
            if idb.get("hostnames"):
                rows.append(["InternetDB hostnames", ", ".join(idb["hostnames"][:8])])
        if len(rows) > 1:
            blocks += [H("Network & reputation"), _table(rows, [140, 360])]

        cs = src.get("censys") or {}
        if cs.get("host", {}).get("services"):
            h = cs["host"]
            srows = [["Port", "Service", "Last scan"]]
            for sv in h["services"]:
                srows.append([str(sv.get("port", "?")), sv.get("service_name") or "?",
                              (sv.get("scan_time") or "")[:10]])
            blocks += [H("Censys services"), _table(srows, [60, 120, 110])]
            extras = []
            if h.get("asn"):
                extras.append(f'ASN {h["asn"]} {h.get("asn_name") or ""}'.strip())
            if h.get("hostnames"):
                extras.append(f'reverse DNS: {", ".join(h["hostnames"][:8])}')
            if extras:
                blocks.append(Paragraph(_s(" | ".join(extras)), styles["Normal"]))
        elif cs.get("hosts"):
            hrows = [["Web property", "Software"]]
            for h in cs["hosts"]:
                hrows.append([h.get("ip", "?"), h.get("services", "")])
            blocks += [H("Censys web properties"), _table(hrows, [160, 340])]
        certs = cs.get("certificates") or []
        if certs:
            crows = [["Subject / Fingerprint", "Issuer", "Host"]]
            for c in certs[:10]:
                crows.append([c.get("subject_dn") or c.get("sha256") or "?",
                              c.get("issuer") or "", c.get("names") or ""])
            blocks += [H("Certificates"), _table(crows, [200, 170, 130])]

        subs = res.get("subdomains") or []
        if subs:
            prows = [["Subdomain", "IP(s)"]]
            for sd in subs[:40]:
                prows.append([sd.get("host", "?"), ", ".join(sd.get("ips") or []) or "-"])
            blocks += [H(f'Subdomains ({len(subs)}) — {res.get("dns_sources") or "multiple sources"}'),
                       _table(prows, [260, 240])]

    elif kind == "username":
        results = res.get("results", [])
        found = [r for r in results if r.get("status") == "found"]
        if found:
            rows = [["Platform", "Profile"]]
            for r in found:
                rows.append([r["site"], r["url"]])
            blocks += [H(f'Matches on {len(found)} platforms'),
                       _table(rows, [130, 370])]
        else:
            blocks.append(Paragraph(_s("No matching profiles found."), styles["Normal"]))

    elif kind == "email":
        gres = res.get("gravatar") or {}
        rows = [["Field", "Value"]]
        if gres.get("display_name"):
            rows.append(["Display name", gres["display_name"]])
            if gres.get("location"):
                rows.append(["Location", gres["location"]])
            if gres.get("about"):
                rows.append(["About", gres["about"][:200]])
            accs = [a.get("name") for a in gres.get("accounts", []) if a.get("name")]
            if accs:
                rows.append(["Verified accounts", ", ".join(accs)])
        users = res.get("possible_usernames") or []
        if users:
            rows.append(["Derived usernames", ", ".join(users)])
        mx = [m for m in (res.get("mx") or []) if not str(m).startswith("lookup failed")]
        if mx:
            rows.append(["MX records", ", ".join(mx)])
        if len(rows) > 1:
            blocks += [H("Identity"), _table(rows, [140, 360])]
        breaches = res.get("breaches") or []
        if breaches:
            brows = [["Breach", "Date", "Data exposed"]]
            for b in breaches[:20]:
                brows.append([b.get("name") or b.get("title") or "?",
                              b.get("date") or "", ", ".join(b.get("data") or [])])
            blocks += [H(f"Breach exposure ({len(breaches)})"), _table(brows, [150, 70, 280])]

    elif kind == "telegram":
        items = [(k, v) for k, v in res.items()
                 if v not in (None, "", []) and k not in ("error",)]
        if items:
            rows = [["Field", "Value"]] + [[k, str(v)[:90]] for k, v in items]
            blocks += [H("Channel profile"), _table(rows, [140, 360])]
    return blocks
