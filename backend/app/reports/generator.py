"""
SPIDERLY - Professional HTML report generator.
"""
import html
from datetime import datetime, timezone
from typing import Any, Dict

SEVERITY_COLORS = {
    "HIGH": "#ff5c5c",
    "MEDIUM": "#ff9f43",
    "LOW": "#4ecbff",
    "INFORMATIONAL": "#7d8ba1",
}


def _esc(v) -> str:
    return html.escape(str(v)) if v is not None else ""


def generate_html_report(results: Dict[str, Any]) -> str:
    scan = results.get("scan", {})
    hosts = results.get("hosts", [])
    ports = results.get("ports", [])
    findings = results.get("findings", [])
    http_meta = {m["port_id"]: m for m in results.get("http_metadata", [])}

    started = scan.get("started_at")
    completed = scan.get("completed_at")
    started_str = datetime.fromtimestamp(started, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if started else "N/A"
    completed_str = datetime.fromtimestamp(completed, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if completed else "N/A"
    duration = f"{completed - started:.2f}s" if started and completed else "N/A"

    open_ports = [p for p in ports if p["state"] == "open"]
    sev_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    port_rows = "\n".join(
        f"""<tr>
            <td>{_esc(p['port'])}</td>
            <td><span class="badge open">OPEN</span></td>
            <td>{_esc(p['protocol'])}</td>
            <td>{_esc(p['service_guess'] or 'Unknown')}</td>
            <td class="mono">{_esc((p.get('banner') or '')[:120])}</td>
        </tr>""" for p in open_ports
    ) or "<tr><td colspan='5' class='empty'>No open ports discovered.</td></tr>"

    finding_cards = "\n".join(
        f"""<div class="finding-card sev-{f['severity'].lower()}">
            <div class="finding-head">
                <span class="sev-pill sev-{f['severity'].lower()}">{_esc(f['severity'])}</span>
                <h3>{_esc(f['title'])}</h3>
            </div>
            <p>{_esc(f['description'])}</p>
            <div class="finding-meta">
                <div><strong>Affected service:</strong> {_esc(f.get('affected_service') or 'N/A')}</div>
                <div><strong>Evidence:</strong> <span class="mono">{_esc(f.get('evidence') or 'N/A')}</span></div>
                <div><strong>Recommendation:</strong> {_esc(f.get('recommendation') or 'N/A')}</div>
            </div>
        </div>""" for f in findings
    ) or "<p class='empty'>No findings recorded for this scan.</p>"

    host_summary = "\n".join(
        f"<div>Host <strong>{_esc(h['address'])}</strong> — "
        f"{'reachable' if h['reachable'] else 'no response to reachability probes'}</div>"
        for h in hosts
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SPIDERLY Report — {_esc(scan.get('target'))}</title>
<style>
  :root {{
    --bg: #0a0e14; --panel: #10151f; --border: #1f2937; --cyan: #35e6ff;
    --text: #dbe4f0; --muted: #8494ab;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 40px; background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    line-height: 1.55;
  }}
  .mono {{ font-family: 'SFMono-Regular', Consolas, monospace; font-size: 0.85em; color: var(--muted); }}
  .wrap {{ max-width: 900px; margin: 0 auto; }}
  header {{ border-bottom: 1px solid var(--border); padding-bottom: 24px; margin-bottom: 32px; }}
  .brand {{ font-size: 28px; font-weight: 700; letter-spacing: 2px; color: var(--cyan); }}
  .subtitle {{ color: var(--muted); margin-top: 4px; }}
  h2 {{ color: var(--cyan); border-bottom: 1px solid var(--border); padding-bottom: 8px; margin-top: 40px; font-size: 18px; letter-spacing: 1px; text-transform: uppercase; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
  th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); font-size: 14px; }}
  th {{ color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 1px; }}
  .badge.open {{ background: rgba(53,230,255,0.15); color: var(--cyan); padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-top: 16px; }}
  .stat {{ background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }}
  .stat .num {{ font-size: 28px; font-weight: 700; color: var(--cyan); }}
  .stat .label {{ font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}
  .meta-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 8px 24px; margin-top: 16px; }}
  .meta-grid div {{ font-size: 14px; }}
  .meta-grid strong {{ color: var(--muted); font-weight: 600; }}
  .finding-card {{ background: var(--panel); border: 1px solid var(--border); border-left: 3px solid var(--muted); border-radius: 6px; padding: 16px 20px; margin-top: 14px; }}
  .finding-card.sev-high {{ border-left-color: {SEVERITY_COLORS['HIGH']}; }}
  .finding-card.sev-medium {{ border-left-color: {SEVERITY_COLORS['MEDIUM']}; }}
  .finding-card.sev-low {{ border-left-color: {SEVERITY_COLORS['LOW']}; }}
  .finding-card.sev-informational {{ border-left-color: {SEVERITY_COLORS['INFORMATIONAL']}; }}
  .finding-head {{ display: flex; align-items: center; gap: 10px; }}
  .finding-head h3 {{ margin: 0; font-size: 15px; }}
  .sev-pill {{ font-size: 10px; font-weight: 700; padding: 3px 8px; border-radius: 10px; letter-spacing: 0.5px; }}
  .sev-pill.sev-high {{ background: rgba(255,92,92,0.15); color: {SEVERITY_COLORS['HIGH']}; }}
  .sev-pill.sev-medium {{ background: rgba(255,159,67,0.15); color: {SEVERITY_COLORS['MEDIUM']}; }}
  .sev-pill.sev-low {{ background: rgba(78,203,255,0.15); color: {SEVERITY_COLORS['LOW']}; }}
  .sev-pill.sev-informational {{ background: rgba(125,139,161,0.15); color: {SEVERITY_COLORS['INFORMATIONAL']}; }}
  .finding-meta {{ margin-top: 10px; font-size: 13px; color: var(--muted); display: flex; flex-direction: column; gap: 4px; }}
  .empty {{ color: var(--muted); font-style: italic; }}
  footer {{ margin-top: 48px; padding-top: 16px; border-top: 1px solid var(--border); color: var(--muted); font-size: 12px; }}
  .warn-banner {{ background: rgba(255,159,67,0.1); border: 1px solid rgba(255,159,67,0.3); color: #ffbd7a; padding: 12px 16px; border-radius: 6px; font-size: 13px; margin-top: 20px; }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand">◈ SPIDERLY</div>
    <div class="subtitle">Network Reconnaissance Report</div>
  </header>

  <h2>Scan Overview</h2>
  <div class="meta-grid">
    <div><strong>Target:</strong> {_esc(scan.get('target'))}</div>
    <div><strong>Scan mode:</strong> {_esc(scan.get('scan_mode'))}</div>
    <div><strong>Port specification:</strong> {_esc(scan.get('port_spec'))}</div>
    <div><strong>Status:</strong> {_esc(scan.get('status'))}</div>
    <div><strong>Started:</strong> {started_str}</div>
    <div><strong>Completed:</strong> {completed_str}</div>
    <div><strong>Duration:</strong> {duration}</div>
    <div><strong>Scan ID:</strong> <span class="mono">{_esc(scan.get('id'))}</span></div>
  </div>

  <h2>Executive Summary</h2>
  <div class="summary-grid">
    <div class="stat"><div class="num">{len(hosts)}</div><div class="label">Hosts</div></div>
    <div class="stat"><div class="num">{len(open_ports)}</div><div class="label">Open Ports</div></div>
    <div class="stat"><div class="num">{len(findings)}</div><div class="label">Findings</div></div>
    <div class="stat"><div class="num">{sev_counts.get('HIGH', 0) + sev_counts.get('MEDIUM', 0)}</div><div class="label">Med/High Issues</div></div>
  </div>

  <h2>Host Information</h2>
  {host_summary}

  <h2>Open Ports &amp; Services</h2>
  <table>
    <thead><tr><th>Port</th><th>State</th><th>Protocol</th><th>Service</th><th>Banner / Evidence</th></tr></thead>
    <tbody>{port_rows}</tbody>
  </table>

  <h2>Findings</h2>
  {finding_cards}

  <div class="warn-banner">
    This report reflects informational reconnaissance and rule-based observations only.
    Items are not confirmed exploitable vulnerabilities unless explicitly stated with
    supporting evidence. Only use SPIDERLY against systems you own or are explicitly
    authorized to test.
  </div>

  <footer>
    Generated by SPIDERLY Network Reconnaissance &amp; Intelligence Platform ·
    Report timestamp: {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
  </footer>
</div>
</body>
</html>"""
