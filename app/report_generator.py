"""HTML Report generation for Event-Analyzer."""

from __future__ import annotations

from datetime import datetime
from html import escape
from typing import Any, Dict, List, Optional

from app import db
from app.ioc_extractor import extract_iocs
from app.logger import get_logger
from app.sigma_matcher import match_event

logger = get_logger("report_generator")


def generate_report(investigation_id: str) -> str:
    inv = db.get_investigation(investigation_id)
    if not inv:
        return "<html><body><h1>Investigation not found</h1></body></html>"

    events = db.get_events(investigation_id, limit=5000)
    total_count = db.get_event_count(investigation_id)
    channels = db.get_channels(investigation_id)
    providers = db.get_providers(investigation_id)

    all_iocs: List[Dict[str, Any]] = []
    sigma_alerts: List[Dict[str, Any]] = []
    mitre_techniques: Dict[str, int] = {}
    event_levels = {"low": 0, "medium": 0, "high": 0}

    for event in events:
        iocs = extract_iocs(event)
        all_iocs.extend(iocs)

        matches = match_event(event)
        for m in matches:
            sigma_alerts.append({"event_id": event.get("id"), "rule": m})
            level = m.get("level", "low")
            event_levels[level] = event_levels.get(level, 0) + 1
            for tech in m.get("mitre_techniques", []):
                tid = tech.get("id", "")
                if tid:
                    mitre_techniques[tid] = mitre_techniques.get(tid, 0) + 1

    by_type: Dict[str, int] = {}
    for ioc in all_iocs:
        ioc_type = ioc.get("ioc_type", "unknown")
        by_type[ioc_type] = by_type.get(ioc_type, 0) + 1

    ioc_summary = dict(sorted(by_type.items(), key=lambda x: -x[1]))

    inv_name = escape(str(inv.get('name', 'Unknown')))
    now_str = datetime.now().isoformat()

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Investigation Report - {inv_name}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 960px; margin: 2em auto; padding: 0 1em; color: #1a1a2e; background: #f8f9fa; }}
h1, h2, h3 {{ color: #16213e; }}
table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
th, td {{ text-align: left; padding: 8px 12px; border-bottom: 1px solid #dee2e6; }}
th {{ background: #e9ecef; }}
.summary-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin: 1em 0; }}
.card {{ background: white; border-radius: 8px; padding: 1em; box-shadow: 0 1px 3px rgba(0,0,0,.1); }}
.card-value {{ font-size: 1.8em; font-weight: 700; color: #0d6efd; }}
.card-label {{ font-size: .85em; color: #6c757d; }}
.section {{ margin: 1.5em 0; }}
.level-high {{ color: #dc3545; font-weight: 700; }}
.level-medium {{ color: #fd7e14; font-weight: 700; }}
.level-low {{ color: #6c757d; }}
</style>
</head>
<body>
<h1>Investigation: {inv_name}</h1>
<p>Generated: {now_str}</p>

<div class="summary-cards">
  <div class="card">
    <div class="card-value">{total_count}</div>
    <div class="card-label">Total Events</div>
  </div>
  <div class="card">
    <div class="card-value">{len(all_iocs)}</div>
    <div class="card-label">IOCs Found</div>
  </div>
  <div class="card">
    <div class="card-value">{len(sigma_alerts)}</div>
    <div class="card-label">Sigma Alerts</div>
  </div>
  <div class="card">
    <div class="card-value">{len(mitre_techniques)}</div>
    <div class="card-label">MITRE Techniques</div>
  </div>
</div>

<div class="section">
<h2>Sigma Rule Alerts</h2>
<table>
<tr><th>Rule</th><th>Level</th><th>Events</th></tr>
"""
    alert_counts: Dict[str, Dict[str, Any]] = {}
    for alert in sigma_alerts:
        rid = alert["rule"]["id"]
        if rid not in alert_counts:
            alert_counts[rid] = {**alert["rule"], "count": 0}
        alert_counts[rid]["count"] += 1

    for rid, info in sorted(alert_counts.items(), key=lambda x: -x[1]["count"]):
        level_class = f"level-{info.get('level', 'low')}"
        title = escape(str(info.get('title', rid)))
        level = escape(str(info.get('level', '')))
        html += f"<tr><td>{title}</td><td class='{level_class}'>{level}</td><td>{info['count']}</td></tr>\n"

    html += """</table>
</div>

<div class="section">
<h2>IOCs by Type</h2>
<table>
<tr><th>Type</th><th>Count</th></tr>
"""
    for ioc_type, count in ioc_summary.items():
        safe_type = escape(str(ioc_type))
        html += f"<tr><td>{safe_type}</td><td>{count}</td></tr>\n"

    html += """</table>
</div>

<div class="section">
<h2>Events by Channel</h2>
<table>
<tr><th>Channel</th></tr>
"""
    for ch in channels:
        safe_ch = escape(str(ch))
        html += f"<tr><td>{safe_ch}</td></tr>\n"

    html += """</table>
</div>

<div class="section">
<h2>Status</h2>
<p>Events: {total_count} | Channels: {len(channels)} | Providers: {len(providers)}</p>
</div>

</body>
</html>"""
    return html
