"""
Report Generator — produces JSON, HTML, and PDF security reports.
"""
import json
import os
import datetime
from typing import Dict, Any

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DroidSec Security Report — {package_name}</title>
<style>
  :root {{
    --bg: #0f0f14;
    --surface: #1a1a24;
    --surface2: #232333;
    --border: #2a2a3d;
    --text: #e4e4ef;
    --text-muted: #8888aa;
    --critical: #ff4757;
    --high: #ff8c42;
    --medium: #ffd166;
    --info: #6ec6ff;
    --accent: #7c5cfc;
    --success: #2ed573;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; line-height: 1.6; padding: 2rem; }}
  .container {{ max-width: 1000px; margin: 0 auto; }}
  .header {{ text-align: center; margin-bottom: 2rem; padding: 2rem; background: linear-gradient(135deg, var(--surface) 0%, var(--surface2) 100%); border-radius: 16px; border: 1px solid var(--border); }}
  .header h1 {{ font-size: 2rem; background: linear-gradient(135deg, var(--accent), var(--info)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
  .header .subtitle {{ color: var(--text-muted); margin-top: 0.5rem; }}
  .score-container {{ display: flex; justify-content: center; gap: 2rem; margin: 2rem 0; flex-wrap: wrap; }}
  .score-card {{ background: var(--surface); padding: 1.5rem 2rem; border-radius: 12px; border: 1px solid var(--border); text-align: center; min-width: 160px; }}
  .score-card .value {{ font-size: 2.5rem; font-weight: 800; }}
  .score-card .label {{ color: var(--text-muted); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 1px; }}
  .grade-A {{ color: var(--success); }}
  .grade-B {{ color: var(--info); }}
  .grade-C {{ color: var(--medium); }}
  .grade-D {{ color: var(--high); }}
  .grade-F {{ color: var(--critical); }}
  .summary {{ background: var(--surface); padding: 1.5rem; border-radius: 12px; border: 1px solid var(--border); margin: 1.5rem 0; }}
  .summary h2 {{ font-size: 1.2rem; margin-bottom: 0.5rem; }}
  .summary p {{ color: var(--text-muted); }}
  .severity-bar {{ display: flex; gap: 0.5rem; margin: 1.5rem 0; }}
  .severity-bar .bar {{ padding: 0.5rem 1rem; border-radius: 8px; font-weight: 600; font-size: 0.85rem; }}
  .sev-critical {{ background: rgba(255,71,87,0.15); color: var(--critical); border: 1px solid rgba(255,71,87,0.3); }}
  .sev-high {{ background: rgba(255,140,66,0.15); color: var(--high); border: 1px solid rgba(255,140,66,0.3); }}
  .sev-medium {{ background: rgba(255,209,102,0.15); color: var(--medium); border: 1px solid rgba(255,209,102,0.3); }}
  .sev-info {{ background: rgba(110,198,255,0.15); color: var(--info); border: 1px solid rgba(110,198,255,0.3); }}
  .findings {{ margin: 2rem 0; }}
  .findings h2 {{ font-size: 1.4rem; margin-bottom: 1rem; }}
  .finding {{ background: var(--surface); border-radius: 12px; border: 1px solid var(--border); margin: 1rem 0; overflow: hidden; }}
  .finding-header {{ display: flex; justify-content: space-between; align-items: center; padding: 1rem 1.5rem; border-bottom: 1px solid var(--border); }}
  .finding-header h3 {{ font-size: 1rem; }}
  .finding-body {{ padding: 1rem 1.5rem; }}
  .finding-body .meta {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 0.75rem; }}
  .finding-body .meta span {{ font-size: 0.8rem; padding: 0.2rem 0.6rem; border-radius: 4px; background: var(--surface2); color: var(--text-muted); }}
  .finding-body .description {{ margin: 0.5rem 0; }}
  .finding-body .evidence {{ background: var(--bg); padding: 0.75rem 1rem; border-radius: 8px; font-family: 'Cascadia Code', monospace; font-size: 0.85rem; margin: 0.5rem 0; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }}
  .finding-body .remediation {{ background: rgba(46,213,115,0.08); border: 1px solid rgba(46,213,115,0.2); border-radius: 8px; padding: 0.75rem 1rem; margin-top: 0.75rem; }}
  .finding-body .remediation strong {{ color: var(--success); }}
  .badge {{ font-size: 0.75rem; padding: 0.25rem 0.75rem; border-radius: 20px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }}
  .footer {{ text-align: center; color: var(--text-muted); margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid var(--border); font-size: 0.85rem; }}
  @media print {{
    body {{ background: #fff; color: #111; }}
    .container {{ max-width: 100%; }}
  }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>🛡️ DroidSec Security Report</h1>
    <div class="subtitle">Static Analysis Report for <strong>{package_name}</strong></div>
    <div class="subtitle">Generated on {timestamp}</div>
  </div>

  <div class="score-container">
    <div class="score-card">
      <div class="value grade-{grade}">{score}</div>
      <div class="label">Security Score</div>
    </div>
    <div class="score-card">
      <div class="value grade-{grade}">{grade}</div>
      <div class="label">Grade</div>
    </div>
    <div class="score-card">
      <div class="value">{total_findings}</div>
      <div class="label">Findings</div>
    </div>
    <div class="score-card">
      <div class="value">{risk_level}</div>
      <div class="label">Risk Level</div>
    </div>
  </div>

  <div class="summary">
    <h2>📋 Executive Summary</h2>
    <p>{executive_summary}</p>
  </div>

  <div class="severity-bar">
    <div class="bar sev-critical">🔴 Critical: {critical_count}</div>
    <div class="bar sev-high">🟠 High: {high_count}</div>
    <div class="bar sev-medium">🟡 Medium: {medium_count}</div>
    <div class="bar sev-info">🔵 Info: {info_count}</div>
  </div>

  <div class="findings">
    <h2>🔍 Detailed Findings</h2>
    {findings_html}
  </div>

  <div class="footer">
    <p>Generated by DroidSec — APK Static Security Analyzer | KrackHack 3.0</p>
  </div>
</div>
</body>
</html>"""

FINDING_TEMPLATE = """
<div class="finding">
  <div class="finding-header">
    <h3>{name}</h3>
    <span class="badge sev-{severity}">{severity_upper}</span>
  </div>
  <div class="finding-body">
    <div class="meta">
      <span>OWASP: {owasp} — {owasp_name}</span>
      <span>Confidence: {confidence}</span>
      <span>Confidence Score: {confidence_score}</span>
      <span>Source: {source_type}</span>
      <span>Instances: {count}</span>
      <span>📍 {location}</span>
    </div>
    {sample_locations_html}
    <div class="description">{description}</div>
    <div class="evidence">{evidence}</div>
    <div class="remediation"><strong>✅ Remediation:</strong> {remediation}</div>
  </div>
</div>
"""

OWASP_NAMES = {
    "M1": "Improper Credential Usage",
    "M2": "Inadequate Supply Chain Security",
    "M3": "Insecure Authentication/Authorization",
    "M4": "Insufficient Input/Output Validation",
    "M5": "Insecure Communication",
    "M6": "Inadequate Privacy Controls",
    "M7": "Insufficient Binary Protections",
    "M8": "Security Misconfiguration",
    "M9": "Insecure Data Storage",
    "M10": "Insufficient Cryptography",
}


def generate_html_report(report_data: Dict[str, Any], package_name: str = "unknown") -> str:
    """Generate a beautiful HTML security report."""
    score_data = report_data.get("security_score", {})
    severity = report_data.get("severity_breakdown", {})

    findings_html_parts = []
    for finding in report_data.get("findings", []):
        owasp_id = finding.get("owasp", "M8")
        sample_locations = finding.get("sample_locations", []) or []
        sample_locations_html = ""
        if sample_locations:
            sample_locations_html = (
                '<div class="description"><strong>Sample Locations:</strong> '
                + ", ".join(sample_locations[:3])
                + "</div>"
            )
        findings_html_parts.append(FINDING_TEMPLATE.format(
            name=finding.get("name", "Unknown"),
            severity=finding.get("severity", "info"),
            severity_upper=finding.get("severity", "info").upper(),
            owasp=owasp_id,
            owasp_name=OWASP_NAMES.get(owasp_id, "Unknown"),
            confidence=finding.get("confidence", "medium").title(),
            confidence_score=f"{float(finding.get('confidence_score', 0.5)):.2f}",
            source_type=finding.get("source_type", "unknown"),
            count=finding.get("count", 1),
            location=finding.get("location", "Unknown"),
            sample_locations_html=sample_locations_html,
            description=finding.get("description", ""),
            evidence=finding.get("evidence", "N/A"),
            remediation=finding.get("remediation", "Review this finding manually."),
        ))

    html = HTML_TEMPLATE.format(
        package_name=package_name,
        timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        score=score_data.get("score", 0),
        grade=score_data.get("grade", "F"),
        total_findings=report_data.get("total_findings", 0),
        risk_level=score_data.get("risk_level", "Unknown"),
        executive_summary=score_data.get("summary", "Report generated."),
        critical_count=severity.get("critical", 0),
        high_count=severity.get("high", 0),
        medium_count=severity.get("medium", 0),
        info_count=severity.get("info", 0),
        findings_html="\n".join(findings_html_parts),
    )

    return html


def generate_json_report(report_data: Dict[str, Any], package_name: str = "unknown") -> str:
    """Generate JSON report."""
    output = {
        "tool": "DroidSec",
        "version": "1.0.0",
        "timestamp": datetime.datetime.now().isoformat(),
        "package": package_name,
        "security_score": report_data.get("security_score"),
        "severity_breakdown": report_data.get("severity_breakdown"),
        "total_findings": report_data.get("total_findings"),
        "owasp_coverage": {
            k: {"name": v["name"], "count": v["count"], "max_severity": v["max_severity"]}
            for k, v in report_data.get("owasp_breakdown", {}).items()
        },
        "dedup_summary": report_data.get("dedup_summary", []),
        "findings": report_data.get("findings", []),
    }
    return json.dumps(output, indent=2, default=str)


def save_report(report_data: Dict[str, Any], output_dir: str, package_name: str = "unknown") -> Dict[str, str]:
    """Save HTML and JSON reports to disk. Returns paths."""
    os.makedirs(output_dir, exist_ok=True)

    html_path = os.path.join(output_dir, "report.html")
    json_path = os.path.join(output_dir, "report.json")

    html_content = generate_html_report(report_data, package_name)
    json_content = generate_json_report(report_data, package_name)

    with open(html_path, "w") as f:
        f.write(html_content)

    with open(json_path, "w") as f:
        f.write(json_content)

    return {"html": html_path, "json": json_path}
