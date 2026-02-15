"""
OWASP Mapper & Severity Scorer — aggregates findings, calculates security score.

Scoring Philosophy:
  - Legitimate, complex apps (Telegram, YouTube, etc.) with thousands of files
    will naturally have more findings due to sheer codebase size.
  - The score normalizes for app complexity so a large app isn't unfairly penalized
    for having proportionally the same issues as a small one.
  - Only *distinct* vulnerability types are penalized (duplicates get diminishing returns).
  - Low-confidence findings are heavily discounted.
  - Context-aware: info-level findings (logging, etc.) barely impact the score.
"""
from typing import List, Dict, Any
from collections import Counter, defaultdict
import hashlib
import math

OWASP_CATEGORIES = {
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

# Weights tuned for security triage realism:
# - Critical and high findings should materially impact score.
# - Medium findings still matter when repeated.
SEVERITY_WEIGHTS = {
    "critical": 20,
    "high": 12,
    "medium": 3,
    "info": 0,
}

# Confidence multipliers — discount uncertainty without neutralizing risk.
CONFIDENCE_MULTIPLIERS = {
    "high": 1.0,
    "medium": 0.7,
    "low": 0.35,
}

# Findings from third-party libraries should not dominate app-code scoring
# unless the category is explicitly supply-chain security (M2).
SOURCE_MULTIPLIERS = {
    "first_party": 1.0,
    "manifest": 1.0,
    "resource": 0.9,
    "smali_fallback": 0.95,
    "third_party": 0.35,
    "unknown": 0.8,
}

RULE_PENALTY_CAPS = {
    "critical": 28,
    "high": 20,
    "medium": 10,
    "info": 2,
}


def _stable_hash(value: str) -> str:
    return hashlib.sha1((value or "").encode("utf-8", errors="ignore")).hexdigest()[:16]


def _normalize_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    f = dict(finding or {})
    evidence = str(f.get("evidence", "") or "")
    confidence = str(f.get("confidence", "medium") or "medium").lower()
    confidence_score = f.get("confidence_score")
    if not isinstance(confidence_score, (int, float)):
        confidence_score = CONFIDENCE_MULTIPLIERS.get(confidence, 0.5)
    f["confidence"] = confidence
    f["confidence_score"] = max(0.05, min(1.0, float(confidence_score)))

    source_type = str(f.get("source_type", "first_party") or "first_party")
    f["source_type"] = source_type

    normalized_evidence = " ".join(evidence.lower().split())
    if "evidence_hash" not in f:
        f["evidence_hash"] = _stable_hash(f"{f.get('id', 'UNKNOWN')}|{normalized_evidence}")
    if "dedup_key" not in f:
        f["dedup_key"] = f"{f.get('id', 'UNKNOWN')}:{f['evidence_hash']}"
    return f


def calculate_security_score(findings: List[Dict], files_scanned: int = 0) -> Dict[str, Any]:
    """
    Calculate a 0–100 security score (100 = most secure, 0 = critically insecure).
    Uses:
      - Diminishing returns for duplicate findings
      - App-size normalization (large apps aren't unfairly penalized)
      - Confidence-weighted penalties
    """
    if not findings:
        return {
            "score": 95,
            "grade": "A",
            "risk_level": "Low",
            "summary": "No significant vulnerabilities detected.",
        }

    normalized_findings = [_normalize_finding(finding) for finding in findings]

    # Group by rule + dedup_key to avoid overweighting repeated equivalents.
    grouped = defaultdict(list)
    for f in normalized_findings:
        grouped[(f.get("id", "UNKNOWN"), f.get("dedup_key", ""))].append(f)

    rule_penalties = defaultdict(float)
    rule_caps = defaultdict(lambda: RULE_PENALTY_CAPS["medium"])
    for _, group in grouped.items():
        # Take the highest severity in the group
        best = max(group, key=lambda f: SEVERITY_WEIGHTS.get(f.get("severity", "info"), 0.5))
        weight = SEVERITY_WEIGHTS.get(best.get("severity", "info"), 0.5)
        confidence_mult = float(
            best.get(
                "confidence_score",
                CONFIDENCE_MULTIPLIERS.get(best.get("confidence", "medium"), 0.5),
            )
        )
        source_mult = SOURCE_MULTIPLIERS.get(best.get("source_type", "unknown"), 0.7)
        if best.get("owasp") == "M2" and best.get("source_type") == "third_party":
            source_mult = 1.0

        # Diminishing returns: 1 finding = 1.0x, 10 = ~2.3x, 100 = ~3.6x (not 100x!)
        count = len(group)
        effective_count = 1 + math.log2(count) if count > 1 else 1

        rule_id = str(best.get("id", "UNKNOWN"))
        penalty = weight * confidence_mult * source_mult * effective_count
        rule_penalties[rule_id] += penalty
        cap = RULE_PENALTY_CAPS.get(best.get("severity", "medium"), RULE_PENALTY_CAPS["medium"])
        rule_caps[rule_id] = max(rule_caps.get(rule_id, cap), cap)

    # Prevent a single noisy rule from dominating the entire score.
    total_penalty = sum(min(rule_penalties[rid], rule_caps[rid]) for rid in rule_penalties)

    # --- App-size normalization ---
    # Large apps naturally produce more findings. Keep normalization, but avoid over-softening.
    if files_scanned > 2000:
        divisor = 170
    elif files_scanned > 1000:
        divisor = 145
    elif files_scanned > 500:
        divisor = 120
    elif files_scanned > 100:
        divisor = 95
    else:
        divisor = 75

    # Score = 100 * e^(-penalty/divisor)
    raw_score = 100 * math.exp(-total_penalty / divisor)
    score = round(max(5, min(95, raw_score)))

    # Guardrails: critical or malware-centric behavior should not receive top grades.
    severity_rank = {"critical": 3, "high": 2, "medium": 1, "info": 0}
    unique_by_key = {}
    for f in normalized_findings:
        key = f.get("dedup_key") or f.get("id", "UNKNOWN")
        prev = unique_by_key.get(key)
        if not prev or severity_rank.get(f.get("severity", "info"), 0) > severity_rank.get(prev.get("severity", "info"), 0):
            unique_by_key[key] = f

    unique_findings = list(unique_by_key.values())
    critical_unique = sum(1 for f in unique_findings if f.get("severity") == "critical")
    high_unique = sum(1 for f in unique_findings if f.get("severity") == "high")
    malware_unique = [f for f in unique_findings if str(f.get("id", "")).upper().startswith("MAL")]
    malware_high = sum(1 for f in malware_unique if f.get("severity") in ("high", "critical"))

    if critical_unique >= 1:
        score = min(score, 68)
    if high_unique >= 6:
        score = min(score, 80)
    if malware_high >= 1:
        score = min(score, 72)
    if malware_high >= 2:
        score = min(score, 58)
    if malware_high >= 3 or (critical_unique >= 2 and malware_unique):
        score = min(score, 45)

    # Grade assignment
    if score >= 85:
        grade, risk_level = "A", "Low"
    elif score >= 70:
        grade, risk_level = "B", "Low-Medium"
    elif score >= 50:
        grade, risk_level = "C", "Medium"
    elif score >= 35:
        grade, risk_level = "D", "High"
    else:
        grade, risk_level = "F", "Critical"

    return {
        "score": score,
        "grade": grade,
        "risk_level": risk_level,
        "summary": _generate_summary(findings, score, grade),
    }


def _generate_summary(findings: List[Dict], score: int, grade: str) -> str:
    """Generate an executive summary paragraph."""
    total = len(findings)
    severity_counts = Counter(f["severity"] for f in findings)
    critical = severity_counts.get("critical", 0)
    high = severity_counts.get("high", 0)
    medium = severity_counts.get("medium", 0)

    parts = []
    if critical > 0:
        parts.append(f"{critical} critical")
    if high > 0:
        parts.append(f"{high} high")
    if medium > 0:
        parts.append(f"{medium} medium")

    severity_text = ", ".join(parts) if parts else "minor"

    if score < 30:
        verdict = "This application has severe security issues and should NOT be released without remediation."
    elif score < 50:
        verdict = "This application has significant security concerns that should be addressed before release."
    elif score < 70:
        verdict = "This application has moderate security issues. Review and fix recommended findings."
    elif score < 85:
        verdict = "This application has minor security concerns. Consider addressing the identified issues."
    else:
        verdict = "This application appears to be reasonably secure based on static analysis."

    return f"DroidSec identified {total} security findings ({severity_text} severity), resulting in a security score of {score}/100 (Grade {grade}). {verdict}"


def aggregate_findings(manifest_findings: List[Dict], code_findings: List[Dict],
                       permission_findings: List[Dict] = None,
                       malware_findings: List[Dict] = None,
                       files_scanned: int = 0) -> Dict[str, Any]:
    """
    Combine all findings, deduplicate, and calculate stats.
    """
    raw_findings = list(manifest_findings) + list(code_findings)
    if permission_findings:
        raw_findings.extend(permission_findings)
    if malware_findings:
        raw_findings.extend(malware_findings)
    raw_findings = [_normalize_finding(finding) for finding in raw_findings]

    # Calculation uses the full list + app size for normalization
    score_data = calculate_security_score(raw_findings, files_scanned=files_scanned)

    # --- Deduplication for display ---
    grouped = defaultdict(list)
    for f in raw_findings:
        key = (f.get("id", "UNKNOWN"), f.get("dedup_key", ""))
        grouped[key].append(f)

    clean_findings = []
    MAX_LOCATION_SAMPLES = 5
    for _, group in grouped.items():
        representative = dict(group[0])
        locations = []
        for finding in group:
            location = finding.get("location")
            if location and location not in locations:
                locations.append(location)
            if len(locations) >= MAX_LOCATION_SAMPLES:
                break

        representative["count"] = len(group)
        representative["sample_locations"] = locations
        if len(group) > 1:
            representative["location"] = "Various locations"
            representative["evidence"] = (
                f"{len(group)} instances grouped by dedup key; sample location: "
                f"{locations[0] if locations else 'unknown'}"
            )
        clean_findings.append(representative)

    # --- Per-rule cap: no single rule ID dominates the report ---
    MAX_DISPLAY_PER_RULE = 3
    severity_order = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    rule_groups = defaultdict(list)
    for f in clean_findings:
        rule_groups[f.get("id", "UNKNOWN")].append(f)

    capped_findings = []
    for rule_id, rule_findings in rule_groups.items():
        # Sort within rule group by severity then confidence (best first)
        rule_findings.sort(
            key=lambda f: (
                severity_order.get(f.get("severity", "info"), 3),
                -float(f.get("confidence_score", 0.5)),
            )
        )
        if len(rule_findings) <= MAX_DISPLAY_PER_RULE:
            capped_findings.extend(rule_findings)
        else:
            capped_findings.extend(rule_findings[:MAX_DISPLAY_PER_RULE])
            total_count = sum(f.get("count", 1) for f in rule_findings)
            shown_count = sum(f.get("count", 1) for f in rule_findings[:MAX_DISPLAY_PER_RULE])
            extra = total_count - shown_count
            if extra > 0:
                summary = dict(rule_findings[0])
                summary["name"] = f"{summary.get('name', rule_id)} (+{extra} more)"
                summary["severity"] = "info"
                summary["count"] = extra
                summary["location"] = "Various locations"
                summary["evidence"] = f"{extra} additional instances suppressed for brevity"
                capped_findings.append(summary)

    # Sort by severity
    capped_findings.sort(
        key=lambda f: (
            severity_order.get(f.get("severity", "info"), 3),
            -float(f.get("confidence_score", 0.5)),
        )
    )

    # OWASP breakdown
    owasp_breakdown = {}
    for cat_id, cat_name in OWASP_CATEGORIES.items():
        cat_findings = [f for f in capped_findings if f.get("owasp") == cat_id]
        owasp_breakdown[cat_id] = {
            "name": cat_name,
            "count": len([f for f in raw_findings if f.get("owasp") == cat_id]),
            "max_severity": _get_max_severity(cat_findings),
            "findings": cat_findings,
        }

    # Severity breakdown (use raw for totals)
    severity_breakdown = {
        "critical": len([f for f in raw_findings if f["severity"] == "critical"]),
        "high": len([f for f in raw_findings if f["severity"] == "high"]),
        "medium": len([f for f in raw_findings if f["severity"] == "medium"]),
        "info": len([f for f in raw_findings if f["severity"] == "info"]),
    }

    return {
        "total_findings": len(raw_findings),
        "unique_findings": len(capped_findings),
        "findings": capped_findings,
        "dedup_summary": capped_findings,
        "severity_breakdown": severity_breakdown,
        "owasp_breakdown": owasp_breakdown,
        "security_score": score_data,
    }


def _get_max_severity(findings: List[Dict]) -> str:
    """Get the highest severity from a list of findings."""
    if not findings:
        return "none"
    order = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    return min(findings, key=lambda f: order.get(f.get("severity", "info"), 3)).get("severity", "info")


def analyze_permissions(permissions: List[str]) -> List[Dict]:
    """Analyze permissions for privacy/security concerns."""
    from rules.permissions import DANGEROUS_PERMISSIONS

    findings = []
    dangerous_count = 0
    critical_perms = []

    for perm in permissions:
        if perm in DANGEROUS_PERMISSIONS:
            pdata = DANGEROUS_PERMISSIONS[perm]
            if pdata["severity"] != "info":
                dangerous_count += 1

            if pdata["severity"] == "critical":
                critical_perms.append(perm)
                findings.append({
                    "id": "PERM001",
                    "name": f"Critical Permission: {perm.split('.')[-1]}",
                    "severity": "high",
                    "confidence": "high",
                    "owasp": pdata["owasp"],
                    "location": "AndroidManifest.xml → <uses-permission>",
                    "evidence": perm,
                    "description": f"{pdata['description']} {pdata['risk']}",
                    "remediation": "Review if this permission is truly needed. Request at runtime and explain to users why it's required."
                })

    # Summary finding for dangerous permissions (informational)
    if dangerous_count > 0:
        severity = "info"
        if dangerous_count > 15:
            severity = "medium"
        elif dangerous_count > 10:
            severity = "info"

        findings.insert(0, {
            "id": "PERM002",
            "name": f"Dangerous Permissions Summary: {dangerous_count} found",
            "severity": severity,
            "confidence": "high",
            "owasp": "M6",
            "location": "AndroidManifest.xml",
            "evidence": f"{dangerous_count} dangerous permissions requested out of {len(permissions)} total",
            "description": f"The app requests {dangerous_count} permissions classified as 'dangerous' by Android. "
                           f"Each requires runtime approval from the user. A high count may indicate "
                           f"over-privileged access but is common in feature-rich applications.",
            "remediation": "Review each permission and remove those not essential to core functionality. "
                           "Follow the principle of least privilege."
        })

    return findings
