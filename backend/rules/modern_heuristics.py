"""
Modern logic-gated heuristics inspired by Chart_Researchh.md.
Implements static checks that combine multiple signals to reduce noisy findings.
"""
import os
import re
from typing import Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET


BASE_SCAN_EXTENSIONS = {
    ".java",
    ".kt",
    ".xml",
    ".json",
    ".properties",
    ".yml",
    ".yaml",
    ".cfg",
    ".conf",
}
SMALI_EXTENSIONS = {".smali"}

SKIP_DIR_SEGMENTS = {
    "/android/",
    "/androidx/",
    "/com/google/",
    "/com/facebook/",
    "/com/chartboost/",
    "/com/adjust/",
    "/com/appsflyer/",
    "/com/tencent/",
    "/com/huawei/",
    "/com/amazonaws/",
    "/com/unity3d/",
    "/com/adcolony/",
    "/com/vungle/",
    "/com/mopub/",
    "/com/ironsource/",
    "/com/paypal/",
    "/com/braintree/",
    "/okhttp3/",
    "/okio/",
    "/retrofit2/",
    "/kotlin/",
    "/kotlinx/",
    "/org/apache/",
}

ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _attr(element, name: str) -> Optional[str]:
    return element.get(f"{{{ANDROID_NS}}}{name}")


def _relative_path(path: str, base: str) -> str:
    try:
        return os.path.relpath(path, base)
    except ValueError:
        return path


def _line_for_offset(text: str, pos: int) -> int:
    return text[:pos].count("\n") + 1


def _snippet(text: str, line: int, radius: int = 2) -> str:
    lines = text.split("\n")
    start = max(0, line - 1 - radius)
    end = min(len(lines), line + radius)
    return "\n".join(lines[start:end])


def _tokenize_identifiers(text: str) -> List[str]:
    return re.findall(r"[A-Za-z_]\w*", text or "")


def _extract_tainted_assignments(content: str) -> Dict[str, int]:
    """
    Collect variable names that appear assigned from common external-input sources.
    """
    tainted: Dict[str, int] = {}
    source_pattern = re.compile(
        r"(getStringExtra|getByteArrayExtra|getExtras|getDataString|getQueryParameter|getLastPathSegment|getCharSequence)\s*\(",
        re.IGNORECASE,
    )
    assign_pattern = re.compile(
        r"^(?:\s*)(?:(?:final|val|var)\s+)?(?:[A-Za-z_][\w<>\[\],?]*\s+)?([A-Za-z_]\w*)\s*=\s*"
    )

    for line_no, raw_line in enumerate((content or "").splitlines(), start=1):
        line = raw_line.strip()
        if not line or not source_pattern.search(line):
            continue
        m = assign_pattern.search(line)
        if not m:
            continue
        var = (m.group(1) or "").strip()
        if var:
            tainted[var] = line_no
    return tainted


def _extract_call_expression(
    text: str,
    start: int,
    max_len: int = 420,
    open_paren_at: Optional[int] = None,
) -> str:
    """
    Return a best-effort balanced call expression starting at index `start`.
    Handles nested parentheses like Runtime.getRuntime().exec(cmd).
    """
    if start < 0 or start >= len(text):
        return ""
    chunk = text[start: min(len(text), start + max_len)]
    if open_paren_at is not None and start <= open_paren_at < (start + len(chunk)):
        open_idx = open_paren_at - start
    else:
        open_idx = chunk.find("(")
    if open_idx == -1:
        return chunk

    depth = 0
    for idx in range(open_idx, len(chunk)):
        ch = chunk[idx]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return chunk[:idx + 1]
    return chunk


def _has_java_sources(source_dirs: List[str]) -> bool:
    for source_dir in source_dirs or []:
        if not source_dir or not os.path.exists(source_dir):
            continue
        for _, _, filenames in os.walk(source_dir):
            for filename in filenames:
                if filename.endswith((".java", ".kt")):
                    return True
    return False


def _should_skip_dir(dirpath: str) -> bool:
    normalized = (dirpath or "").replace("\\", "/")
    for seg in SKIP_DIR_SEGMENTS:
        if seg in normalized:
            return True
    return False


def _is_third_party_rel_path(rel_path: str) -> bool:
    normalized = "/" + (rel_path or "").replace("\\", "/").lstrip("/")
    for seg in SKIP_DIR_SEGMENTS:
        if seg in normalized:
            return True
    return False


def _file_inventory(source_dirs: List[str], resource_dirs: Optional[List[str]] = None) -> List[Dict]:
    files = []
    scan_extensions = set(BASE_SCAN_EXTENSIONS)
    if not _has_java_sources(source_dirs or []):
        scan_extensions |= SMALI_EXTENSIONS

    scan_roots = list(source_dirs or [])
    if resource_dirs:
        scan_roots.extend(resource_dirs)

    for root_dir in scan_roots:
        if not root_dir or not os.path.exists(root_dir):
            continue
        for dirpath, dirnames, filenames in os.walk(root_dir):
            dirnames.sort()
            filenames.sort()
            if _should_skip_dir(dirpath):
                continue
            for filename in filenames:
                ext = os.path.splitext(filename)[1].lower()
                if ext not in scan_extensions:
                    continue
                path = os.path.join(dirpath, filename)
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue
                files.append(
                    {
                        "path": path,
                        "base": root_dir,
                        "rel": _relative_path(path, root_dir),
                        "content": content,
                        "lower": content.lower(),
                    }
                )
    return files


def analyze_modern_heuristics(
    source_dirs: List[str],
    manifest_path: Optional[str] = None,
    resource_dirs: Optional[List[str]] = None,
) -> List[Dict]:
    """
    Run logic-gated heuristics from research doc:
    - ADV-001/002/004/005
    - TAINT-001/002/003
    - CRYPTO-001
    - MAL-001..004
    - NATIVE-001..003
    """
    files = _file_inventory(source_dirs, resource_dirs)
    findings: List[Dict] = []
    seen = set()
    app_package: Optional[str] = None
    app_pkg_path: Optional[str] = None

    if manifest_path and os.path.exists(manifest_path):
        try:
            _mtree = ET.parse(manifest_path)
            _mroot = _mtree.getroot()
            app_package = _mroot.get("package")
            if app_package:
                app_pkg_path = app_package.replace(".", "/")
        except Exception:
            pass

    def add_finding(data: Dict):
        key = (
            data.get("id", "UNK"),
            data.get("location", "unknown"),
            (data.get("evidence", "") or "")[:120],
        )
        if key in seen:
            return
        seen.add(key)
        findings.append(data)

    def related_files_for_component(component_name: str) -> List[Dict]:
        """
        Best-effort linkage from manifest component names to decompiled source files.
        """
        simple = (component_name or "").split(".")[-1]
        if not simple:
            return []

        out: List[Dict] = []
        java_name = f"{simple}.java"
        kt_name = f"{simple}.kt"
        smali_name = f"{simple}.smali"
        class_pat = re.compile(rf"\bclass\s+{re.escape(simple)}\b")
        kotlin_obj_pat = re.compile(rf"\bobject\s+{re.escape(simple)}\b")

        for f in files:
            rel_lower = f["rel"].lower()
            if (
                rel_lower.endswith("/" + java_name.lower())
                or rel_lower.endswith("/" + kt_name.lower())
                or rel_lower.endswith("/" + smali_name.lower())
            ):
                out.append(f)
                continue
            c = f["content"]
            if class_pat.search(c) or kotlin_obj_pat.search(c):
                out.append(f)

        return out

    def is_first_party_path(rel_path: str) -> bool:
        rel_norm = (rel_path or "").replace("\\", "/")
        if not app_pkg_path:
            return not _is_third_party_rel_path(rel_norm)
        return (
            rel_norm.startswith(app_pkg_path + "/")
            or rel_norm.startswith("sources/" + app_pkg_path + "/")
            or ("/" + app_pkg_path + "/") in rel_norm
        )

    def resolve_accessibility_config(resource_ref: str) -> Optional[Dict[str, bool]]:
        """
        Parse accessibility-service XML reference like @xml/my_service_config.
        Returns capability flags when available.
        """
        if not resource_ref or not resource_ref.startswith("@xml/"):
            return None

        xml_name = resource_ref.split("/", 1)[-1].strip()
        if not xml_name:
            return None

        target_suffixes = (
            f"/res/xml/{xml_name}.xml",
            f"/xml/{xml_name}.xml",
            f"res/xml/{xml_name}.xml",
            f"xml/{xml_name}.xml",
        )
        candidate = None
        for f in files:
            rel_norm = f["rel"].replace("\\", "/")
            if rel_norm.endswith(target_suffixes):
                candidate = f
                break

        if not candidate:
            return None

        text = candidate["content"]
        lower = candidate["lower"]
        return {
            "window_content": bool(
                re.search(r"canRetrieveWindowContent\s*=\s*[\"']true[\"']", text, re.IGNORECASE)
            )
            or "canretrievewindowcontent=\"true\"" in lower,
            "broad_events": bool(
                re.search(r"TYPE_VIEW_TEXT_CHANGED|TYPE_WINDOW_CONTENT_CHANGED|TYPE_WINDOW_STATE_CHANGED", text)
            )
            or ("type_view_text_changed" in lower or "type_window_content_changed" in lower),
        }

    # -----------------------------------------------------------------
    # ADV-001 / ADV-002 - Biometric auth misconfigurations
    # -----------------------------------------------------------------
    biometric_auth_single = re.compile(r"BiometricPrompt\s*\.\s*authenticate\s*\(\s*[^,\)\n]+\s*\)", re.MULTILINE)
    biometric_auth_with_crypto = re.compile(
        r"BiometricPrompt\s*\.\s*authenticate\s*\(\s*[^,\)\n]+\s*,\s*[^\)]+\)", re.MULTILINE
    )
    biometric_success_cb = re.compile(r"onAuthenticationSucceeded\s*\(")
    privileged_gate_ops = re.compile(
        r"setAuthenticated\s*\(\s*true\s*\)|putBoolean\s*\(\s*['\"]logged_in['\"]\s*,\s*true\s*\)|"
        r"openVault|unlock|startActivity\s*\(|navigate|approveTransfer|confirmPayment|withdraw",
        re.IGNORECASE,
    )
    weak_authenticator = re.compile(r"setAllowedAuthenticators\s*\([^\)]*(DEVICE_CREDENTIAL|BIOMETRIC_WEAK)", re.MULTILINE)
    high_risk_flow = re.compile(r"transfer|payment|withdraw|approve|bank|wallet|password|otp|identity", re.IGNORECASE)

    for f in files:
        content = f["content"]
        rel = f["rel"]

        m_single = biometric_auth_single.search(content)
        has_crypto_overload = bool(biometric_auth_with_crypto.search(content))
        has_success_cb = bool(biometric_success_cb.search(content))
        has_privileged_action = bool(privileged_gate_ops.search(content))

        if m_single and not has_crypto_overload and has_success_cb and has_privileged_action:
            line = _line_for_offset(content, m_single.start())
            add_finding(
                {
                    "id": "ADV001",
                    "name": "Biometric Authentication Without CryptoObject Binding",
                    "severity": "high",
                    "confidence": "medium",
                    "owasp": "M3",
                    "location": f"{rel}:{line}",
                    "file": rel,
                    "line": line,
                    "evidence": m_single.group(0)[:180],
                    "context": _snippet(content, line),
                    "description": "BiometricPrompt.authenticate(...) is used without CryptoObject while privileged actions run in onAuthenticationSucceeded. This can behave like a boolean gate and is easier to bypass in compromised environments.",
                    "remediation": "Use authenticate(promptInfo, CryptoObject) with Android Keystore-backed keys and bind the protected operation to cryptographic proof.",
                }
            )

        for m in weak_authenticator.finditer(content):
            if not high_risk_flow.search(content):
                continue
            line = _line_for_offset(content, m.start())
            add_finding(
                {
                    "id": "ADV002",
                    "name": "Weak Biometric Authenticator Policy on High-Risk Flow",
                    "severity": "medium",
                    "confidence": "medium",
                    "owasp": "M3",
                    "location": f"{rel}:{line}",
                    "file": rel,
                    "line": line,
                    "evidence": m.group(0)[:180],
                    "context": _snippet(content, line),
                    "description": "High-risk workflow appears to allow DEVICE_CREDENTIAL/BIOMETRIC_WEAK fallback. This lowers assurance for sensitive actions.",
                    "remediation": "Prefer BIOMETRIC_STRONG plus CryptoObject for sensitive actions. Use separate step-up auth flows instead of weak fallback.",
                }
            )

    # -----------------------------------------------------------------
    # ADV-004 - Dynamic receiver exposure without permission requirement
    # -----------------------------------------------------------------
    dyn_receiver_call = re.compile(r"(?:ContextCompat\s*\.\s*)?registerReceiver\s*\(", re.MULTILINE)
    custom_action = re.compile(
        r"IntentFilter\s*\(\s*[\"']com\.[A-Za-z0-9_.-]+[\"']\s*\)|"
        r"addAction\s*\(\s*[\"']com\.[A-Za-z0-9_.-]+[\"']\s*\)|"
        r"[\"']com\.[A-Za-z0-9_.-]+[\"']"
    )
    sensitive_on_receive = re.compile(
        r"startService\s*\(|startActivity\s*\(|sendTextMessage\s*\(|Runtime\.getRuntime\(\)\.exec|"
        r"SharedPreferences|commit\s*\(|apply\s*\(|write\s*\(",
        re.IGNORECASE,
    )
    receiver_sensitive_callback = re.compile(
        r"onReceive\s*\([^\)]*\)\s*\{[\s\S]{0,700}?"
        r"(startService\s*\(|startActivity\s*\(|sendTextMessage\s*\(|Runtime\.getRuntime\(\)\.exec|"
        r"SharedPreferences|commit\s*\(|apply\s*\(|write\s*\()",
        re.IGNORECASE,
    )

    for f in files:
        content = f["content"]
        rel = f["rel"]
        for m in dyn_receiver_call.finditer(content):
            line = _line_for_offset(content, m.start())
            local_context = _snippet(content, line, radius=18)
            if not custom_action.search(local_context):
                continue

            call_preview = _extract_call_expression(content, m.start(), max_len=520, open_paren_at=m.end() - 1)
            comma_count = call_preview.count(",")
            has_literal_permission = bool(
                re.search(r"registerReceiver\s*\([^\)]*,\s*[^\)]*,\s*[\"'][^\"']+[\"']", call_preview)
            )
            has_null_permission = bool(
                re.search(r"registerReceiver\s*\([^\)]*,\s*[^\)]*,\s*null\b", call_preview)
            )
            receiver_not_exported = "RECEIVER_NOT_EXPORTED" in call_preview

            missing_permission_guard = (comma_count <= 1) or has_null_permission
            if has_literal_permission and not has_null_permission:
                missing_permission_guard = False
            if receiver_not_exported and not has_null_permission and has_literal_permission:
                missing_permission_guard = False
            if not missing_permission_guard:
                continue

            local_sensitive = bool(sensitive_on_receive.search(local_context))
            callback_sensitive = bool(receiver_sensitive_callback.search(content))
            if not (local_sensitive or callback_sensitive):
                continue

            add_finding(
                {
                    "id": "ADV004",
                    "name": "Dynamic Broadcast Receiver Without Permission Guard",
                    "severity": "medium",
                    "confidence": "high" if local_sensitive else "medium",
                    "owasp": "M8",
                    "location": f"{rel}:{line}",
                    "file": rel,
                    "line": line,
                    "evidence": call_preview[:200],
                    "context": _snippet(content, line),
                    "description": "A dynamically registered receiver appears to accept custom broadcasts without a required sender permission, and the code handles sensitive actions.",
                    "remediation": "Use registerReceiver overloads with required permission and RECEIVER_NOT_EXPORTED where possible.",
                }
            )

    # -----------------------------------------------------------------
    # ADV-005 - ContentProvider SQL injection heuristics
    # -----------------------------------------------------------------
    provider_marker = re.compile(r"extends\s+ContentProvider|\bContentProvider\b")
    provider_sqli_patterns = [
        re.compile(r"rawQuery\s*\(\s*\"[^\"]*\"\s*\+\s*", re.MULTILINE),
        re.compile(r"execSQL\s*\(\s*\"[^\"]*\"\s*\+\s*", re.MULTILINE),
        re.compile(r"(?:query|update|delete)\s*\([^\)]*,\s*[^\)]*,\s*\"[^\"]*\"\s*\+\s*", re.MULTILINE),
        re.compile(r"appendWhere\s*\(\s*\"[^\"]*\"\s*\+\s*", re.MULTILINE),
    ]

    for f in files:
        content = f["content"]
        rel = f["rel"]
        if not provider_marker.search(content):
            continue
        for patt in provider_sqli_patterns:
            for m in patt.finditer(content):
                line = _line_for_offset(content, m.start())
                add_finding(
                    {
                        "id": "ADV005",
                        "name": "Potential SQL Injection in ContentProvider",
                        "severity": "high",
                        "confidence": "medium",
                        "owasp": "M4",
                        "location": f"{rel}:{line}",
                        "file": rel,
                        "line": line,
                        "evidence": m.group(0)[:200],
                        "context": _snippet(content, line),
                        "description": "SQL query construction appears to concatenate untrusted input in a ContentProvider path, which can enable SQL injection.",
                        "remediation": "Use parameterized selection clauses (e.g., selectionArgs with '?') and avoid string concatenation in SQL statements.",
                    }
                )

    # -----------------------------------------------------------------
    # TAINT-001/002/003
    # -----------------------------------------------------------------
    taint_sources = re.compile(
        r"getStringExtra\s*\(|getByteArrayExtra\s*\(|getExtras\s*\(|getDataString\s*\(|getQueryParameter\s*\(|getLastPathSegment\s*\("
    )
    exec_sinks = re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\(|new\s+ProcessBuilder\s*\(")

    ui_sources = re.compile(r"EditText|TextView|getText\s*\(\)\s*\.\s*toString\s*\(")
    ui_assignment = re.compile(
        r"(?:^|[;\s])(?:final\s+)?(?:[A-Za-z_][\w<>\[\],?\s]*\s+)?([A-Za-z_]\w*)\s*=\s*[^;\n]{0,220}"
        r"(?:getText\s*\(\)\s*\.\s*toString\s*\(|findViewById\s*<\s*EditText\s*>|EditText|TextView)",
        re.IGNORECASE,
    )
    webview_sinks = re.compile(r"WebView\s*\.\s*(?:loadUrl|evaluateJavascript|loadDataWithBaseURL)\s*\(|\.loadUrl\s*\(")
    risky_webview = re.compile(r"setJavaScriptEnabled\s*\(\s*true\s*\)|addJavascriptInterface\s*\(")

    pii_keywords = re.compile(r"token|otp|password|secret|credential|auth|session|credit|ssn", re.IGNORECASE)
    sensitive_var_names = re.compile(
        r"token|otp|pass|pwd|secret|auth|session|cookie|credit|card|ssn|jwt|api|email|phone",
        re.IGNORECASE,
    )
    non_sensitive_log_hints = re.compile(
        r"without extras|unable to access|unexpected|ignoring|analytics data|unrecognized action",
        re.IGNORECASE,
    )
    log_sinks = re.compile(r"\bLog\s*\.\s*[divew]\s*\(")
    notification_source = re.compile(
        r"onNotificationPosted\s*\(|notification\s*\.\s*extras|getCharSequence\s*\(\s*['\"]android\.text['\"]"
    )
    notification_assignment = re.compile(
        r"(?:^|[;\s])(?:final\s+)?(?:[A-Za-z_][\w<>\[\],?\s]*\s+)?([A-Za-z_]\w*)\s*=\s*[^;\n]{0,240}"
        r"(?:notification\s*\.\s*extras|getCharSequence\s*\(\s*['\"]android\.(?:text|title)['\"])",
        re.IGNORECASE,
    )

    for f in files:
        content = f["content"]
        rel = f["rel"]
        tainted_vars = _extract_tainted_assignments(content)
        for nm in notification_assignment.finditer(content):
            tainted_vars[(nm.group(1) or "").strip()] = _line_for_offset(content, nm.start())

        # TAINT-001: require source-to-sink linkage in nearby context.
        for m in exec_sinks.finditer(content):
            line = _line_for_offset(content, m.start())
            call_preview = _extract_call_expression(content, m.start(), max_len=320, open_paren_at=m.end() - 1)
            direct_source = bool(taint_sources.search(call_preview))
            token_set = set(_tokenize_identifiers(call_preview))
            linked_vars = [
                var for var, source_line in tainted_vars.items()
                if var in token_set and abs(line - source_line) <= 30
            ]
            if not direct_source and not linked_vars:
                continue

            add_finding(
                {
                    "id": "TAINT001",
                    "name": "Intent/URI Input Reaches Command Execution API",
                    "severity": "high",
                    "confidence": "high" if direct_source else "medium",
                    "owasp": "M4",
                    "location": f"{rel}:{line}",
                    "file": rel,
                    "line": line,
                    "evidence": call_preview[:200] + (f" | vars={','.join(linked_vars[:3])}" if linked_vars else ""),
                    "context": _snippet(content, line),
                    "description": "Potential taint flow from external component input (Intent/URI) to Runtime.exec/ProcessBuilder sink.",
                    "remediation": "Avoid shell execution for untrusted input. Validate via strict allowlists before invoking command/process APIs.",
                }
            )

        # TAINT-002: require UI source linkage to WebView sink.
        ui_vars: Dict[str, int] = {}
        for um in ui_assignment.finditer(content):
            ui_vars[(um.group(1) or "").strip()] = _line_for_offset(content, um.start())

        if ui_sources.search(content):
            for m in webview_sinks.finditer(content):
                line = _line_for_offset(content, m.start())
                call_preview = _extract_call_expression(content, m.start(), max_len=320, open_paren_at=m.end() - 1)
                direct_ui_source = bool(re.search(r"getText\s*\(\)\s*\.\s*toString\s*\(", call_preview))
                token_set = set(_tokenize_identifiers(call_preview))
                linked_ui_vars = [
                    var for var, source_line in ui_vars.items()
                    if var in token_set and abs(line - source_line) <= 30
                ]
                if not direct_ui_source and not linked_ui_vars:
                    continue

                has_risky_webview = bool(risky_webview.search(_snippet(content, line, radius=10)) or risky_webview.search(content))
                severity = "high" if has_risky_webview else "medium"
                add_finding(
                    {
                        "id": "TAINT002",
                        "name": "Potential User Input Flow Into WebView Sink",
                        "severity": severity,
                        "confidence": "high" if direct_ui_source else "medium",
                        "owasp": "M4",
                        "location": f"{rel}:{line}",
                        "file": rel,
                        "line": line,
                        "evidence": call_preview[:200] + (f" | vars={','.join(linked_ui_vars[:3])}" if linked_ui_vars else ""),
                        "context": _snippet(content, line),
                        "description": "User-controlled text may reach WebView load/eval sinks. If not constrained to trusted URLs, this can introduce content injection risk.",
                        "remediation": "Enforce https allowlists before loading URLs. Disable JavaScript and JS interfaces unless strictly required.",
                    }
                )

        # TAINT-003: focus on log statements that include sensitive literals or tainted vars.
        for m in log_sinks.finditer(content):
            if not is_first_party_path(rel):
                continue
            line = _line_for_offset(content, m.start())
            call_preview = _extract_call_expression(content, m.start(), max_len=280, open_paren_at=m.end() - 1)
            sensitive_literal = bool(pii_keywords.search(call_preview))
            token_set = set(_tokenize_identifiers(call_preview))
            linked_vars = [
                var for var, source_line in tainted_vars.items()
                if var in token_set and abs(line - source_line) <= 80
            ]
            sensitive_linked_vars = [v for v in linked_vars if sensitive_var_names.search(v)]
            nearby_source = bool(
                taint_sources.search(_snippet(content, line, radius=8))
                or notification_source.search(_snippet(content, line, radius=8))
            )
            if not (sensitive_literal or sensitive_linked_vars):
                continue
            if not (sensitive_linked_vars or nearby_source):
                continue
            if non_sensitive_log_hints.search(call_preview) and not sensitive_linked_vars:
                continue

            add_finding(
                {
                    "id": "TAINT003",
                    "name": "Potential Sensitive Data Logging",
                    "severity": "medium",
                    "confidence": "high" if linked_vars else "medium",
                    "owasp": "M6",
                    "location": f"{rel}:{line}",
                    "file": rel,
                    "line": line,
                    "evidence": call_preview[:200] + (f" | vars={','.join(sensitive_linked_vars[:3])}" if sensitive_linked_vars else ""),
                    "context": _snippet(content, line),
                    "description": "Sensitive values sourced from intents/notifications appear to be logged. Logs can leak data in debug/rooted or forensic scenarios.",
                    "remediation": "Never log tokens/OTP/password/session data. Redact or remove sensitive fields from all logging paths.",
                }
            )

    # -----------------------------------------------------------------
    # CRYPTO-001 - Broken X509TrustManager checks
    # -----------------------------------------------------------------
    trust_manager_decl = re.compile(r"implements\s+X509TrustManager|new\s+X509TrustManager\s*\(")
    empty_check_server = re.compile(
        r"checkServerTrusted\s*\([^\)]*\)\s*\{\s*(?:/\*.*?\*/\s*)?(?:return\s*;)?\s*\}",
        re.DOTALL,
    )
    catch_cert_in_check = re.compile(
        r"checkServerTrusted\s*\([^\)]*\)\s*\{[\s\S]*?catch\s*\(\s*CertificateException[^\)]*\)",
        re.DOTALL,
    )
    cert_catch_rethrows = re.compile(
        r"catch\s*\(\s*CertificateException[^\)]*\)\s*\{[^}]*throw",
        re.DOTALL,
    )
    accepted_issuers_empty = re.compile(
        r"getAcceptedIssuers\s*\(\s*\)\s*\{\s*return\s+new\s+X509Certificate\s*\[\s*0\s*\]\s*;\s*\}",
        re.DOTALL,
    )
    trust_manager_use = re.compile(
        r"new\s+TrustManager\s*\[\s*\]|setSSLSocketFactory\s*\(|\.sslSocketFactory\s*\(|HostnameVerifier|X509TrustManager",
        re.IGNORECASE,
    )

    for f in files:
        content = f["content"]
        rel = f["rel"]
        if not trust_manager_decl.search(content):
            continue
        for m in empty_check_server.finditer(content):
            if not trust_manager_use.search(content):
                continue
            line = _line_for_offset(content, m.start())
            add_finding(
                {
                    "id": "CRY011",
                    "name": "Unsafe X509TrustManager (Trust-All Behavior)",
                    "severity": "critical",
                    "confidence": "high",
                    "owasp": "M5",
                    "location": f"{rel}:{line}",
                    "file": rel,
                    "line": line,
                    "evidence": "checkServerTrusted() appears empty / no-op",
                    "context": _snippet(content, line),
                    "description": "Custom X509TrustManager appears to skip certificate validation, enabling TLS interception (MITM).",
                    "remediation": "Use system trust validation or Network Security Config. Do not ship trust-all certificate logic.",
                }
            )

        for m in catch_cert_in_check.finditer(content):
            if not trust_manager_use.search(content):
                continue
            if cert_catch_rethrows.search(content):
                continue
            line = _line_for_offset(content, m.start())
            add_finding(
                {
                    "id": "CRY012",
                    "name": "CertificateException Suppressed in checkServerTrusted",
                    "severity": "critical",
                    "confidence": "high",
                    "owasp": "M5",
                    "location": f"{rel}:{line}",
                    "file": rel,
                    "line": line,
                    "evidence": "checkServerTrusted catches CertificateException without fail-closed throw path",
                    "context": _snippet(content, line),
                    "description": "Certificate-validation exceptions appear to be swallowed, which can effectively allow invalid server certificates.",
                    "remediation": "Fail closed on CertificateException and rely on platform trust-chain validation.",
                }
            )

        for m in accepted_issuers_empty.finditer(content):
            if not trust_manager_use.search(content):
                continue
            line = _line_for_offset(content, m.start())
            add_finding(
                {
                    "id": "CRY013",
                    "name": "Suspicious Empty Accepted Issuers in TrustManager",
                    "severity": "high",
                    "confidence": "medium",
                    "owasp": "M5",
                    "location": f"{rel}:{line}",
                    "file": rel,
                    "line": line,
                    "evidence": "getAcceptedIssuers returns empty certificate array",
                    "context": _snippet(content, line),
                    "description": "getAcceptedIssuers() returning an empty array is a common trait in trust-all TrustManager implementations.",
                    "remediation": "Use standard trust manager implementations from TrustManagerFactory unless there is a strict, validated pinning strategy.",
                }
            )

    # Smali fallback variant for unsafe TLS bypass patterns.
    smali_check_server_method = re.compile(
        r"\.method[^\n]*checkServerTrusted\([^\n]*\n([\s\S]{0,1600}?)\.end method",
        re.IGNORECASE,
    )
    smali_hostname_verify_method = re.compile(
        r"\.method[^\n]*verify\(Ljava/lang/String;Ljavax/net/ssl/SSLSession;\)Z[\s\S]{0,1400}?\.end method",
        re.IGNORECASE,
    )

    def _is_noop_smali_method(method_body: str) -> bool:
        instructions = []
        for raw in (method_body or "").splitlines():
            line = raw.strip()
            if not line or line.startswith((".", "#", ":", ".line", ".param", ".local", ".prologue")):
                continue
            instructions.append(line)
        if not instructions:
            return True
        return all(inst.startswith("return-void") for inst in instructions)

    def _is_always_true_hostname_verifier(method_text: str) -> bool:
        if not method_text:
            return False
        if re.search(r"const(?:/4|/16)?\s+v\d+,\s+0x1", method_text) and re.search(r"return\s+v\d+", method_text):
            return True
        return False

    for f in files:
        rel = f["rel"]
        if not rel.endswith(".smali") or not is_first_party_path(rel):
            continue

        content = f["content"]
        for m in smali_check_server_method.finditer(content):
            body = m.group(1) or ""
            if not _is_noop_smali_method(body):
                continue
            line = _line_for_offset(content, m.start())
            add_finding(
                {
                    "id": "CRY011",
                    "name": "Unsafe X509TrustManager (Trust-All Behavior)",
                    "severity": "critical",
                    "confidence": "high",
                    "owasp": "M5",
                    "location": f"{rel}:{line}",
                    "file": rel,
                    "line": line,
                    "evidence": "smali checkServerTrusted() appears empty / no-op",
                    "context": _snippet(content, line),
                    "description": "Smali implementation indicates a TrustManager method that effectively skips certificate validation.",
                    "remediation": "Use default platform trust validation and remove trust-all TLS logic.",
                }
            )

        for m in smali_hostname_verify_method.finditer(content):
            method_text = m.group(0) or ""
            if not _is_always_true_hostname_verifier(method_text):
                continue
            line = _line_for_offset(content, m.start())
            add_finding(
                {
                    "id": "CRY014",
                    "name": "HostnameVerifier Always Returns True",
                    "severity": "critical",
                    "confidence": "high",
                    "owasp": "M5",
                    "location": f"{rel}:{line}",
                    "file": rel,
                    "line": line,
                    "evidence": "smali verify(host, session) returns constant true",
                    "context": _snippet(content, line),
                    "description": "Hostname verification appears bypassed by always returning true, enabling MITM attacks.",
                    "remediation": "Remove permissive HostnameVerifier implementations and rely on strict hostname validation.",
                }
            )

    # -----------------------------------------------------------------
    # NATIVE-001/002/003
    # -----------------------------------------------------------------
    native_load_path = re.compile(r"(?:System\.load|Runtime\.getRuntime\(\)\.load)\s*\(\s*([^\)]+)\)")
    dangerous_path_hint = re.compile(r"/sdcard|/storage|/download|/tmp|getExternalStorageDirectory|getExternalFilesDir", re.IGNORECASE)

    dynamic_loadlibrary = re.compile(r"System\.loadLibrary\s*\(\s*[^\"'\)]+\s*\)")
    dex_loader_hint = re.compile(r"DexClassLoader|PathClassLoader|BaseDexClassLoader")
    loadlib_obfuscation_hint = re.compile(
        r"decrypt|Base64|Cipher|xor|Class\.forName|Method\.invoke|getDeclaredMethod|reflection",
        re.IGNORECASE,
    )
    loadlib_early_lifecycle = re.compile(r"onCreate\s*\(|attachBaseContext\s*\(|Application\b", re.IGNORECASE)

    native_decl_patterns = [
        re.compile(r"\bnative\s+[\w\<\>\[\],\s]+\s+([A-Za-z_]\w*)\s*\(([^\)]*)\)"),
        re.compile(r"\bexternal\s+native\s+fun\s+([A-Za-z_]\w*)\s*\(([^\)]*)\)"),
    ]
    untrusted_input = re.compile(
        r"getStringExtra\s*\(|getByteArrayExtra\s*\(|getExtras\s*\(|getDataString\s*\(|getQueryParameter\s*\(|"
        r"getCharSequence\s*\(\s*['\"]android\.text['\"]|event\s*\.\s*getText\s*\(",
        re.IGNORECASE,
    )

    for f in files:
        content = f["content"]
        rel = f["rel"]
        tainted_vars = _extract_tainted_assignments(content)

        for m in native_load_path.finditer(content):
            arg = (m.group(1) or "").strip()
            if not dangerous_path_hint.search(content) and not dangerous_path_hint.search(arg):
                continue
            line = _line_for_offset(content, m.start())
            add_finding(
                {
                    "id": "NATIVE001",
                    "name": "Native Library Loaded From Potentially Untrusted Path",
                    "severity": "high",
                    "confidence": "medium",
                    "owasp": "M7",
                    "location": f"{rel}:{line}",
                    "file": rel,
                    "line": line,
                    "evidence": m.group(0)[:220],
                    "context": _snippet(content, line),
                    "description": "System.load/Runtime.load appears to use a path that may be attacker-influenced (external/writable location).",
                    "remediation": "Load native libraries only from trusted app-private directories and enforce integrity checks before loading.",
                }
            )

        for m in dynamic_loadlibrary.finditer(content):
            has_contextual_risk = bool(
                dex_loader_hint.search(content)
                or loadlib_obfuscation_hint.search(content)
                or loadlib_early_lifecycle.search(_snippet(content, _line_for_offset(content, m.start()), radius=8))
            )
            if not has_contextual_risk:
                continue

            line = _line_for_offset(content, m.start())
            risk_signals = 0
            risk_signals += 1 if dex_loader_hint.search(content) else 0
            risk_signals += 1 if loadlib_obfuscation_hint.search(content) else 0
            risk_signals += 1 if loadlib_early_lifecycle.search(_snippet(content, line, radius=8)) else 0
            severity = "high" if risk_signals >= 2 else "medium"
            add_finding(
                {
                    "id": "NATIVE002",
                    "name": "Suspicious Dynamic System.loadLibrary Usage",
                    "severity": severity,
                    "confidence": "medium" if risk_signals >= 2 else "low",
                    "owasp": "M7",
                    "location": f"{rel}:{line}",
                    "file": rel,
                    "line": line,
                    "evidence": m.group(0)[:220],
                    "context": _snippet(content, line),
                    "description": "System.loadLibrary is called with a non-literal value, increasing dynamic loading attack surface.",
                    "remediation": "Use explicit constant library names and minimize dynamic loading behavior in production builds.",
                }
            )

        native_methods: List[str] = []
        for decl_pat in native_decl_patterns:
            native_methods.extend([m.group(1) for m in decl_pat.finditer(content)])
        if native_methods and untrusted_input.search(content):
            for nm in native_methods:
                call_pattern = re.compile(rf"\b{re.escape(nm)}\s*\(([^\)]*)\)")
                for cm in call_pattern.finditer(content):
                    before = content[max(0, cm.start() - 30):cm.start()]
                    # Skip declaration site itself.
                    if "native" in before:
                        continue

                    line = _line_for_offset(content, cm.start())
                    args = cm.group(1) or ""
                    direct_taint = bool(untrusted_input.search(args))
                    arg_tokens = set(_tokenize_identifiers(args))
                    linked_vars = [
                        var for var, source_line in tainted_vars.items()
                        if var in arg_tokens and abs(line - source_line) <= 60
                    ]
                    if not direct_taint and not linked_vars:
                        continue

                    add_finding(
                        {
                            "id": "NATIVE003",
                            "name": "Untrusted Input May Reach Native Method",
                            "severity": "medium",
                            "confidence": "medium" if linked_vars or direct_taint else "low",
                            "owasp": "M4",
                            "location": f"{rel}:{line}",
                            "file": rel,
                            "line": line,
                            "evidence": (
                                f"native call '{nm}(...)' receives untrusted-like input"
                                + (f" | vars={','.join(linked_vars[:3])}" if linked_vars else "")
                            ),
                            "context": _snippet(content, line),
                            "description": "Untrusted input appears to flow into JNI/native method arguments. Memory-unsafe native parsing can increase exploitability.",
                            "remediation": "Validate and bound-check all external input before passing data into JNI/native methods.",
                        }
                    )

    # -----------------------------------------------------------------
    # MAL-001..004 - Accessibility and Notification service abuse signals
    # -----------------------------------------------------------------
    if manifest_path and os.path.exists(manifest_path):
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            app = root.find("application")
        except Exception:
            app = None

        if app is not None:
            # ADV-003: exported receiver + no sender permission + sensitive behavior.
            protected_receiver_actions = {
                "android.intent.action.BOOT_COMPLETED",
                "android.intent.action.LOCKED_BOOT_COMPLETED",
                "android.intent.action.MY_PACKAGE_REPLACED",
                "android.intent.action.PACKAGE_REPLACED",
                "android.intent.action.PACKAGE_ADDED",
                "android.intent.action.PACKAGE_REMOVED",
                "android.intent.action.PACKAGE_CHANGED",
                "android.net.conn.CONNECTIVITY_CHANGE",
                "android.intent.action.ACTION_POWER_CONNECTED",
                "android.intent.action.ACTION_POWER_DISCONNECTED",
                "android.intent.action.USER_PRESENT",
                "android.intent.action.TIME_SET",
                "android.intent.action.TIMEZONE_CHANGED",
                "android.intent.action.ACTION_SHUTDOWN",
            }
            receiver_on_receive = re.compile(r"onReceive\s*\(", re.IGNORECASE)
            sensitive_receiver_behavior = re.compile(
                r"startService\s*\(|startActivity\s*\(|sendBroadcast\s*\(|"
                r"sendTextMessage\s*\(|Runtime\.getRuntime\(\)\.exec\s*\(|SharedPreferences|putExtra\s*\(|"
                r"WorkManager|enqueue\s*\(|NotificationManager|\.cancel\s*\(",
                re.IGNORECASE,
            )

            for receiver in app.iter("receiver"):
                rcv_name = _attr(receiver, "name") or "unknown"
                exported = _attr(receiver, "exported")
                permission = _attr(receiver, "permission")
                has_intent_filter = receiver.find("intent-filter") is not None
                is_exported = exported == "true" or (exported is None and has_intent_filter)
                if not is_exported or permission:
                    continue

                actions: List[str] = []
                for intent in receiver.findall("intent-filter"):
                    for action in intent.findall("action"):
                        act_name = _attr(action, "name") or ""
                        if act_name:
                            actions.append(act_name)
                custom_actions = [a for a in actions if not a.startswith("android.")]
                if actions and all(a in protected_receiver_actions for a in actions):
                    continue

                # Check whether corresponding class appears to perform sensitive behavior.
                receiver_files = related_files_for_component(rcv_name)
                scan_pool = receiver_files if receiver_files else files
                behavior_hit: Optional[Tuple[str, int, str]] = None
                for f in scan_pool:
                    content = f["content"]
                    on_receive_positions = [m.start() for m in receiver_on_receive.finditer(content)]
                    if not on_receive_positions:
                        continue
                    for m in sensitive_receiver_behavior.finditer(content):
                        nearest_on_receive = None
                        for pos in on_receive_positions:
                            if pos <= m.start():
                                nearest_on_receive = pos
                            else:
                                break
                        if nearest_on_receive is None:
                            continue
                        # Side effect should be reasonably close to the onReceive callback.
                        if (m.start() - nearest_on_receive) > 6000:
                            continue
                        line = _line_for_offset(content, m.start())
                        behavior_hit = (f["rel"], line, m.group(0)[:120])
                        break
                    if behavior_hit:
                        break

                if behavior_hit:
                    rel, line, ev = behavior_hit
                    add_finding(
                        {
                            "id": "ADV003",
                            "name": "Exported Broadcast Receiver Without Sender Permission Guard",
                            "severity": "high",
                            "confidence": "medium",
                            "owasp": "M8",
                            "location": f"AndroidManifest.xml → <receiver android:name=\"{rcv_name}\">",
                            "evidence": (
                                "exported receiver without android:permission"
                                + (f"; custom actions={','.join(custom_actions[:4])}" if custom_actions else "")
                                + f"; sensitive behavior in {rel}:{line} ({ev})"
                            ),
                            "description": "Receiver is externally reachable and appears to process potentially sensitive operations without sender permission checks.",
                            "remediation": "Set android:exported='false' if external access is unnecessary, or enforce signature-level android:permission and validate sender identity.",
                        }
                    )

            # Accessibility and notification service declarations
            for service in app.iter("service"):
                svc_name = _attr(service, "name") or "unknown"
                svc_perm = _attr(service, "permission") or ""
                svc_files = related_files_for_component(svc_name)
                svc_scope = svc_files if svc_files else files
                svc_text = "\n".join(sf["content"] for sf in svc_scope)

                has_accessibility_action = False
                has_notif_action = False
                for intent in service.findall("intent-filter"):
                    for action in intent.findall("action"):
                        act_name = _attr(action, "name") or ""
                        if act_name == "android.accessibilityservice.AccessibilityService":
                            has_accessibility_action = True
                        if act_name == "android.service.notification.NotificationListenerService":
                            has_notif_action = True

                # MAL-001 / MAL-002
                if svc_perm == "android.permission.BIND_ACCESSIBILITY_SERVICE" and has_accessibility_action:
                    has_meta_decl = False
                    has_window_content = False
                    has_broad_events = False
                    for meta in service.findall("meta-data"):
                        meta_name = _attr(meta, "name") or ""
                        if meta_name == "android.accessibilityservice":
                            has_meta_decl = True
                            cfg = resolve_accessibility_config(_attr(meta, "resource") or "")
                            if cfg:
                                has_window_content = bool(cfg.get("window_content"))
                                has_broad_events = bool(cfg.get("broad_events"))

                    dynamic_service_info = bool(re.search(r"setServiceInfo\s*\(", svc_text))
                    on_event_handler = bool(re.search(r"onAccessibilityEvent\s*\(", svc_text))
                    reads_screen = bool(re.search(r"event\s*\.\s*getText\s*\(|event\s*\.\s*getSource\s*\(", svc_text))
                    remote_actions = bool(
                        re.search(
                            r"performGlobalAction\s*\(|AccessibilityNodeInfo\s*\.\s*performAction\s*\(|dispatchGesture\s*\(",
                            svc_text,
                            re.IGNORECASE,
                        )
                    )
                    exfil_sinks = bool(
                        re.search(
                            r"HttpURLConnection|OkHttpClient|Retrofit|sendTextMessage|Socket|FileOutputStream",
                            svc_text,
                        )
                    )
                    risk_config = has_window_content or has_broad_events or dynamic_service_info

                    if on_event_handler and reads_screen and (has_meta_decl or dynamic_service_info) and risk_config:
                        severity = "high" if exfil_sinks else "medium"
                        evidence_parts = []
                        if has_window_content:
                            evidence_parts.append("canRetrieveWindowContent=true")
                        if has_broad_events:
                            evidence_parts.append("broad accessibilityEventTypes")
                        if dynamic_service_info:
                            evidence_parts.append("setServiceInfo(...) used")
                        evidence_parts.append("onAccessibilityEvent reads event text/source")
                        add_finding(
                            {
                                "id": "MAL001",
                                "name": "Accessibility Service With High-Risk Data Capture Patterns",
                                "severity": severity,
                                "confidence": "high" if (has_window_content and exfil_sinks) else "medium",
                                "owasp": "M6",
                                "location": f"AndroidManifest.xml → <service android:name=\"{svc_name}\">",
                                "evidence": "; ".join(evidence_parts),
                                "description": "Accessibility service appears to capture UI content broadly. This can be abused for credential/PII harvesting if not tightly scoped.",
                                "remediation": "Limit event scope to minimum required and avoid collecting/transmitting raw on-screen text or node content.",
                            }
                        )

                    if on_event_handler and remote_actions:
                        severity = "high" if exfil_sinks else "medium"
                        add_finding(
                            {
                                "id": "MAL002",
                                "name": "Accessibility Service Remote-Control Primitives Detected",
                                "severity": severity,
                                "confidence": "high" if exfil_sinks else "medium",
                                "owasp": "M3",
                                "location": f"AndroidManifest.xml → <service android:name=\"{svc_name}\">",
                                "evidence": "performGlobalAction/performAction/dispatchGesture patterns found in linked accessibility service code",
                                "description": "Accessibility service code includes UI-control primitives that can automate device actions.",
                                "remediation": "Use accessibility control APIs only when strictly required for user-facing assistive functionality.",
                            }
                        )

                # MAL-003 / MAL-004
                if svc_perm == "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" and has_notif_action:
                    posted = re.search(r"onNotificationPosted\s*\(|getActiveNotifications\s*\(", svc_text)
                    reads_text = re.search(
                        r"notification\s*\.\s*extras|getCharSequence\s*\(\s*['\"]android\.(?:text|title)['\"]",
                        svc_text,
                    )
                    otp_logic = re.search(r"otp|verification|code|2fa|one[\s_-]?time|\b\d{4,8}\b", svc_text, re.IGNORECASE)
                    notif_exfil = re.search(
                        r"HttpURLConnection|OkHttpClient|Retrofit|sendTextMessage|FileOutputStream|Socket",
                        svc_text,
                    )
                    notif_hide = re.search(r"cancelAllNotifications\s*\(|cancelNotification\s*\(|cancelNotifications\s*\(", svc_text)

                    if posted and reads_text and otp_logic and notif_exfil:
                        add_finding(
                            {
                                "id": "MAL003",
                                "name": "Notification Listener May Harvest OTP/Sensitive Content",
                                "severity": "high",
                                "confidence": "high",
                                "owasp": "M6",
                                "location": f"AndroidManifest.xml → <service android:name=\"{svc_name}\">",
                                "evidence": "Notification text extraction + OTP-like logic + exfiltration sink patterns",
                                "description": "Notification listener behavior suggests potential interception of sensitive notification content (e.g., OTP codes).",
                                "remediation": "Minimize notification access scope and never exfiltrate full notification text/content.",
                            }
                        )

                    if posted and notif_hide:
                        add_finding(
                            {
                                "id": "MAL004",
                                "name": "Notification Suppression APIs Used",
                                "severity": "high" if otp_logic else "medium",
                                "confidence": "high" if reads_text else "medium",
                                "owasp": "M8",
                                "location": f"AndroidManifest.xml → <service android:name=\"{svc_name}\">",
                                "evidence": "cancelNotification/cancelAllNotifications API usage detected",
                                "description": "Notification listener appears to suppress notifications, which can hide security-relevant events if misused.",
                                "remediation": "Only cancel notifications for explicit user-driven UX actions. Avoid broad suppression behavior.",
                            }
                        )

    # Cap to keep report actionable
    findings.sort(
        key=lambda f: {"critical": 0, "high": 1, "medium": 2, "info": 3}.get(f.get("severity", "info"), 3)
    )
    return findings[:60]
