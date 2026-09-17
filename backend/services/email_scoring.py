METHODOLOGY_VERSION = "email-1.0"
RISKY_EXTENSIONS = (".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".docm", ".xlsm", ".pptm", ".msi")

def calculate_email_score(evidence):
    score, deductions = 100, []
    if evidence.get("sender_mismatch"): score -= 20; deductions.append("Sender/reply-to mismatch (-20)")
    if evidence.get("suspicious_keywords"): score -= 25; deductions.append("Suspicious language detected (-25)")
    if evidence.get("link_flags"): score -= min(30, len(evidence["link_flags"]) * 10); deductions.append("Suspicious link indicators (-10 each)")
    if evidence.get("html_form_detected"): score -= 10; deductions.append("HTML form detected (-10)")
    if evidence.get("attachment_metadata") and any(str(x).lower().endswith(RISKY_EXTENSIONS) for x in evidence["attachment_metadata"]): score -= 15; deductions.append("Risky attachment metadata (-15)")
    checks = {"sender": "warning" if evidence.get("sender_mismatch") else "passed", "language": "warning" if evidence.get("suspicious_keywords") else "passed", "links": "warning" if evidence.get("link_flags") else "passed", "html": "warning" if evidence.get("html_form_detected") else "passed", "attachments": "warning" if evidence.get("attachment_metadata") else "passed"}
    risk = "low" if score >= 80 else "medium" if score >= 55 else "high"
    return {"safety_score": max(0, min(100, score)), "risk_level": risk, "confidence_score": 100, "completeness_percentage": 100, "deductions": deductions, "positive_findings": ["No suspicious indicators detected"] if score == 100 else [], "warnings": evidence.get("warnings", []), "check_results": checks, "methodology_version": "1.0"}
