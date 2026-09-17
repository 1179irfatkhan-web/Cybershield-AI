METHODOLOGY_VERSION = "1.0"
WEIGHTS = {"https": 15, "ssl": 20, "headers": 25, "redirects": 10, "domain": 10, "phishing": 20}


def calculate_trust_score(scan):
    """Calculate explainable trust, evidence confidence, and completeness."""
    results = getattr(scan, "check_results", None) or _derive_check_results(scan)
    state = lambda name: (results.get(name) or {}).get("status", "unavailable")
    value = {"passed": 1, "warning": .5, "failed": 0, "unavailable": 0, "skipped": 0}
    trust = sum(round(weight * value.get(state(name), 0)) for name, weight in WEIGHTS.items())
    deductions = []
    positive = [f"{name.title()} check passed (+{weight})" for name, weight in WEIGHTS.items() if state(name) == "passed"]
    if state("https") == "failed": deductions.append("HTTPS is disabled (-15)")
    if state("ssl") == "failed": deductions.append("Expired TLS certificate (-20)" if getattr(scan, "ssl_expired", False) else "TLS certificate is invalid or expired (-20)")
    elif state("ssl") == "warning": deductions.append("TLS certificate expires in under 30 days (-10)")
    missing = set((results.get("headers") or {}).get("evidence", {}).get("missing", []))
    for header, weight in (("strict-transport-security", 5), ("content-security-policy", 10), ("x-frame-options", 5), ("x-content-type-options", 5)):
        if header in missing: deductions.append(f"Missing {header} (-{weight})")
    if state("redirects") == "warning": deductions.append("Redirect chain requires review (-5)")
    if state("domain") == "warning": deductions.append("Domain intelligence indicates elevated age risk (-5)")
    if state("phishing") == "warning": deductions.append("Phishing URL indicators detected (-10)")
    elif state("phishing") == "failed": deductions.append("Strong phishing indicators detected (-20)")
    relevant = [name for name in WEIGHTS if state(name) != "skipped"]
    completed = [name for name in relevant if state(name) in {"passed", "warning", "failed"}]
    confidence = round(len(completed) / len(relevant) * 100) if relevant else 0
    if confidence < 50: risk = "unknown"
    elif trust >= 90 and confidence >= 90: risk = "low"
    elif trust >= 70: risk = "medium"
    elif trust >= 40: risk = "high"
    else: risk = "critical"
    return {"trust_score": max(0, min(100, trust)), "score": max(0, min(100, trust)), "risk_level": risk, "risk": risk, "confidence_score": confidence, "completeness_percentage": confidence, "completed_checks": [n for n in results if state(n) == "passed"], "warning_checks": [n for n in results if state(n) == "warning"], "failed_checks": [n for n in results if state(n) == "failed"], "unavailable_checks": [n for n in results if state(n) == "unavailable"], "deductions": deductions, "positive_findings": positive, "methodology_version": METHODOLOGY_VERSION, "check_results": results}


def _derive_check_results(scan):
    https, ssl_valid, headers = getattr(scan, "uses_https", None), getattr(scan, "ssl_valid", None), getattr(scan, "headers_score", None)
    ssl_expired = getattr(scan, "ssl_expired", False)
    return {"https": {"status": "passed" if https else "failed" if https is False else "unavailable"}, "ssl": {"status": "failed" if ssl_expired else "passed" if ssl_valid else "failed" if ssl_valid is False else "unavailable"}, "headers": {"status": "passed" if headers is not None and headers >= 80 else "warning" if headers is not None else "unavailable", "evidence": {"missing": getattr(scan, "headers_missing", [])}}, "redirects": {"status": "passed" if getattr(scan, "redirect_risk", "") == "low" else "warning"}, "domain": {"status": "passed" if getattr(scan, "domain_risk", "") == "low" else "warning"}, "phishing": {"status": "passed" if not getattr(scan, "phishing_score_penalty", 0) else "warning"}}
