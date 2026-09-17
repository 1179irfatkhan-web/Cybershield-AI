RECOMMENDATIONS = {
    "strict-transport-security": "Enable HSTS with an appropriate max-age.",
    "content-security-policy": "Define a restrictive Content-Security-Policy.",
    "x-frame-options": "Set X-Frame-Options to DENY or SAMEORIGIN.",
    "x-content-type-options": "Set X-Content-Type-Options to nosniff.",
    "referrer-policy": "Set an explicit privacy-preserving Referrer-Policy.",
    "permissions-policy": "Restrict unnecessary browser capabilities.",
    "cross-origin-opener-policy": "Set an appropriate Cross-Origin-Opener-Policy.",
    "cross-origin-embedder-policy": "Set Cross-Origin-Embedder-Policy where compatible.",
    "cross-origin-resource-policy": "Set an appropriate Cross-Origin-Resource-Policy.",
}


def analyze_headers(headers: dict) -> dict:
    normalized = {str(key).lower(): str(value) for key, value in (headers or {}).items()}
    names = tuple(RECOMMENDATIONS)
    present = [name for name in names if normalized.get(name, "").strip()]
    missing = [name for name in names if name not in present]
    score = round(len(present) / len(names) * 100)
    if score >= 80:
        risk = "low"
    elif score >= 50:
        risk = "medium"
    else:
        risk = "high"
    return {
        "present": present,
        "missing": missing,
        "score": score,
        "risk": risk,
        "recommendations": [RECOMMENDATIONS[name] for name in missing],
        "message": f"{len(present)} of {len(names)} recommended security headers are present.",
    }
