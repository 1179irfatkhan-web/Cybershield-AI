"""Passive analyzers operating exclusively on CanonicalResponseContext."""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from services.assessment_context import CanonicalResponseContext
from services.assessment_headers import analyze_headers
from services.assessment_cookies import analyze_cookies
from services.assessment_forms import analyze_forms
from services.assessment_exposure import analyze_exposure


@dataclass
class CategoryResult:
    category_name: str
    score: Optional[int]
    max_score: int = 100
    status: str = "unavailable"
    findings: List[Dict[str, Any]] = field(default_factory=list)
    positive_findings: List[Dict[str, Any]] = field(default_factory=list)
    deductions: int = 0
    checks_completed: List[str] = field(default_factory=list)
    checks_planned: List[str] = field(default_factory=list)
    unavailable_checks: List[str] = field(default_factory=list)

    def as_dict(self):
        return self.__dict__.copy()


def _safe(category, checks, fn, *args):
    try:
        result = fn(*args)
        findings = result.get("findings", [])
        # Ensure evidence cannot accidentally persist target URLs or values.
        masked = [{k: ("" if k in {"affected_url", "evidence"} else v) for k, v in item.items()} for item in findings]
        score = max(0, 100 - min(100, len(masked) * 10))
        return CategoryResult(category, score, status="passed" if not masked else "warning", findings=masked, positive_findings=result.get("positive_findings", []), deductions=100-score, checks_completed=checks, checks_planned=checks, unavailable_checks=result.get("unavailable_checks", [])).as_dict()
    except Exception:
        return CategoryResult(category, None, status="unavailable", checks_planned=checks, unavailable_checks=[category]).as_dict()


class TransportAnalyzer:
    def analyze(self, context: CanonicalResponseContext):
        if not context or context.status_code is None:
            return CategoryResult("transport", None, checks_planned=["https", "redirects", "tls"], unavailable_checks=["transport"]).as_dict()
        downgrade = any(item.get("scheme_downgrade") for item in context.redirect_chain if isinstance(item, dict))
        findings = []
        if not context.is_https and not (context.redirect_chain and not downgrade):
            findings.append({"id": "https_unavailable", "title": "HTTPS is not enforced", "severity": "high", "status": "warning"})
        return CategoryResult("transport", 100 if not findings else 75, status="passed" if not findings else "warning", findings=findings, deductions=0 if not findings else 25, checks_completed=["https", "redirects", "tls"], checks_planned=["https", "redirects", "tls"]).as_dict()


class HeaderAnalyzer:
    def analyze(self, context):
        return _safe("headers", ["security_headers"], analyze_headers, context.headers, context.is_https)


class CookieAnalyzer:
    def analyze(self, context):
        return _safe("cookies", ["cookie_attributes"], analyze_cookies, context.set_cookie_headers, context.is_https)


class FormAnalyzer:
    def analyze(self, context):
        return _safe("forms", ["forms", "mixed_content"], analyze_forms, context.bounded_body, context.final_url)


class ExposureAnalyzer:
    def analyze(self, context):
        return _safe("exposure", ["disclosure", "debug_indicators"], analyze_exposure, context.bounded_body, context.headers, context.final_url)
