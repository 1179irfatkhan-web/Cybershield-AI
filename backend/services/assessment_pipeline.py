"""Synchronous, bounded orchestration for authorized passive assessments."""
import logging
from django.utils import timezone
from services.assessment_transport import assess_transport
from services.assessment_headers import analyze_headers
from services.assessment_cookies import analyze_cookies
from services.assessment_forms import analyze_forms
from services.assessment_exposure import analyze_exposure
from services.assessment_scoring import calculate_assessment_score, CATEGORY_WEIGHTS
from services.assessment_technology import TechnologyAnalyzer
from services.assessment_public_files import PublicFileAnalyzer
from services.assessment_ai_explainer import generate_assessment_explanation

logger = logging.getLogger(__name__)


def _category(result, name):
    if not result or result.get("status") == "unavailable":
        return {"status": "unavailable", "score": None}
    maximum = CATEGORY_WEIGHTS[name]
    deductions = min(maximum, len(result.get("findings", [])) * 10)
    return {"status": result.get("status", "completed"), "score": maximum - deductions}


def run_security_assessment(assessment):
    try:
        transport = assess_transport(assessment.normalized_url)
        assessment.final_url = transport.get("final_url", "")
        # The immutable context is an in-memory analyzer contract and must
        # never be persisted in the JSONField (Django's encoder cannot
        # serialize it, and it may contain more response data than we need).
        assessment.transport_findings = {
            key: value for key, value in transport.items() if key != "context"
        }
        if transport.get("status") != "completed":
            assessment.findings = []
            assessment.unavailable_checks = transport.get("unavailable_checks", [])
            assessment.check_results = {k: "unavailable" for k in CATEGORY_WEIGHTS}
            assessment.overall_score = None
            assessment.risk_level = ""
            assessment.confidence_score = 0
            assessment.completeness_percentage = 0
            assessment.status = "failed"
            assessment.error_category = transport.get("error_category", "target_request")
            assessment.failure_stage = "target_request"
            assessment.error_message = "CyberShield AI could not retrieve this website safely, so no security score was calculated."
            assessment.completed_at = timezone.now()
            assessment.save()
            return assessment

        headers_raw = transport.get("headers", {})
        body = transport.get("bounded_body_text", "")
        https = transport.get("uses_https_final", False)
        headers = analyze_headers(headers_raw, https) if headers_raw else {"status": "unavailable", "findings": [], "unavailable_checks": ["headers"]}
        cookies = analyze_cookies(transport.get("set_cookie_headers", []), https) if headers_raw else {"status": "unavailable", "findings": [], "unavailable_checks": ["cookies"]}
        forms = analyze_forms(body, assessment.normalized_url) if body else {"status": "unavailable", "findings": [], "unavailable_checks": ["forms"]}
        exposure = analyze_exposure(body, headers_raw, assessment.normalized_url) if body else {"status": "unavailable", "findings": [], "unavailable_checks": ["exposure"]}
        technology = TechnologyAnalyzer().analyze(transport.get("context")) if transport.get("context") else {"status": "unavailable", "findings": [], "unavailable_checks": ["technology"]}
        public_files = PublicFileAnalyzer().analyze(transport.get("context"))
        assessment.header_findings, assessment.cookie_findings = headers, cookies
        assessment.form_findings, assessment.exposure_findings = forms, exposure
        assessment.technology_findings, assessment.public_file_findings = technology, public_files
        assessment.mixed_content_findings = transport.get("mixed_content_findings", [])
        assessment.findings = (headers.get("findings", []) + cookies.get("findings", []) + forms.get("findings", []) + exposure.get("findings", []))
        assessment.positive_findings = headers.get("positive_findings", [])
        unavailable = []
        for result in (headers, cookies, forms, exposure, technology, public_files):
            unavailable.extend(result.get("unavailable_checks", []))
        assessment.unavailable_checks = list(dict.fromkeys(unavailable + transport.get("unavailable_checks", [])))
        categories = {name: {"status": "unavailable", "score": None} for name in CATEGORY_WEIGHTS}
        categories.update({"transport": _category(transport, "transport"), "headers": _category(headers, "headers"), "cookies": _category(cookies, "cookies"), "forms": _category(forms, "forms"), "exposure": _category(exposure, "exposure"), "technology": _category(technology, "technology"), "public_files": _category(public_files, "public_files")})
        score = calculate_assessment_score(categories, assessment.unavailable_checks, findings=assessment.findings)
        assessment.check_results = {**score["check_results"], "category_scores": score["category_scores"], "score_breakdown": score["deductions"]}
        assessment.overall_score = score["overall_score"]
        assessment.risk_level = score["risk_level"]
        assessment.confidence_score = score["confidence_score"]
        assessment.completeness_percentage = score["completeness_percentage"]
        assessment.recommendations = score["recommendations"]
        # Only the sanitized deterministic summary is sent to the explainer.
        hostname = assessment.normalized_url.split("/", 3)[2].split(":", 1)[0]
        summary = {"target_hostname": hostname, "overall_score": score["overall_score"], "risk_level": score["risk_level"], "confidence_score": score["confidence_score"], "completeness_percentage": score["completeness_percentage"], "category_scores": score["category_scores"], "priority_findings": assessment.findings[:10], "positive_findings": assessment.positive_findings[:10], "unavailable_checks": assessment.unavailable_checks, "recommendations": assessment.recommendations, "methodology_version": "4.6"}
        try:
            assessment.ai_security_report = generate_assessment_explanation(summary)
        except Exception:
            assessment.ai_security_report = "Automated explanation unavailable. Review the deterministic findings and recommendations."
        assessment.methodology_version = "4.6"
        assessment.status = "completed"
        assessment.completed_at = timezone.now()
        assessment.save()
        return assessment
    except Exception:
        logger.exception("assessment_pipeline_failed assessment_id=%s", assessment.id)
        assessment.status = "failed"
        assessment.error_category = "assessment_failure"
        assessment.error_message = "The assessment could not be completed safely."
        assessment.failure_stage = "pipeline"
        assessment.completed_at = timezone.now()
        assessment.save()
        return assessment
