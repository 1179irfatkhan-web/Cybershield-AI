import logging
import time

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.db import transaction
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from services.ai_explainer import (
    AIExplanationError,
    generate_security_explanation,
)
from services.domain_checker import (
    DomainCheckError,
    analyze_domain,
)
from services.header_checker import analyze_headers
from services.ip_intelligence import summarize_vetted_target
from services.phishing_checker import (
    analyze_phishing_url,
)
from services.redirect_checker import (
    WebsiteRequestError,
    analyze_redirects,
    fetch_website,
)
from services.ssl_checker import SSLCheckError, analyze_ssl
from services.scoring import (
    calculate_trust_score,
)
from services.url_scanner import (
    check_https,
    normalize_url,
)
from services.url_validator import (
    URLValidationError,
    validate_url,
)

from urllib.parse import urlparse

from .forms import WebsiteScanForm


logger = logging.getLogger(__name__)


def _run_scan(request):
    if request.method == "POST":
        form = WebsiteScanForm(request.POST)

        if form.is_valid():
            submitted_url = form.cleaned_data["submitted_url"]
            normalized_url = normalize_url(submitted_url)

            try:
                safe_target = validate_url(normalized_url)

            except URLValidationError as error:
                form.add_error(
                    "submitted_url",
                    str(error),
                )

            else:
                scan = form.save(commit=False)
                scan.user = request.user
                scan.normalized_url = safe_target.normalized_url
                ip_result = summarize_vetted_target(safe_target)
                scan.resolved_ipv4 = ip_result["ipv4_addresses"]
                scan.resolved_ipv6 = ip_result["ipv6_addresses"]
                scan.ip_resolution_status = ip_result["resolution_status"]
                scan.ip_resolution_message = ip_result["message"]
                scan.status = "pending"
                scan.save(update_fields=["user", "normalized_url", "status", "submitted_url"])
                started = time.monotonic()
                logger.info("scan_started scan_id=%s user_id=%s target=%s", scan.id, request.user.id, safe_target.hostname)

                try:
                    website_result = fetch_website(safe_target, scan_id=scan.id)

                except WebsiteRequestError as error:
                    scan.status = "failed"
                    scan.failure_stage = "request"
                    scan.error_category = "request"
                    if "too long" in str(error).lower():
                        scan.error_message = (
                            "The target did not respond from the scanner network within the safe time limit. "
                            "Check that outbound ports 80/443 are allowed, then try again."
                        )
                    else:
                        scan.error_message = str(error)
                    scan.redirect_chain = error.redirect_chain
                    scan.redirect_count = len(error.redirect_chain)
                    scan.redirect_cross_host_count = sum(
                        item["source_host"] != item["destination_host"]
                        for item in error.redirect_chain
                    )
                    scan.redirect_has_scheme_downgrade = any(
                        item["scheme_downgrade"] for item in error.redirect_chain
                    )
                    scan.redirect_loop_detected = error.loop_detected
                    scan.completed_at = timezone.now()
                    scan.save()

                    return redirect(
                        "scans:result",
                        scan_id=scan.id,
                    )

                # ---------------------------------
                # Redirect Analysis
                # ---------------------------------
                redirect_result = analyze_redirects(
                    website_result
                )

                # ---------------------------------
                # Domain Intelligence
                # ---------------------------------
                try:
                    domain_result = analyze_domain(
                        website_result["final_url"]
                    )
                except DomainCheckError as error:
                    fallback_hostname = (
                        urlparse(website_result["final_url"]).hostname
                        or ""
                    ).lower()

                    domain_result = {
                        "domain_name": fallback_hostname,
                        "registrar": "",
                        "creation_date": None,
                        "expiration_date": None,
                        "age_days": None,
                        "risk": "unknown",
                        "message": str(error),
                        "hosting_provider": "",
                        "domain_type": "Registered Domain",
                        "root_domain": fallback_hostname,
                        "is_managed_subdomain": False,
                    }
                # ---------------------------------
                # Phishing URL Analysis
                # ---------------------------------
                phishing_result = analyze_phishing_url(
                    website_result["final_url"]
                )

                # ---------------------------------
                # HTTPS Analysis
                # ---------------------------------
                uses_https = check_https(
                    website_result["final_url"]
                )

                # ---------------------------------
                # Website Information
                # ---------------------------------
                scan.final_url = website_result["final_url"]
                scan.http_status_code = website_result["status_code"]

                try:
                    ssl_result = (
                        analyze_ssl(website_result["final_url"])
                        if check_https(website_result["final_url"])
                        else None
                    )
                    if ssl_result is None:
                        scan.ssl_message = "TLS analysis is not applicable because the final URL uses HTTP."
                    else:
                        scan.ssl_valid = ssl_result["valid"]
                        scan.ssl_expired = ssl_result["expired"]
                        scan.ssl_days_remaining = ssl_result["days_remaining"]
                        scan.ssl_tls_version = ssl_result["tls_version"]
                        scan.ssl_cipher = ssl_result["cipher"]
                        scan.ssl_issuer = ssl_result["issuer"]
                        scan.ssl_subject = ssl_result["subject"]
                        scan.ssl_subject_alt_names = ssl_result["subject_alt_names"]
                        scan.ssl_signature_algorithm = ssl_result["signature_algorithm"]
                        scan.ssl_message = ssl_result["message"]
                except SSLCheckError as error:
                    logger.warning("SSL analysis unavailable for scan %s (%s).", scan.id, type(error).__name__)
                    scan.ssl_message = "TLS analysis was unavailable for this scan."

                try:
                    header_result = analyze_headers(website_result.get("headers", {}))
                    scan.headers_score = header_result["score"]
                    scan.headers_risk = header_result["risk"]
                    scan.headers_present = header_result["present"]
                    scan.headers_missing = header_result["missing"]
                    scan.headers_recommendations = header_result["recommendations"]
                    scan.headers_message = header_result["message"]
                except Exception as error:
                    logger.warning("Header analysis unavailable for scan %s (%s).", scan.id, type(error).__name__)
                    scan.headers_message = "Security header analysis was unavailable for this scan."

                # ---------------------------------
                # Redirect Information
                # ---------------------------------
                scan.redirect_count = website_result["redirect_count"]
                scan.redirect_risk = redirect_result["risk"]
                scan.redirect_message = redirect_result["message"]
                scan.redirect_chain = website_result["redirect_chain"]
                scan.redirect_cross_host_count = website_result[
                    "redirect_cross_host_count"
                ]
                scan.redirect_has_scheme_downgrade = website_result[
                    "redirect_has_scheme_downgrade"
                ]
                scan.redirect_loop_detected = website_result[
                    "redirect_loop_detected"
                ]

                # ---------------------------------
                # Domain Information
                # ---------------------------------
                scan.domain_name = domain_result["domain_name"]
                scan.domain_registrar = domain_result["registrar"]
                scan.domain_created_at = domain_result["creation_date"]
                scan.domain_expires_at = domain_result["expiration_date"]
                scan.domain_age_days = domain_result["age_days"]
                scan.domain_risk = domain_result["risk"]
                scan.domain_message = domain_result["message"]
                scan.hosting_provider = domain_result["hosting_provider"]
                scan.domain_type = domain_result["domain_type"]
                scan.root_domain = domain_result["root_domain"]
                scan.is_managed_subdomain = domain_result[
                    "is_managed_subdomain"
                ]
                scan.registration_data_source = domain_result.get("registration_data_source", "unavailable")
                scan.rdap_available = domain_result.get("rdap_available")
                scan.whois_available = domain_result.get("whois_available")
                scan.domain_statuses = domain_result.get("domain_statuses", [])
                scan.domain_nameservers = domain_result.get("nameservers", [])
                scan.domain_dnssec_status = domain_result.get("dnssec_status", "unknown")
                scan.domain_updated_at = domain_result.get("registration_updated_at")

                # ---------------------------------
                # Phishing Information
                # ---------------------------------
                scan.phishing_risk = phishing_result["risk"]
                scan.phishing_score_penalty = phishing_result[
                    "score_penalty"
                ]
                scan.phishing_indicator_count = phishing_result[
                    "indicator_count"
                ]
                scan.phishing_indicators = phishing_result["indicators"]
                scan.phishing_message = phishing_result["message"]

                # ---------------------------------
                # HTTPS Information
                # ---------------------------------
                scan.uses_https = uses_https

                if uses_https:
                    scan.https_message = (
                        "The final website connection uses HTTPS, "
                        "which encrypts communication between the "
                        "browser and the server."
                    )
                else:
                    scan.https_message = (
                        "The final website connection does not use HTTPS. "
                        "Information may not be securely encrypted."
                    )

                # ---------------------------------
                # Weighted Trust Score
                # ---------------------------------
                scan.check_results = {
                    "https": {"status": "passed" if uses_https else "failed", "message": scan.https_message},
                    "ssl": {"status": "passed" if scan.ssl_valid else "failed" if scan.ssl_valid is False else "unavailable", "message": scan.ssl_message, "evidence": {"days_remaining": scan.ssl_days_remaining}},
                    "headers": {"status": "passed" if scan.headers_score is not None and scan.headers_score >= 80 else "warning" if scan.headers_score is not None else "unavailable", "message": scan.headers_message, "evidence": {"missing": scan.headers_missing, "score": scan.headers_score}},
                    "redirects": {"status": "passed" if scan.redirect_risk == "low" else "warning" if scan.redirect_risk == "medium" else "failed", "message": scan.redirect_message},
                    "domain": {"status": "passed" if scan.domain_risk == "low" or (scan.is_managed_subdomain and scan.hosting_provider and scan.root_domain) else "warning" if scan.domain_risk in {"medium", "high"} else "unavailable", "message": scan.domain_message},
                    "phishing": {"status": "passed" if scan.phishing_risk == "low" and not scan.phishing_score_penalty else "warning" if scan.phishing_risk == "medium" else "failed" if scan.phishing_risk == "high" else "unavailable", "message": scan.phishing_message},
                }
                score_result = calculate_trust_score(scan)

                scan.trust_score = score_result["trust_score"]
                scan.risk_level = score_result["risk_level"]
                scan.score_breakdown = score_result["deductions"]
                scan.confidence_score = score_result["confidence_score"]
                scan.completeness_percentage = score_result["completeness_percentage"]
                scan.positive_findings = score_result["positive_findings"]
                scan.unavailable_checks = score_result["unavailable_checks"]
                scan.scoring_methodology_version = score_result["methodology_version"]

                # ---------------------------------
                # AI Security Report
                # ---------------------------------
                try:
                    scan.ai_security_report = (
                        generate_security_explanation(scan)
                    )

                except AIExplanationError as error:
                    logger.warning(
                        "Gemini explanation unavailable for scan %s (%s).",
                        scan.id,
                        type(error).__name__,
                    )

                    scan.ai_security_report = (
                        "CyberShield AI could not generate the AI security explanation "
                        "because the Gemini service was temporarily unavailable. "
                        "The deterministic scan results shown in this report are still valid."
                    )

                # ---------------------------------
                # Final Scan Status
                # ---------------------------------
                scan.status = "completed"
                scan.completed_at = timezone.now()
                scan.stage_durations_ms = {"total": round((time.monotonic() - started) * 1000)}

                scan.save()
                logger.info("scan_completed scan_id=%s user_id=%s duration_ms=%s", scan.id, request.user.id, scan.stage_durations_ms["total"])

                return redirect(
                    "scans:result",
                    scan_id=scan.id,
                )

    else:
        form = WebsiteScanForm()

    return render(
        request,
        "scans/create_scan.html",
        {
            "form": form,
        },
    )


@login_required
def scan_result(request, scan_id):
    scan = get_object_or_404(
        request.user.website_scans,
        id=scan_id,
    )
    return render(request, "scans/result.html", {"scan": scan})


@login_required
def create_scan(request):
    if request.method == "POST":
        user_key = f"scan-rate:{request.user.pk}"
        try:
            recent = cache.get(user_key, 0)
            if recent >= settings.SCAN_RATE_LIMIT_COUNT:
                logger.info("scan_rate_limited user_id=%s reason=window", request.user.id)
                return render(request, "scans/create_scan.html", {"form": WebsiteScanForm(), "rate_limited": True})
            cache.set(user_key, recent + 1, settings.SCAN_RATE_LIMIT_WINDOW_SECONDS)
            day_key = f"scan-quota:{request.user.pk}:{timezone.now().date().isoformat()}"
            daily = cache.get(day_key, 0)
            if daily >= settings.SCAN_DAILY_QUOTA:
                logger.info("scan_rate_limited user_id=%s reason=daily", request.user.id)
                return render(request, "scans/create_scan.html", {"form": WebsiteScanForm(), "rate_limited": True})
            cache.set(day_key, daily + 1, 86400)
        except Exception as error:
            logger.warning("scan_limit_check_failed user_id=%s error_category=%s", request.user.id, type(error).__name__)
        try:
            return _run_scan(request)
        except Exception as error:
            scan = request.user.website_scans.filter(status="pending").order_by("-created_at").first()
            if scan:
                scan.status = "failed"
                scan.completed_at = timezone.now()
                scan.failure_stage = "unexpected"
                scan.error_category = type(error).__name__
                scan.error_message = "The scan could not be completed. Please try again later."
                scan.save(update_fields=["status", "completed_at", "failure_stage", "error_category", "error_message"])
                logger.exception("scan_failed scan_id=%s user_id=%s error_category=%s", scan.id, request.user.id, type(error).__name__)
                return redirect("scans:result", scan_id=scan.id)
            logger.exception("scan_failed user_id=%s error_category=%s", request.user.id, type(error).__name__)
            return render(request, "scans/create_scan.html", {"form": WebsiteScanForm(), "scan_error": True})
    return _run_scan(request)

