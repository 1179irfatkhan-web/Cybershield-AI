from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.conf import settings
from django.core.cache import cache
from services.email_phishing_checker import analyze_email
from services.email_scoring import calculate_email_score
from services.email_ai_explainer import generate_email_explanation
from .forms import EmailScanForm
from .models import EmailScan
from services.email_pdf_extractor import extract_email_pdf, PDFExtractionError
import os, tempfile
import logging

logger = logging.getLogger(__name__)

@login_required
def create_email_scan(request):
    form = EmailScanForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        try:
            key = f"email-scan-rate:{request.user.pk}"
            count = cache.get(key, 0)
            if count >= settings.EMAIL_SCAN_RATE_LIMIT_COUNT:
                form.add_error(None, "Email scan limit reached. Please wait before submitting another scan.")
                return render(request, "email_scans/create.html", {"form": form})
            cache.set(key, count + 1, settings.EMAIL_SCAN_RATE_LIMIT_WINDOW_SECONDS)
            day_key = f"email-scan-daily:{request.user.pk}:{timezone.now().date().isoformat()}"
            daily = cache.get(day_key, 0)
            if daily >= settings.EMAIL_SCAN_DAILY_QUOTA:
                form.add_error(None, "Daily email scan quota reached. Please try again tomorrow.")
                return render(request, "email_scans/create.html", {"form": form})
            cache.set(day_key, daily + 1, 86400)
        except Exception as error:
            logger.warning("email_scan_limit_unavailable category=%s", type(error).__name__)
        scan = form.save(commit=False); scan.user = request.user; scan.status = EmailScan.Status.PENDING; scan.input_source = request.POST.get("input_source") if request.POST.get("input_source") in {"manual", "pasted", "pdf_import"} else "manual"; scan.pdf_extraction_confidence = request.session.pop("email_pdf_confidence", None); scan.pdf_extraction_warnings = request.session.pop("email_pdf_warnings", []); scan.save()
        try:
            evidence = analyze_email(form.cleaned_data)
            result = calculate_email_score(evidence)
            for field in ("sender_mismatch", "reply_to_mismatch", "html_form_detected", "hidden_link_mismatch_count", "extracted_links", "suspicious_keywords", "attachment_metadata"):
                setattr(scan, field, evidence.get(field, getattr(scan, field)))
            scan.link_findings = evidence.get("link_findings", [])
            scan.warning_findings = result["warnings"]; scan.score_breakdown = result["deductions"]; scan.positive_findings = result["positive_findings"]; scan.check_results = result["check_results"]; scan.methodology_version = result["methodology_version"]
            scan.safety_score = result["safety_score"]; scan.risk_level = result["risk_level"]; scan.confidence_score = result["confidence_score"]; scan.completeness_percentage = result["completeness_percentage"]; scan.save()
            scan.ai_security_report = generate_email_explanation(scan); scan.save(update_fields=["ai_security_report"])
            scan.status = EmailScan.Status.COMPLETED; scan.completed_at = timezone.now(); scan.save(update_fields=["status", "completed_at"])
            return redirect("email_scans:result", scan_id=scan.id)
        except Exception as error:
            logger.exception("email_scan_failed scan_id=%s user_id=%s category=%s", scan.id, request.user.id, type(error).__name__)
            scan.status = EmailScan.Status.FAILED; scan.failure_stage = "analysis"; scan.error_message = "The email could not be analyzed."; scan.completed_at = timezone.now(); scan.save(update_fields=["status", "failure_stage", "error_message", "completed_at"])
            return redirect("email_scans:result", scan_id=scan.id)
    if request.method == "POST":
        logger.warning("email_scan_form_invalid user_id=%s fields=%s", request.user.id, ",".join(form.errors.keys()))
    return render(request, "email_scans/create.html", {"form": form})

@login_required
def import_pdf(request):
    if request.method == "GET":
        return render(request, "email_scans/create.html", {"form": EmailScanForm(), "pdf_upload": True})
    upload = request.FILES.get("pdf_file")
    if not upload or not upload.name.lower().endswith(".pdf"):
        return render(request, "email_scans/create.html", {"form": EmailScanForm(), "pdf_upload": True, "pdf_error": "Please upload a PDF file."})
    if upload.size > settings.EMAIL_PDF_MAX_SIZE:
        return render(request, "email_scans/create.html", {"form": EmailScanForm(), "pdf_upload": True, "pdf_error": "That PDF is too large."})
    upload.seek(0)
    signature = upload.read(5)
    upload.seek(0)
    allowed_types = {"application/pdf", "application/x-pdf", "application/octet-stream"}
    if signature != b"%PDF-" or upload.content_type not in allowed_types:
        return render(request, "email_scans/create.html", {"form": EmailScanForm(), "pdf_upload": True, "pdf_error": "The uploaded file is not a valid PDF."})
    fd, path = tempfile.mkstemp(prefix="email-pdf-", suffix=".pdf")
    try:
        with os.fdopen(fd, "wb") as target:
            for chunk in upload.chunks(): target.write(chunk)
        data = extract_email_pdf(path, max_pages=settings.EMAIL_PDF_MAX_PAGES, max_text=settings.EMAIL_PDF_MAX_TEXT)
    except PDFExtractionError as exc:
        logger.warning("email_pdf_extraction_failed error_category=%s exception_type=%s", exc.category, type(exc).__name__)
        return render(request, "email_scans/create.html", {"form": EmailScanForm(), "pdf_upload": True, "pdf_error": str(exc)})
    finally:
        try: os.remove(path)
        except OSError: pass
    request.session["email_pdf_preview"] = data
    request.session["email_pdf_confidence"] = data.get("extraction_confidence")
    request.session["email_pdf_warnings"] = data.get("extraction_warnings", [])
    return render(request, "email_scans/pdf_preview.html", {"data": data})

@login_required
def email_result(request, scan_id):
    scan = get_object_or_404(request.user.email_scans, id=scan_id)
    return render(request, "email_scans/result.html", {"scan": scan})

@login_required
def email_history(request):
    return render(request, "email_scans/history.html", {"scans": request.user.email_scans.all()[:50]})
