import uuid
from django.conf import settings
from django.db import models

class EmailScan(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="email_scans")
    subject = models.CharField(max_length=500, blank=True)
    sender_name = models.CharField(max_length=255, blank=True)
    sender_email = models.EmailField(blank=True)
    reply_to = models.EmailField(blank=True)
    email_body = models.TextField()
    body_type = models.CharField(max_length=10, choices=(("plain_text", "Plain text"), ("html", "HTML")), default="plain_text")
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    risk_level = models.CharField(max_length=20, blank=True)
    safety_score = models.PositiveSmallIntegerField(null=True, blank=True)
    confidence_score = models.PositiveSmallIntegerField(null=True, blank=True)
    completeness_percentage = models.PositiveSmallIntegerField(null=True, blank=True)
    score_breakdown = models.JSONField(default=list, blank=True)
    positive_findings = models.JSONField(default=list, blank=True)
    warning_findings = models.JSONField(default=list, blank=True)
    extracted_links = models.JSONField(default=list, blank=True)
    suspicious_keywords = models.JSONField(default=list, blank=True)
    sender_mismatch = models.BooleanField(default=False)
    reply_to_mismatch = models.BooleanField(default=False)
    html_form_detected = models.BooleanField(default=False)
    hidden_link_mismatch_count = models.PositiveSmallIntegerField(default=0)
    attachment_metadata = models.JSONField(default=list, blank=True)
    input_source = models.CharField(max_length=20, choices=(("manual", "Manual"), ("pasted", "Pasted"), ("pdf_import", "PDF import")), default="manual")
    pdf_extraction_confidence = models.PositiveSmallIntegerField(null=True, blank=True)
    pdf_extraction_warnings = models.JSONField(default=list, blank=True)
    check_results = models.JSONField(default=dict, blank=True)
    link_findings = models.JSONField(default=list, blank=True)
    methodology_version = models.CharField(max_length=20, blank=True)
    ai_security_report = models.TextField(blank=True)
    error_message = models.TextField(blank=True)
    failure_stage = models.CharField(max_length=50, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    class Meta:
        ordering = ["-created_at"]
