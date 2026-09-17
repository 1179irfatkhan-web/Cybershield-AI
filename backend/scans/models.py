import uuid

from django.conf import settings
from django.db import models


class WebsiteScan(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="website_scans",
    )

    submitted_url = models.URLField(max_length=2048)
    normalized_url = models.URLField(max_length=2048, blank=True)

    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING,
    )

    trust_score = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
    )

    risk_level = models.CharField(
        max_length=20,
        blank=True,
    )
    uses_https = models.BooleanField(
    null=True,
    blank=True,
)
    https_message = models.CharField(
    max_length=255,
    blank=True,
)
    http_status_code = models.PositiveSmallIntegerField(
    null=True,
    blank=True,
)

    final_url = models.URLField(
    max_length=2048,
    blank=True,
)

    redirect_count = models.PositiveSmallIntegerField(
    default=0,
)
    redirect_risk = models.CharField(
    max_length=20,
    blank=True,
)

    redirect_message = models.CharField(
        max_length=255,
        blank=True,
    )
    redirect_chain = models.JSONField(
        default=list,
        blank=True,
    )
    redirect_cross_host_count = models.PositiveSmallIntegerField(
        default=0,
    )
    redirect_has_scheme_downgrade = models.BooleanField(
        default=False,
    )
    redirect_loop_detected = models.BooleanField(
        default=False,
    )
    ssl_valid = models.BooleanField(null=True, blank=True)
    ssl_expired = models.BooleanField(null=True, blank=True)
    ssl_days_remaining = models.IntegerField(null=True, blank=True)
    ssl_tls_version = models.CharField(max_length=50, blank=True)
    ssl_cipher = models.CharField(max_length=100, blank=True)
    ssl_issuer = models.CharField(max_length=500, blank=True)
    ssl_subject = models.CharField(max_length=500, blank=True)
    ssl_subject_alt_names = models.JSONField(default=list, blank=True)
    ssl_signature_algorithm = models.CharField(max_length=100, blank=True)
    ssl_message = models.CharField(max_length=500, blank=True)
    headers_score = models.PositiveSmallIntegerField(null=True, blank=True)
    headers_risk = models.CharField(max_length=20, blank=True)
    headers_present = models.JSONField(default=list, blank=True)
    headers_missing = models.JSONField(default=list, blank=True)
    headers_recommendations = models.JSONField(default=list, blank=True)
    headers_message = models.CharField(max_length=500, blank=True)
    confidence_score = models.PositiveSmallIntegerField(null=True, blank=True)
    completeness_percentage = models.PositiveSmallIntegerField(null=True, blank=True)
    check_results = models.JSONField(default=dict, blank=True)
    positive_findings = models.JSONField(default=list, blank=True)
    unavailable_checks = models.JSONField(default=list, blank=True)
    scoring_methodology_version = models.CharField(max_length=20, blank=True)
    stage_durations_ms = models.JSONField(default=dict, blank=True)
    failure_stage = models.CharField(max_length=50, blank=True)
    error_category = models.CharField(max_length=50, blank=True)
    registration_data_source = models.CharField(max_length=20, blank=True)
    rdap_available = models.BooleanField(null=True, blank=True)
    whois_available = models.BooleanField(null=True, blank=True)
    domain_statuses = models.JSONField(default=list, blank=True)
    domain_nameservers = models.JSONField(default=list, blank=True)
    domain_dnssec_status = models.CharField(max_length=50, blank=True)
    domain_updated_at = models.DateField(null=True, blank=True)
    resolved_ipv4 = models.JSONField(default=list, blank=True)
    resolved_ipv6 = models.JSONField(default=list, blank=True)
    ip_resolution_status = models.CharField(max_length=20, blank=True)
    ip_resolution_message = models.CharField(max_length=500, blank=True)
    domain_name = models.CharField(
        max_length=255,
        blank=True,
    )
    domain_registrar = models.CharField(
        max_length=255,
        blank=True,
    )
    domain_created_at = models.DateField(
        null=True,
        blank=True,
    )
    domain_expires_at = models.DateField(
        null=True,
        blank=True,
    )
    domain_age_days = models.PositiveIntegerField(
        null=True,
        blank=True,
    )
    domain_risk = models.CharField(
        max_length=20,
        blank=True,
    )
    domain_message = models.CharField(
        max_length=500,
        blank=True,
    )
    hosting_provider = models.CharField(
        max_length=100,
        blank=True,
    )
    domain_type = models.CharField(
        max_length=50,
        blank=True,
    )
    root_domain = models.CharField(
        max_length=255,
        blank=True,
    )
    is_managed_subdomain = models.BooleanField(
        default=False,
    )

    phishing_risk = models.CharField(
    max_length=20,
    blank=True,
)

    phishing_score_penalty = models.PositiveSmallIntegerField(
    default=0,
)

    phishing_indicator_count = models.PositiveSmallIntegerField(
    default=0,
)

    phishing_indicators = models.JSONField(
    default=list,
    blank=True,
)

    phishing_message = models.CharField(
    max_length=500,
    blank=True,
)
    score_breakdown = models.JSONField(
    default=list,
    blank=True,
)
    ai_security_report = models.TextField(
    blank=True,
)
    error_message = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.submitted_url} - {self.status}"
