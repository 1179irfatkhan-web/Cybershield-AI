from django.contrib import admin
from .models import WebsiteScan


@admin.register(WebsiteScan)
class WebsiteScanAdmin(admin.ModelAdmin):
    list_display = ("submitted_url", "user", "status", "trust_score", "confidence_score", "created_at")
    list_filter = ("status", "risk_level", "created_at")
    search_fields = ("submitted_url", "normalized_url", "user__username")
    readonly_fields = ("id", "created_at", "completed_at", "trust_score", "confidence_score", "check_results", "stage_durations_ms")
