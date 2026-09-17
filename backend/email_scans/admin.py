from django.contrib import admin
from .models import EmailScan

@admin.register(EmailScan)
class EmailScanAdmin(admin.ModelAdmin):
    list_display = ("subject", "sender_email", "user", "status", "safety_score", "risk_level", "created_at")
    list_filter = ("status", "risk_level", "created_at")
    search_fields = ("subject", "sender_email", "user__username")
    readonly_fields = ("id", "user", "email_body", "created_at", "completed_at", "safety_score", "confidence_score", "completeness_percentage", "check_results")
