from django.contrib import admin
from .models import SecurityAssessment
@admin.register(SecurityAssessment)
class SecurityAssessmentAdmin(admin.ModelAdmin):
    list_display=('submitted_url','user','status','authorization_confirmed','created_at'); list_filter=('status','authorization_confirmed','created_at'); search_fields=('submitted_url','normalized_url','user__username'); readonly_fields=('user','submitted_url','normalized_url','authorization_confirmed','authorization_confirmed_at','status','created_at','completed_at','findings','check_results')
