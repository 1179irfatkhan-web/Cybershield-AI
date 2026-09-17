from django.contrib import admin
from .models import AttachmentScan
@admin.register(AttachmentScan)
class AttachmentScanAdmin(admin.ModelAdmin):
    list_display=('original_filename','user','status','risk_level','safety_score','created_at')
    readonly_fields=('id','user','md5_hash','sha1_hash','sha256_hash','created_at','completed_at','check_results')
