from django.urls import path
from .views import create_email_scan, email_history, email_result, import_pdf
app_name = "email_scans"
urlpatterns = [path("new/", create_email_scan, name="create"), path("import-pdf/", import_pdf, name="import_pdf"), path("history/", email_history, name="history"), path("<uuid:scan_id>/", email_result, name="result")]
