from django.urls import path

from .views import create_scan, scan_result

app_name = "scans"

urlpatterns = [
    path("new/", create_scan, name="create"),
    path("<uuid:scan_id>/", scan_result, name="result"),
]