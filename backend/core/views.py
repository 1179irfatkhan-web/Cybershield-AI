from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from scans.models import WebsiteScan


def home(request):
    return render(request, "core/home.html")


@login_required
def dashboard(request):
    recent_scans = WebsiteScan.objects.filter(
        user=request.user
    )[:5]

    return render(
        request,
        "core/dashboard.html",
        {
            "recent_scans": recent_scans,
        },
    )