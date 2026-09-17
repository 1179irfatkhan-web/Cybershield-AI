from django.urls import path
from .views import create_scan, history, result
app_name='attachment_scans'
urlpatterns=[path('new/',create_scan,name='create'),path('history/',history,name='history'),path('<uuid:scan_id>/',result,name='result')]
