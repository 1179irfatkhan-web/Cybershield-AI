from django.urls import path
from .views import create_assessment, history, result
app_name='security_assessments'
urlpatterns=[path('new/',create_assessment,name='create'),path('history/',history,name='history'),path('<uuid:assessment_id>/',result,name='result')]
