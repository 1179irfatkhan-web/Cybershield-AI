import logging
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.shortcuts import get_object_or_404,redirect,render
from django.utils import timezone
from .forms import AssessmentForm
from .models import SecurityAssessment
from services.assessment_pipeline import run_security_assessment
logger=logging.getLogger(__name__)
def _friendly_findings(items):
    out=[]
    for item in items or []:
        copy=dict(item); title=copy.get('title','Finding').replace(' missing',' was not detected').replace('-',' ').replace('_',' '); copy['display_title']=title[:1].upper()+title[1:]; out.append(copy)
    return out
FAILURES={'dns_failure':('Website address could not be resolved','CyberShield AI could not find a public network address for this website.',['Check the spelling of the domain.','Confirm the domain is active.','Try again after DNS changes have propagated.']),'connection_timeout':('The website took too long to respond','The website did not respond within the safe assessment time limit.',['Confirm the website opens in your browser.','Retry after a few minutes.','Check whether the website blocks automated security tools.']),'tls_failure':('A secure connection could not be established','CyberShield AI could not validate the website’s secure HTTPS connection.',['Confirm the HTTPS certificate is valid.','Review hosting or certificate configuration.']),'blocked_destination':('The destination could not be assessed safely','The website resolved or redirected to a network address that CyberShield AI does not allow for security reasons.',['Confirm the target is a public website.','Private and internal-network targets cannot be assessed.']),'unsafe_redirect':('A website redirect was blocked','The website redirected to a destination that could not be safely assessed.',['Review where the submitted URL redirects.','Confirm that the final destination is public and expected.']),'response_too_large':('The website response was too large','The returned page exceeded CyberShield AI’s safe analysis limit',['Try a smaller public page.']),'unexpected_failure':('The assessment could not be completed','An unexpected problem prevented CyberShield AI from completing the assessment safely.',['Retry the assessment later.'])}
@login_required
def create_assessment(request):
    form=AssessmentForm(request.POST or None, initial={'submitted_url':request.GET.get('submitted_url','')})
    if request.method=='POST' and form.is_valid():
        try:
            key=f'assessment-rate:{request.user.pk}'; count=cache.get(key,0)
            if count>=settings.SECURITY_ASSESSMENT_RATE_LIMIT_COUNT:
                form.add_error(None,'Assessment limit reached. Please try again later.'); logger.info('assessment_rate_limited user_id=%s',request.user.id); return render(request,'security_assessments/create.html',{'form':form})
            cache.set(key,count+1,settings.SECURITY_ASSESSMENT_RATE_LIMIT_WINDOW_SECONDS)
        except Exception as exc: logger.warning('assessment_rate_check_failed category=%s',type(exc).__name__)
        now=timezone.now(); assessment=SecurityAssessment.objects.create(user=request.user,submitted_url=request.POST['submitted_url'],normalized_url=form.cleaned_data['submitted_url'],authorization_confirmed=True,authorization_confirmed_at=now,status='pending',target_scope={'submitted_page':form.cleaned_data['submitted_url'],'phase':'4.5','checks':'transport and passive configuration checks'}); run_security_assessment(assessment); logger.info('assessment_request_created assessment_id=%s user_id=%s',assessment.id,request.user.id); return redirect('security_assessments:result',assessment_id=assessment.id)
    return render(request,'security_assessments/create.html',{'form':form})
@login_required
def result(request,assessment_id):
    assessment=get_object_or_404(request.user.security_assessments,id=assessment_id); failure=FAILURES.get(assessment.error_category,FAILURES['unexpected_failure']); logger.info('assessment_viewed assessment_id=%s user_id=%s status=%s',assessment.id,request.user.id,assessment.status); return render(request,'security_assessments/result.html',{'assessment':assessment,'failure':failure,'display_findings':_friendly_findings(assessment.findings)})
@login_required
def history(request):
    return render(request,'security_assessments/history.html',{'assessments':request.user.security_assessments.all()})
