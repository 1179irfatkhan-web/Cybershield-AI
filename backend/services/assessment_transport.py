"""Assessment transport adapter reusing the Website Scanner's hardened request path."""
from services.url_validator import validate_url, URLValidationError
from services.redirect_checker import fetch_website, WebsiteRequestError
from services.assessment_context import CanonicalResponseContext
def assess_transport(url, **kwargs):
    try:
        target=validate_url(url); result=fetch_website(target, scan_id=kwargs.get("scan_id"))
        final=result.get('final_url',url); https=final.lower().startswith('https://')
        context=CanonicalResponseContext(url,target.normalized_url,final,result.get('status_code'),{str(k).lower():str(v) for k,v in result.get('headers',{}).items()},result.get('set_cookie_headers',[]),(result.get('body_text',result.get('text','')) or '')[:524288],result.get('content_type',''),result.get('redirect_chain',[]),len(result.get('redirect_chain',[])),https,0,{})
        return {'status':'completed','context':context,'submitted_url':url,'normalized_url':target.normalized_url,'final_url':final,'status_code':context.status_code,'headers':context.headers,'set_cookie_headers':context.set_cookie_headers,'bounded_body_text':context.bounded_body,'content_type':context.content_type,'redirect_chain':context.redirect_chain,'https_available':https,'uses_https_final':https,'http_to_https_redirect':url.lower().startswith('http://') and https,'https_to_http_downgrade':url.lower().startswith('https://') and not https,'redirect_count':context.redirect_count,'tls_checked':https,'tls_valid':None,'tls_expired':None,'tls_not_yet_valid':None,'tls_days_remaining':None,'tls_version':'','cipher':'','issuer':'','subject':'','hostname_match':None,'mixed_content_count':0,'mixed_content_findings':[],'findings':[],'positive_findings':[],'unavailable_checks':['tls_details'],'check_results':{'transport':'completed'},'error_category':'','message':'Bounded target response retrieved.'}
    except URLValidationError:
        return {'status':'failed','submitted_url':url,'final_url':'','findings':[],'positive_findings':[],'unavailable_checks':['https','tls','redirects','mixed_content'],'check_results':{'transport':'failed'},'error_category':'blocked_destination','message':'The target could not be assessed safely.'}
    except WebsiteRequestError as exc:
        return {'status':'failed','submitted_url':url,'final_url':'','findings':[],'positive_findings':[],'unavailable_checks':['https','tls','redirects','mixed_content'],'check_results':{'transport':'failed'},'error_category':'connection_failure','message':'CyberShield AI could not connect to the website.'}
