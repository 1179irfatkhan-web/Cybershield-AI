from urllib.parse import urljoin,urlsplit
from bs4 import BeautifulSoup
def analyze_forms(html, page_url):
    soup=BeautifulSoup((html or '')[:524288],'html.parser'); out=[]; findings=[]
    for i,form in enumerate(soup.find_all('form')):
        action=urljoin(page_url,form.get('action') or page_url); method=(form.get('method') or 'get').lower(); fields=[(x.get('type') or 'text').lower() for x in form.find_all('input')]; sensitive=any(x in fields for x in ('password','email','tel'))
        item={'id':i,'method':method,'action':action,'same_origin':urlsplit(action).netloc==urlsplit(page_url).netloc,'secure_action':urlsplit(action).scheme=='https','input_types':fields,'password_present':'password' in fields,'email_present':'email' in fields,'hidden_input_count':fields.count('hidden'),'csrf_indicator':any('csrf' in str(x).lower() for x in form.find_all(['input','meta']))}
        out.append(item)
        if sensitive and method=='get': findings.append({'id':f'form_get_{i}','title':'Sensitive form uses GET','category':'forms','severity':'medium','confidence':'high','status':'warning','evidence':'A form with sensitive-looking fields uses GET.','affected_url':page_url,'recommendation':'Use POST for sensitive submissions.','reference':'','deterministic':True})
        if sensitive and urlsplit(page_url).scheme=='https' and not item['secure_action']: findings.append({'id':f'form_http_{i}','title':'Form action is not HTTPS','category':'forms','severity':'high','confidence':'high','status':'warning','evidence':'Sensitive-looking form action is not HTTPS.','affected_url':action,'recommendation':'Submit sensitive data only over HTTPS.','reference':'','deterministic':True})
    return {'form_count':len(out),'forms':out,'findings':findings,'positive_findings':[],'unavailable_checks':[],'check_results':{'forms':'completed'},'message':'Forms were parsed without submission.'}
