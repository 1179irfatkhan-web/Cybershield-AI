from http.cookies import SimpleCookie
def analyze_cookies(set_cookie_headers, https=False):
    cookies=[]; findings=[]; positive=[]
    for raw in set_cookie_headers or []:
        c=SimpleCookie(); c.load(raw)
        for name,m in c.items():
            item={'name':name,'secure':bool(m['secure']),'httponly':bool(m['httponly']),'samesite':m['samesite'] or '','domain':m['domain'] or '','path':m['path'] or '','max_age_present':bool(m['max-age']),'expires_present':bool(m['expires'])}
            cookies.append(item)
            if https and not item['secure']: findings.append({'id':'cookie_secure_'+name,'title':'Cookie missing Secure','category':'cookies','severity':'medium','confidence':'high','status':'warning','evidence':'A cookie returned over HTTPS lacks the Secure attribute.','affected_url':'','recommendation':'Set Secure on sensitive cookies.','reference':'','deterministic':True})
            if not item['httponly']: findings.append({'id':'cookie_http_'+name,'title':'Cookie missing HttpOnly','category':'cookies','severity':'low','confidence':'high','status':'warning','evidence':'Cookie is accessible to client-side scripts.','affected_url':'','recommendation':'Consider HttpOnly for sensitive cookies.','reference':'','deterministic':True})
            if not item['samesite']: findings.append({'id':'cookie_same_'+name,'title':'Cookie missing SameSite','category':'cookies','severity':'low','confidence':'high','status':'warning','evidence':'SameSite was not specified.','affected_url':'','recommendation':'Set an appropriate SameSite value.','reference':'','deterministic':True})
    return {'cookie_count':len(cookies),'cookies':cookies,'findings':findings,'positive_findings':positive,'unavailable_checks':[],'check_results':{'cookies':'completed'},'message':'Cookie values are never stored.'}
