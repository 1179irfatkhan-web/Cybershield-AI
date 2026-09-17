def analyze_headers(headers, final_is_https=False):
    h={str(k).lower():str(v) for k,v in headers.items()}; present=[]; missing=[]; weak=[]; findings=[]; positive=[]
    rules=['strict-transport-security','content-security-policy','x-frame-options','x-content-type-options','referrer-policy','permissions-policy','cross-origin-opener-policy','cross-origin-embedder-policy','cross-origin-resource-policy']
    for key in rules:
        if key in h: present.append(key); positive.append({'id':key+'_present','title':key+' present','category':'headers','severity':'info','confidence':'high','status':'passed','evidence':'Header present.','affected_url':'','recommendation':'','reference':'','deterministic':True})
        elif key!='strict-transport-security' or final_is_https: missing.append(key)
    if 'content-security-policy' in h and any(x in h['content-security-policy'].lower() for x in ('unsafe-inline','unsafe-eval')): weak.append('content-security-policy')
    if 'x-content-type-options' in h and h['x-content-type-options'].lower()!='nosniff': weak.append('x-content-type-options')
    for key in missing: findings.append({'id':key+'_missing','title':key+' missing','category':'headers','severity':'low','confidence':'high','status':'warning','evidence':'Header was not present in the response.','affected_url':'','recommendation':'Consider adding this defense-in-depth header.','reference':'','deterministic':True})
    return {'status':'completed','present_headers':present,'missing_headers':missing,'weak_headers':weak,'findings':findings,'positive_findings':positive,'unavailable_checks':[],'check_results':{k:('present' if k in present else 'missing') for k in rules},'message':'Header analysis is passive and based only on the observed response.'}
