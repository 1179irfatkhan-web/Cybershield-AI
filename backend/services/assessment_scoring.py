CATEGORY_WEIGHTS={'transport':15,'headers':20,'cookies':15,'forms':15,'exposure':15,'cors':10,'public_files':5,'technology':5}
def calculate_assessment_score(categories, unavailable=(), minimum_completeness=50, findings=None):
    earned=0; available=0; scores={}; completed=[]
    for name,maximum in CATEGORY_WEIGHTS.items():
        item=categories.get(name) or {}; status=item.get('status','unavailable'); raw=item.get('score')
        if status in {'completed','partial'} and isinstance(raw,(int,float)):
            value=max(0,min(maximum,int(raw))); scores[name]={'score':value,'maximum_score':maximum,'status':status}; earned+=value; available+=maximum; completed.append(name)
        else: scores[name]={'score':None,'maximum_score':maximum,'status':'unavailable' if name in unavailable or not item else status}
    completeness=round(len(completed)/len(CATEGORY_WEIGHTS)*100)
    overall=round(earned/available*100) if available and completeness>=minimum_completeness else None
    evidence = list(findings or [])
    for item in categories.values():
        evidence.extend(item.get('findings', []) if isinstance(item, dict) else [])
    severities = {str(item.get('severity', '')).lower() for item in evidence if isinstance(item, dict)}
    if 'critical' in severities:
        risk = 'critical'
    elif 'high' in severities:
        risk = 'high'
    elif 'medium' in severities:
        risk = 'medium'
    elif severities & {'low', 'info'}:
        risk = 'low'
    elif overall is None:
        risk = 'unknown'
    else:
        risk = 'low' if overall >= 85 else 'medium' if overall >= 70 else 'high' if overall >= 40 else 'critical'
    return {'overall_score':overall,'risk_level':risk,'confidence_score':completeness,'completeness_percentage':completeness,'category_scores':scores,'deductions':[],'positive_findings':[],'priority_findings':[],'recommendations':[],'unavailable_checks':list(unavailable),'check_results':{k:v['status'] for k,v in scores.items()},'methodology_version':'1.0'}
