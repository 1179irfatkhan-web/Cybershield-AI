def summarize_assessment(data):
    allowed=('target_hostname','overall_score','risk_level','confidence_score','completeness_percentage','category_scores','priority_findings','positive_findings','unavailable_checks','recommendations','methodology_version'); return {k:data.get(k) for k in allowed}
def generate_assessment_explanation(data):
    return 'This is an automated low-impact configuration assessment, not a complete penetration test. No exploitation or authentication testing occurred. Missing evidence does not prove safety or vulnerability. Only authorized targets should be assessed. No live CVE matching was performed in Phase 4.5.'
