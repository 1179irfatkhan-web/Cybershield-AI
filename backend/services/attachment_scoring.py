def calculate_attachment_score(evidence):
    deductions=[]; warnings=[]; positives=[]; checks={}
    if evidence.get('extension_mismatch'): deductions.append('File identity mismatch'); checks['identity']='warning'
    else: positives.append('File identity is consistent'); checks['identity']='pass'
    if evidence.get('executable_detected') or evidence.get('script_detected'): deductions.append('Executable or script content detected'); checks['execution']='warning'
    else: checks['execution']='not_detected'
    if evidence.get('macro_detected'): deductions.append('Macro content detected'); checks['embedded_content']='warning'
    else: checks['embedded_content']='not_detected'
    score=max(0,min(95,100-len(deductions)*20)); risk='critical' if score<30 else 'high' if score<55 else 'medium' if score<80 else 'low'
    return {'safety_score':score,'risk_level':risk,'confidence_score':max(0,min(100,evidence.get('confidence_score',70))),'completeness_percentage':max(0,min(100,evidence.get('completeness_percentage',60))),'deductions':deductions,'positive_findings':positives,'warnings':warnings,'check_results':checks,'methodology_version':'1.0'}
