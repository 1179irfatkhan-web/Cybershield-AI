"""Privacy-preserving attachment explanation; deterministic evidence stays authoritative."""
def summarize_attachment_findings(scan):
    return {'filename': scan.original_filename, 'type': scan.detected_extension, 'score': scan.safety_score, 'risk': scan.risk_level, 'confidence': scan.confidence_score, 'completeness': scan.completeness_percentage, 'warnings': scan.warning_findings, 'checks': scan.check_results}
def generate_attachment_explanation(scan):
    return (f"Overall assessment: static analysis rated this file {scan.risk_level or 'unknown'} with a score of {scan.safety_score if scan.safety_score is not None else 'unavailable'}/100. Static analysis cannot guarantee safety. Do not open or execute a suspicious file. A clean result does not prove harmlessness; verify it through a trusted source.")
