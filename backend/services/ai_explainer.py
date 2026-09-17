import logging
import time

from decouple import config
from google import genai


logger = logging.getLogger(__name__)


class AIExplanationError(Exception):
    """Raised when Gemini cannot generate a security explanation."""


def generate_security_explanation(scan) -> str:
    """
    Generate a human-readable explanation from deterministic scan results.

    Gemini explains the scanner findings only.
    It does not calculate or modify the trust score.
    """

    try:
        api_key = config("GEMINI_API_KEY")
        model_name = config("GEMINI_MODEL")

        if not str(api_key).strip():
            raise ValueError("Missing Gemini API key.")

        if not str(model_name).strip():
            raise ValueError("Missing Gemini model.")

        client = genai.Client(api_key=api_key)

    except Exception as error:
        logger.error(
            "Gemini configuration or client initialization failed (%s).",
            type(error).__name__,
        )
        raise AIExplanationError(
            "Gemini is not configured or could not be initialized."
        ) from error

    phishing_indicators = scan.phishing_indicators or []
    score_breakdown = scan.score_breakdown or []
    check_results = getattr(scan, "check_results", {}) or {}

    if scan.is_managed_subdomain:
        domain_context = f"""
Domain: {scan.domain_name or "Unavailable"}
Domain Type: Managed Subdomain
Hosting Provider: {scan.hosting_provider or "Unavailable"}
Root Domain: {scan.root_domain or "Unavailable"}
WHOIS Status: WHOIS is unavailable because this website uses a managed cloud-hosting subdomain.
Domain Risk: {scan.domain_risk or "Unknown"}
Domain Finding: {scan.domain_message or "Unavailable"}
"""
    else:
        domain_context = f"""
Domain: {scan.domain_name or "Unavailable"}
Domain Type: {scan.domain_type or "Registered Domain"}
Root Domain: {scan.root_domain or scan.domain_name or "Unavailable"}
Registrar: {scan.domain_registrar or "Unavailable"}
Created Date: {scan.domain_created_at or "Unavailable"}
Expiration Date: {scan.domain_expires_at or "Unavailable"}
Domain Age: {scan.domain_age_days if scan.domain_age_days is not None else "Unavailable"} days
Domain Risk: {scan.domain_risk or "Unknown"}
Domain Finding: {scan.domain_message or "Unavailable"}
"""

    prompt = f"""
You are a cybersecurity report assistant for CyberShield AI.

Explain the deterministic security scan findings below.

Important rules:
- Do not modify or recalculate the trust score.
- Do not claim that the website is completely safe.
- Do not claim that it is malicious without conclusive evidence.
- Explain that phishing heuristics are warning signals, not proof.
- Use clear language for non-technical users.
- Keep the response between 150 and 250 words.
- Do not use Markdown tables.
- Do not invent information.
- When the website uses a managed subdomain, explain that missing WHOIS
  information is expected and is not automatically a security problem.

Website: {scan.submitted_url}
Final URL: {scan.final_url or "Unavailable"}

Trust Score: {scan.trust_score}/100
Overall Risk: {scan.risk_level or "Unknown"}
Confidence Score: {getattr(scan, "confidence_score", "Unavailable")}/100
Scan Completeness: {getattr(scan, "completeness_percentage", "Unavailable")}%
Check States: {check_results}
Resolved public IPv4: {getattr(scan, "resolved_ipv4", [])}
Resolved public IPv6: {getattr(scan, "resolved_ipv6", [])}
IP data is informational only and does not prove trustworthiness or maliciousness.
Score Deductions: {score_breakdown}

HTTPS Enabled: {scan.uses_https}
HTTPS Finding: {scan.https_message or "Unavailable"}

HTTP Status Code: {scan.http_status_code or "Unavailable"}

Redirect Count: {scan.redirect_count}
Redirect Risk: {scan.redirect_risk or "Unknown"}
Redirect Finding: {scan.redirect_message or "Unavailable"}

{domain_context}

Phishing Risk: {scan.phishing_risk or "Unknown"}
Phishing Indicator Count: {scan.phishing_indicator_count}
Phishing Indicators: {phishing_indicators}
Phishing Finding: {scan.phishing_message or "Unavailable"}

Write the response using these headings:

Overall Assessment
Positive Findings
Potential Risks
Recommendations
Safety Note
"""

    last_error = None

    for attempt in range(2):
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=prompt,
            )

            explanation = (response.text or "").strip()

            if not explanation:
                raise AIExplanationError(
                    "Gemini returned an empty response."
                )

            return explanation

        except Exception as error:
            last_error = error

            logger.warning(
                "Gemini explanation failed on attempt %s (%s).",
                attempt + 1,
                type(error).__name__,
            )

            if attempt == 0:
                time.sleep(2)

    raise AIExplanationError(
        "Gemini could not generate a security explanation."
    ) from last_error
