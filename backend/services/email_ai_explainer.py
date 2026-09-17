import logging
from decouple import config
from google import genai

logger = logging.getLogger(__name__)

def generate_email_explanation(scan):
    try:
        client = genai.Client(api_key=config("GEMINI_API_KEY"))
        prompt = f"Explain deterministic email findings without reproducing private content or claiming certainty: score={scan.safety_score}, risk={scan.risk_level}, warnings={scan.warning_findings}, deductions={scan.score_breakdown}, links={len(scan.extracted_links)}. Recommend safe verification steps."
        text = (client.models.generate_content(model=config("GEMINI_MODEL"), contents=prompt).text or "").strip()
        if not text: raise ValueError("empty response")
        return text
    except Exception as error:
        logger.warning("email Gemini explanation unavailable category=%s", type(error).__name__)
        return "AI explanation is unavailable. Review the deterministic warnings and verify the message through a trusted channel."
