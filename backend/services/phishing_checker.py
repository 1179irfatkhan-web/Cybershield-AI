import ipaddress
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = {
    "account",
    "bank",
    "confirm",
    "credential",
    "free",
    "login",
    "password",
    "payment",
    "recover",
    "secure",
    "signin",
    "support",
    "update",
    "verify",
    "wallet",
    "webscr",
}

URL_SHORTENERS = {
    "bit.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "rebrand.ly",
    "shorturl.at",
    "t.co",
    "tiny.cc",
    "tinyurl.com",
}


def _is_ip_address(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def analyze_phishing_url(url: str) -> dict:
    """
    Analyze URL-based phishing indicators.

    This function uses heuristic signals only.
    It does not confirm that a website is malicious.
    """

    parsed_url = urlparse(url)

    hostname = (parsed_url.hostname or "").lower()
    full_url = url.lower()

    indicators = []
    score_penalty = 0

    # IP address instead of a domain name
    if hostname and _is_ip_address(hostname):
        indicators.append(
            "The URL uses an IP address instead of a domain name."
        )
        score_penalty += 25

    # Internationalized domain / possible homograph indicator
    if "xn--" in hostname:
        indicators.append(
            "The domain uses Punycode. Review it carefully for possible "
            "look-alike or homograph characters."
        )
        score_penalty += 20

    # @ symbol can hide the real destination in misleading URLs
    if "@" in parsed_url.netloc:
        indicators.append(
            "The URL contains an @ symbol, which can be used to obscure "
            "the actual destination."
        )
        score_penalty += 20

    # URL shortener
    if hostname in URL_SHORTENERS:
        indicators.append(
            "The URL uses a shortening service that hides the final domain."
        )
        score_penalty += 15

    # Excessively long URL
    if len(url) > 150:
        indicators.append(
            "The URL is unusually long."
        )
        score_penalty += 10

    # Multiple subdomains
    hostname_parts = hostname.split(".")

    if len(hostname_parts) > 4:
        indicators.append(
            "The hostname contains an unusually high number of subdomains."
        )
        score_penalty += 10

    # Suspicious keywords
    matched_keywords = sorted(
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in full_url
    )

    if matched_keywords:
        indicators.append(
            "Suspicious phishing-related keywords were detected: "
            + ", ".join(matched_keywords)
            + "."
        )

        score_penalty += min(
            len(matched_keywords) * 5,
            20,
        )

    # Excessive hyphens
    if hostname.count("-") >= 3:
        indicators.append(
            "The domain contains an unusually high number of hyphens."
        )
        score_penalty += 10

    score_penalty = min(score_penalty, 100)

    if score_penalty >= 50:
        risk = "high"
        message = (
            "Multiple strong phishing indicators were detected. "
            "Avoid entering passwords, payment details, or personal data "
            "until the website is independently verified."
        )

    elif score_penalty >= 20:
        risk = "medium"
        message = (
            "Some suspicious URL characteristics were detected. "
            "Review the domain and website carefully before sharing "
            "sensitive information."
        )

    elif score_penalty > 0:
        risk = "low"
        message = (
            "Minor URL-related warning signs were detected, but they do "
            "not independently prove that the website is malicious."
        )

    else:
        risk = "low"
        message = (
            "No obvious phishing indicators were detected in the URL."
        )

    return {
        "risk": risk,
        "score_penalty": score_penalty,
        "indicator_count": len(indicators),
        "indicators": indicators,
        "message": message,
    }