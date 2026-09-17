import ipaddress
import re
from urllib.parse import urlparse

MAX_LINKS = 20
URGENT = {"urgent", "immediately", "suspend", "suspended", "verify", "action required", "final notice"}
SENSITIVE = {"password", "credential", "login", "reset", "payment", "invoice", "bank", "wallet", "gift card"}
RISKY_EXTENSIONS = (".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".docm", ".xlsm", ".pptm", ".msi")

def analyze_email(data):
    body = data.get("email_body", "")
    lowered = re.sub(r"<[^>]+>", " ", body).lower()
    sender = (data.get("sender_email") or "").lower().split("@")[-1]
    reply = (data.get("reply_to") or "").lower().split("@")[-1]
    mismatch = bool(sender and reply and sender != reply)
    links = list(dict.fromkeys(re.findall(r"https?://[^\s<>'\"]+", body)))[:MAX_LINKS]
    keywords = sorted({term for term in URGENT | SENSITIVE if term in lowered})
    flags = []
    for link in links:
        host = (urlparse(link).hostname or "").lower()
        try: ipaddress.ip_address(host); flags.append("IP-based URL")
        except ValueError: pass
        if host.startswith("xn--"): flags.append("Punycode URL")
        if host in {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"}: flags.append("Shortened URL")
        if "@" in urlparse(link).netloc: flags.append("URL contains @")
        if len(link) > 150: flags.append("Long URL")
    forms = bool(re.search(r"<form\b", body, re.I))
    html_indicators = [name for name, pattern in (("form", r"<form\b"), ("password_input", r"<input[^>]+type=[\"']password"), ("script", r"<script\b"), ("iframe", r"<iframe\b"), ("remote_image", r"<img[^>]+src=[\"']https?"), ("tracking_pixel", r"<img[^>]+(?:width|height)=[\"']?[01]\b")) if re.search(pattern, body, re.I)]
    display_mismatch = bool(data.get("sender_name") and sender and sender not in str(data.get("sender_name")).lower() and "support" in str(data.get("sender_name")).lower())
    language_flags = sorted(set(keywords + (["excessive_uppercase"] if sum(c.isupper() for c in body) > max(20, len(body) // 2) else []) + (["excessive_punctuation"] if re.search(r"!{2,}|\?{2,}", body) else [])))
    hidden = sum(1 for href, visible in re.findall(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', body, re.I | re.S) if (urlparse(visible.strip()).hostname and urlparse(visible.strip()).hostname != urlparse(href).hostname))
    attachments = data.get("attachment_metadata") or []
    risky = [item for item in attachments if str(item).lower().endswith(RISKY_EXTENSIONS)]
    warnings = (["Sender and Reply-To domains differ."] if mismatch else []) + (["Suspicious display name detected."] if display_mismatch else []) + (["HTML security indicators detected."] if html_indicators else []) + (["Hidden link destination mismatch detected."] if hidden else []) + (["Risky attachment metadata detected."] if risky else [])
    return {"sender_mismatch": mismatch or display_mismatch, "reply_to_mismatch": mismatch, "display_name_mismatch": display_mismatch, "html_form_detected": forms, "html_indicators": html_indicators, "hidden_link_mismatch_count": hidden, "extracted_links": links, "link_findings": sorted(set(flags)), "link_flags": sorted(set(flags)), "suspicious_keywords": language_flags, "attachment_metadata": risky or attachments, "warnings": warnings}
