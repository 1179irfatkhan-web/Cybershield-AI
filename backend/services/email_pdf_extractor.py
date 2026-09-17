"""Safe, text-only extraction for exported email PDFs."""
import re
from email.utils import parseaddr, getaddresses
from pathlib import Path

class PDFExtractionError(Exception):
    def __init__(self, message, category="malformed"):
        super().__init__(message); self.category = category

EMAIL_RE = re.compile(r"(?:^|\s)([^<>\s]+@[^<>\s]+)(?:$|\s)")
URL_RE = re.compile(r"https?://[^\s<>]+", re.I)
EMAIL_TOKEN_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)

def _address(value):
    m = re.search(r"([^<>\s]+@[^<>\s]+)", value)
    return m.group(1).rstrip('>,.') if m else ""

def parse_gmail_export(text):
    lines = [x.strip() for x in text.splitlines() if x.strip()]
    result = {"provider":"gmail", "subject":"", "sender_name":"", "sender_email":"", "reply_to":"", "recipients":[], "email_body":"", "body_type":"plain_text", "links":[], "attachment_metadata":[], "dates":[], "extraction_warnings":[], "extraction_confidence":20}
    msg_indexes = [i for i, line in enumerate(lines) if re.fullmatch(r"\d+\s+messages?", line, re.I)]
    if msg_indexes:
        mi = msg_indexes[0]
        if mi and "@" not in lines[mi-1] and not re.search(r"gmail|http|/", lines[mi-1], re.I):
            result["subject"] = lines[mi-1]; result["extraction_confidence"] += 20
        # Search the whole bounded page text; body may precede headers.
        for line in lines[:80]:
            m = re.match(r"(.*?)\s*<([^>]+)>\s+(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s+", line)
            if m:
                result["sender_name"], result["sender_email"] = m.group(1).strip(), m.group(2).lower(); break
        # The first owner-style address near the message block is not sender.
        owner_candidates = [x for x in lines[:mi] if re.match(r".*<[^>]+@[^>]+>", x)]
        result["mailbox_owner"] = owner_candidates[0] if owner_candidates else ""
        if result["sender_email"]: result["extraction_confidence"] += 15
    for i, line in enumerate(lines):
        low = line.lower()
        if low.startswith("reply-to:"): result["reply_to"] = _address(line)
        elif low.startswith("to:") or low.startswith("cc:"):
            result["recipients"] += EMAIL_TOKEN_RE.findall(line)
    result["recipients"] = list(dict.fromkeys(result["recipients"]))
    if result["reply_to"]: result["extraction_confidence"] += 10
    if result["recipients"]: result["extraction_confidence"] += 10
    links = re.findall(r"(?:https?://)?(?:meet\.google\.com|www\.[^\s]+|[a-z0-9.-]+\.[a-z]{2,})/[^\s<>]+", text, re.I)
    result["links"] = list(dict.fromkeys(x.rstrip('.,)') for x in links if "mail.google.com" not in x.lower()))[:20]
    attachment = []
    for i, line in enumerate(lines[:-1]):
        if re.fullmatch(r"[^\s]+\.(?:ics|pdf|docx?|xlsx?|pptx?|zip)", line, re.I):
            size = re.match(r"(\d+(?:\.\d+)?)\s*([KMGT]B?|B)", lines[i+1], re.I)
            unit = size.group(2).upper() if size else ""
            unit = {"K":"KB", "M":"MB", "G":"GB", "T":"TB"}.get(unit, unit)
            attachment.append({"filename": line, "size": (size.group(1)+" "+unit if size else "")})
    result["attachment_metadata"] = attachment
    noise = ("1 message", "reply-to:", "to:", "cc:", "mail.google.com", "print", "page ")
    body = []
    for line in lines:
        if line in lines[:5] or line == result.get("subject") or line == result.get("mailbox_owner") or re.fullmatch(r"\d+\s+messages?", line, re.I) or re.match(r".*<[^>]+@[^>]+>\s+(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),?\s+", line) or any(line.lower().startswith(n) for n in noise) or re.fullmatch(r"\d+\s*/\s*\d+", line): continue
        if re.match(r"^\d+\s*[KMGT]B?$", line, re.I) or re.fullmatch(r"[^\s]+\.(?:ics|pdf|docx?|xlsx?|pptx?|zip)", line, re.I): continue
        body.append(line)
    result["email_body"] = "\n".join(body).strip()
    result["field_confidence"] = {"subject": "high" if result["subject"] else "missing", "sender_name": "high" if result["sender_name"] else "missing", "sender_email": "high" if result["sender_email"] else "missing", "reply_to": "high" if result["reply_to"] else "missing", "recipients": "high" if result["recipients"] else "missing", "email_body": "high" if result["email_body"] else "missing"}
    if not result["reply_to"]: result["extraction_warnings"].append("No separate Reply-To address was found. This is normal for many emails.")
    if result["email_body"]: result["extraction_confidence"] += 15
    return result

def parse_explicit_headers(text):
    lines = [x.strip() for x in text.splitlines() if x.strip()]
    out = {"provider":"generic", "subject":"", "sender_name":"", "sender_email":"", "reply_to":"", "recipients":[], "email_body":"", "body_type":"plain_text", "links":[], "attachment_metadata":[], "dates":[], "extraction_warnings":[], "extraction_confidence":35}
    labels = {"from":"sender", "sender":"sender", "reply-to":"reply", "reply to":"reply", "subject":"subject", "to":"to", "cc":"to"}
    for i, line in enumerate(lines):
        m = re.match(r"^(From|Sender|Reply[- ]To|To|Cc|Subject)\s*(?::|\t| {2,})\s*(.*)$", line, re.I)
        if not m and re.match(r"^(From|Sender|Reply[- ]To|To|Cc|Subject)\s*:?$", line, re.I) and i + 1 < len(lines):
            m = re.match(r"^(From|Sender|Reply[- ]To|To|Cc|Subject)\s*:?$", line, re.I); val = lines[i+1]
        elif m: val = m.group(2).strip()
        else: continue
        kind = labels[m.group(1).lower()]
        if kind == "subject" and not out["subject"]: out["subject"] = val
        elif kind == "sender" and not out["sender_email"]:
            name, email = parseaddr(val); out["sender_name"], out["sender_email"] = name.strip(), email.lower()
        elif kind == "reply": out["reply_to"] = parseaddr(val)[1].lower() or _address(val).lower()
        elif kind == "to": out["recipients"].extend(a.lower() for _, a in getaddresses([val]) if a)
    out["recipients"] = list(dict.fromkeys(out["recipients"]))
    if out["sender_email"] or out["subject"]:
        out["email_body"] = text
        return out
    return None

def extract_email_pdf(path, *, max_pages=20, max_text=250000):
    try:
        from pypdf import PdfReader
        reader = PdfReader(str(path), strict=True)
        if reader.is_encrypted:
            raise PDFExtractionError("This PDF is encrypted and cannot be read safely.", "encrypted")
        if len(reader.pages) > max_pages:
            raise PDFExtractionError("This PDF has too many pages to import.", "too_many_pages")
        text = "\n".join((page.extract_text() or "") for page in reader.pages)
    except PDFExtractionError:
        raise
    except Exception as exc:
        raise PDFExtractionError("The PDF is malformed or unsupported.", "malformed") from exc
    if len(text) > max_text:
        raise PDFExtractionError("This PDF contains too much text to import.", "text_limit")
    if not text.strip():
        return {"subject":"", "sender_name":"", "sender_email":"", "reply_to":"", "recipients":[], "email_body":"", "body_type":"plain_text", "links":[], "attachment_metadata":[], "dates":[], "extraction_warnings":["This PDF appears to contain scanned images. Automatic extraction is not available yet. Please paste the email text or enter the details manually."], "extraction_confidence":0}
    explicit = parse_explicit_headers(text)
    if explicit:
        return explicit
    if re.search(r"\b\d+\s+messages?\b", text, re.I) and ("gmail" in text.lower() or re.search(r"<[^>]+@[^>]+>", text)):
        return parse_gmail_export(text)
    lines = [line.strip() for line in text.splitlines()]
    def value(label):
        for i, line in enumerate(lines):
            if line.lower().startswith(label.lower() + ":"):
                return line.split(":", 1)[1].strip()
        return ""
    sender = value("From") or value("Sender"); reply = value("Reply-To")
    match = re.search(r"^(.*?)\s*<([^<>]+)>$", sender)
    sender_name, sender_email = (match.group(1).strip(' "'), match.group(2).strip()) if match else ("", sender)
    if not sender_email:
        m = EMAIL_RE.search(sender); sender_email = m.group(1) if m else ""
    recipients = []
    for label in ("To", "CC"):
        recipients.extend(EMAIL_RE.findall(value(label)))
    subject = value("Subject")
    links = list(dict.fromkeys(URL_RE.findall(text)))[:20]
    attachments = [line for line in lines if re.search(r"\.(?:pdf|docx?|xlsx?|pptx?|ics|zip)\b", line, re.I)]
    headers = {"From", "Sender", "Reply-To", "To", "CC", "Subject", "Date", "Meeting link", "Attachment"}
    body_lines = [line for line in lines if not any(line.lower().startswith(h.lower()+":") for h in headers)]
    return {"subject":subject, "sender_name":sender_name, "sender_email":sender_email, "reply_to":reply, "recipients":recipients[:50], "email_body":"\n".join(body_lines).strip(), "body_type":"plain_text", "links":links, "attachment_metadata":list(dict.fromkeys(attachments))[:20], "dates":[value("Date")] if value("Date") else [], "extraction_warnings":[], "extraction_confidence":80}
