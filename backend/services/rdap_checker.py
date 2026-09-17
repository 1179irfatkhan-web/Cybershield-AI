import logging
import time
from datetime import datetime
from urllib.parse import quote
import requests
from django.conf import settings

logger = logging.getLogger(__name__)
BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_bootstrap_cache = {"expires": 0, "services": {}}

def _bootstrap():
    now = time.monotonic()
    if _bootstrap_cache["expires"] > now:
        return _bootstrap_cache["services"]
    response = requests.get(BOOTSTRAP_URL, timeout=(settings.RDAP_BOOTSTRAP_CONNECT_TIMEOUT, settings.RDAP_BOOTSTRAP_READ_TIMEOUT))
    data = response.json()
    services = {}
    for entry in data.get("services", []):
        if len(entry) != 2 or not isinstance(entry[0], list) or not isinstance(entry[1], list):
            continue
        for tld in entry[0]:
            for base in entry[1]:
                if str(base).startswith("https://"):
                    services[str(tld).lower()] = str(base).rstrip("/")
    if not services:
        raise ValueError("RDAP bootstrap contained no usable services")
    _bootstrap_cache.update(expires=now + settings.RDAP_CACHE_LIFETIME, services=services)
    return services

def lookup_rdap(domain):
    try:
        tld = domain.rsplit(".", 1)[-1].lower()
        base = _bootstrap().get(tld)
        if not base:
            return {"available": False, "source": "rdap", "error_category": "unsupported_tld", "message": "RDAP is not available for this TLD."}
        response = requests.get(f"{base}/domain/{quote(domain, safe='.-')}", timeout=(settings.RDAP_QUERY_CONNECT_TIMEOUT, settings.RDAP_QUERY_READ_TIMEOUT), headers={"Accept": "application/rdap+json"})
        if response.status_code == 404:
            return {"available": False, "source": "rdap", "error_category": "not_found", "message": "RDAP has no record for this domain."}
        response.raise_for_status(); data = response.json()
        events = {event.get("eventAction"): event.get("eventDate") for event in data.get("events", []) if isinstance(event, dict)}
        registrar = ""
        for entity in data.get("entities", []):
            for role in entity.get("roles", []):
                if role == "registrar": registrar = entity.get("vcardArray", [None, []])[1][1][3] if entity.get("vcardArray") else ""
        return {"available": True, "source": "rdap", "queried_domain": domain, "handle": data.get("handle", ""), "registrar": registrar, "registration_date": events.get("registration"), "expiration_date": events.get("expiration"), "updated_date": events.get("last changed"), "statuses": data.get("status", []), "nameservers": [item.get("ldhName") for item in data.get("nameservers", []) if item.get("ldhName")], "secure_dns": data.get("secureDNS", {}), "notices": data.get("notices", []), "error_category": "", "message": "RDAP registration data retrieved."}
    except Exception as error:
        logger.warning("RDAP lookup unavailable domain=%s category=%s", domain, type(error).__name__)
        return {"available": False, "source": "rdap", "error_category": type(error).__name__, "message": "RDAP registration data is unavailable."}
