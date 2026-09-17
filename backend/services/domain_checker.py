import logging
from datetime import date, datetime, timezone
from urllib.parse import urlparse
from services.rdap_checker import lookup_rdap
from django.conf import settings

import whois


logger = logging.getLogger(__name__)


class DomainCheckError(Exception):
    """Raised only when the URL hostname cannot be identified."""


MANAGED_SUBDOMAIN_PROVIDERS = {
    "netlify.app": "Netlify",
    "vercel.app": "Vercel",
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "pages.dev": "Cloudflare Pages",
    "web.app": "Firebase Hosting",
    "firebaseapp.com": "Firebase Hosting",
    "azurewebsites.net": "Microsoft Azure",
    "onrender.com": "Render",
    "railway.app": "Railway",
    "pythonanywhere.com": "PythonAnywhere",
}


def _extract_date(value):
    """
    Convert WHOIS date values into a Python date.
    """

    if isinstance(value, list):
        value = next(
            (item for item in value if item is not None),
            None,
        )

    if isinstance(value, datetime):
        return value.date()

    if isinstance(value, date):
        return value

    return None


def _detect_managed_subdomain(hostname: str):
    """
    Detect whether the hostname belongs to a managed hosting platform.
    """

    for root_domain, provider in MANAGED_SUBDOMAIN_PROVIDERS.items():
        if hostname == root_domain:
            return None

        if hostname.endswith(f".{root_domain}"):
            return {
                "provider": provider,
                "root_domain": root_domain,
            }

    return None

def _registrable_domain(hostname):
    labels = hostname.split(".")
    if len(labels) < 2:
        return hostname
    if len(labels) >= 3 and ".".join(labels[-2:]) in {"co.uk", "org.uk", "ac.uk", "com.au", "co.jp"}:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])

def _rdap_date(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except (TypeError, ValueError):
        return None


def analyze_domain(url: str) -> dict:
    """
    Analyze domain registration information.

    WHOIS failures do not fail the complete scan. The detected hostname
    remains available even when registration information cannot be fetched.
    """

    parsed_url = urlparse(url)
    hostname = parsed_url.hostname

    if not hostname:
        raise DomainCheckError(
            "The website hostname could not be identified."
        )

    hostname = hostname.lower().rstrip(".")

    if hostname.startswith("www."):
        hostname = hostname[4:]

    managed_subdomain = _detect_managed_subdomain(hostname)

    if managed_subdomain:
        provider = managed_subdomain["provider"]
        root_domain = managed_subdomain["root_domain"]

        return {
            "domain_name": hostname,
            "registrar": "",
            "creation_date": None,
            "expiration_date": None,
            "age_days": None,
            "risk": "unknown",
            "message": (
                "WHOIS information is not available because this website "
                "uses a managed cloud-hosting subdomain."
            ),
            "hosting_provider": provider,
            "domain_type": "Managed Subdomain",
            "root_domain": root_domain,
            "is_managed_subdomain": True,
            "registration_data_source": "unavailable", "rdap_available": False, "whois_available": False, "domain_statuses": [], "nameservers": [], "dnssec_status": "not_applicable", "registration_updated_at": None,
        }

    root_domain = _registrable_domain(hostname)
    rdap = lookup_rdap(root_domain)
    if rdap.get("available"):
        creation_date = _rdap_date(rdap.get("registration_date"))
        expiration_date = _rdap_date(rdap.get("expiration_date"))
        age = (datetime.now(timezone.utc).date() - creation_date).days if creation_date else None
        risk = "unknown" if age is None else "high" if age < 30 else "medium" if age < 180 else "low"
        return {"domain_name": hostname, "registrar": rdap.get("registrar", ""), "creation_date": creation_date, "expiration_date": expiration_date, "age_days": age, "risk": risk, "message": "RDAP registration data retrieved.", "hosting_provider": "", "domain_type": "Registered Domain", "root_domain": root_domain, "is_managed_subdomain": False, "registration_data_source": "rdap", "rdap_available": True, "whois_available": False, "domain_statuses": rdap.get("statuses", []), "nameservers": rdap.get("nameservers", []), "dnssec_status": str(rdap.get("secure_dns", {}).get("delegationSigned", "unknown")), "registration_updated_at": _rdap_date(rdap.get("updated_date"))}

    # Preserve these values even when WHOIS fails.
    registrar = ""
    creation_date = None
    expiration_date = None
    domain_age_days = None
    whois_available = False

    try:
        if not settings.WHOIS_FALLBACK_ENABLED:
            raise RuntimeError("WHOIS fallback disabled")
        domain_info = whois.whois(root_domain)

        registrar = domain_info.registrar or ""
        creation_date = _extract_date(
            domain_info.creation_date
        )
        expiration_date = _extract_date(
            domain_info.expiration_date
        )

        whois_available = bool(
            registrar
            or creation_date
            or expiration_date
        )

    except Exception as error:
        # WHOIS is optional intelligence. Do not emit a traceback or expose
        # library/server details to the user when registries return no data.
        logger.warning(
            "WHOIS lookup unavailable hostname=%s error_category=%s",
            hostname,
            type(error).__name__,
        )

    if creation_date:
        domain_age_days = (
            datetime.now(timezone.utc).date()
            - creation_date
        ).days

    if not whois_available:
        domain_risk = "unknown"
        domain_message = (
            "The domain was identified successfully, but WHOIS "
            "registration information could not be retrieved. "
            "This may happen when a registry does not provide compatible "
            "WHOIS data or when its server is temporarily unavailable."
        )

    elif domain_age_days is None:
        domain_risk = "unknown"
        domain_message = (
            "WHOIS information was partially available, but the domain "
            "creation date could not be determined."
        )

    elif domain_age_days < 30:
        domain_risk = "high"
        domain_message = (
            "This domain appears to be less than 30 days old. "
            "Very new domains require additional caution."
        )

    elif domain_age_days < 180:
        domain_risk = "medium"
        domain_message = (
            "This domain appears to be less than six months old. "
            "Review the website carefully before sharing information."
        )

    else:
        domain_risk = "low"
        domain_message = (
            "The domain has been registered for more than six months. "
            "Domain age alone does not guarantee that the website is safe."
        )

    return {
            "domain_name": hostname,
        "registrar": str(registrar),
        "creation_date": creation_date,
        "expiration_date": expiration_date,
        "age_days": domain_age_days,
        "risk": domain_risk,
        "message": domain_message,
        "hosting_provider": "",
        "domain_type": "Registered Domain",
        "root_domain": hostname,
        "is_managed_subdomain": False,
        "registration_data_source": "whois" if whois_available else "unavailable",
        "rdap_available": False,
        "whois_available": whois_available,
        "domain_statuses": [], "nameservers": [], "dnssec_status": "unknown", "registration_updated_at": None,
    }
