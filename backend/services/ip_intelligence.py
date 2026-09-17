import ipaddress
import logging
from services.url_validator import NAT64_PREFIX, URLValidationError, classify_ip

logger = logging.getLogger(__name__)


def summarize_vetted_target(target):
    """Summarize only addresses already vetted by URL validation."""
    ipv4, ipv6, nat64_mappings = set(), set(), []
    try:
        for address in target.addresses:
            parsed = ipaddress.ip_address(address.ip)
            try:
                classification = classify_ip(parsed.compressed)
            except URLValidationError:
                return {"hostname": target.hostname, "ipv4_addresses": [], "ipv6_addresses": [], "all_addresses_public": False, "resolution_status": "blocked", "message": "The hostname resolved to a blocked address.", "error_category": "blocked_address"}
            (ipv4 if parsed.version == 4 else ipv6).add(parsed.compressed)
            if classification["address_type"] == "nat64":
                nat64_mappings.append({"ipv6": parsed.compressed, "embedded_ipv4": str(ipaddress.IPv4Address(int(parsed) & 0xffffffff))})
    except Exception as error:
        logger.warning("IP intelligence unavailable hostname=%s category=%s", getattr(target, "hostname", "unknown"), type(error).__name__)
        return {"hostname": getattr(target, "hostname", ""), "ipv4_addresses": [], "ipv6_addresses": [], "all_addresses_public": False, "resolution_status": "unavailable", "message": "Public IP resolution was unavailable.", "error_category": type(error).__name__}
    return {"hostname": target.hostname, "ipv4_addresses": sorted(ipv4), "ipv6_addresses": sorted(ipv6), "nat64_mappings": nat64_mappings, "all_addresses_public": True, "resolution_status": "completed", "message": "Public IP addresses resolved from the vetted target.", "error_category": ""}
