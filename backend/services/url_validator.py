import ipaddress
import re
import socket
import logging
import time
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


class URLValidationError(Exception):
    """Raised when a submitted URL is unsafe or invalid."""


@dataclass(frozen=True)
class ResolvedAddress:
    ip: str
    family: int
    socktype: int
    protocol: int
    sockaddr: tuple


@dataclass(frozen=True)
class ValidatedTarget:
    normalized_url: str
    scheme: str
    hostname: str
    port: int
    addresses: tuple[ResolvedAddress, ...]

    @property
    def vetted_ip_addresses(self) -> tuple[str, ...]:
        return tuple(address.ip for address in self.addresses)


_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_METADATA_HOSTNAMES = {
    "metadata",
    "metadata.google.internal",
    "instance-data",
    "instance-data.ec2.internal",
}
_ALLOWED_PORTS = {"http": 80, "https": 443}
NAT64_PREFIX = ipaddress.IPv6Network("64:ff9b::/96")
logger = logging.getLogger(__name__)

def _debug(scan_id, hostname, stage, started, **extra):
    if scan_id is None:
        return
    elapsed = round((time.monotonic() - started) * 1000)
    logger.info("TEMPORARY DEBUG LOGGING stage=%s scan_uuid=%s hostname=%s elapsed_ms=%s %s", stage, scan_id, hostname, elapsed, " ".join(f"{k}={v}" for k,v in extra.items()))


def _normalize_hostname(hostname: str) -> str:
    hostname = hostname.rstrip(".")
    if not hostname:
        raise URLValidationError("Invalid hostname.")

    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            hostname = hostname.encode("idna").decode("ascii").lower()
        except UnicodeError as error:
            raise URLValidationError("Invalid hostname.") from error

        if len(hostname) > 253:
            raise URLValidationError("Invalid hostname.")

        if any(not _HOST_LABEL.fullmatch(label) for label in hostname.split(".")):
            raise URLValidationError("Invalid hostname.")
    else:
        hostname = literal.compressed

    if hostname in _METADATA_HOSTNAMES or hostname.endswith(".localhost"):
        raise URLValidationError(
            "Private or internal addresses cannot be scanned."
        )

    return hostname


def classify_ip(ip_text: str) -> dict:
    try:
        address = ipaddress.ip_address(ip_text.split("%", 1)[0])
    except ValueError as error:
        raise URLValidationError("The hostname resolved to an invalid address.") from error

    if isinstance(address, ipaddress.IPv6Address) and address in NAT64_PREFIX:
        embedded = ipaddress.IPv4Address(int(address) & 0xffffffff)
        if not embedded.is_global:
            raise URLValidationError("Private or internal addresses cannot be scanned.")
        return {"allowed": True, "address": address.compressed, "address_type": "nat64", "embedded_ipv4": str(embedded), "reason": ""}

    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        if not address.ipv4_mapped.is_global:
            raise URLValidationError(
                "Private or internal addresses cannot be scanned."
            )

    # is_global excludes private, loopback, link-local, multicast, reserved,
    # unspecified, CGNAT, documentation ranges, and cloud metadata addresses.
    if not address.is_global:
        raise URLValidationError(
            "Private or internal addresses cannot be scanned."
        )

    return {"allowed": True, "address": address.compressed, "address_type": "ipv4" if address.version == 4 else "ipv6", "embedded_ipv4": "", "reason": ""}


def _validate_ip(ip_text: str) -> str:
    return classify_ip(ip_text)["address"]


def validate_url(url: str, *, scan_id=None) -> ValidatedTarget:
    """Normalize a URL and resolve every address before outbound use."""
    started = time.monotonic()
    url = url.strip()
    hostname_hint = urlsplit(url).hostname or ""
    _debug(scan_id, hostname_hint, "SCAN STARTED", started)
    if not url:
        raise URLValidationError("URL cannot be empty.")

    if any(ord(character) < 32 or ord(character) == 127 for character in url):
        raise URLValidationError("The URL contains invalid characters.")

    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as error:
        raise URLValidationError("The URL is malformed.") from error

    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_PORTS:
        raise URLValidationError("Only HTTP and HTTPS URLs are allowed.")

    if parsed.username is not None or parsed.password is not None:
        raise URLValidationError("URLs containing credentials are not allowed.")

    if not parsed.hostname:
        raise URLValidationError("Invalid hostname.")

    hostname = _normalize_hostname(parsed.hostname)
    _debug(scan_id, hostname, "URL NORMALIZED", started)
    expected_port = _ALLOWED_PORTS[scheme]
    port = port or expected_port
    if port != expected_port:
        raise URLValidationError(
            "Only the standard HTTP and HTTPS ports are allowed."
        )

    _debug(scan_id, hostname, "DNS LOOKUP START", started)
    try:
        address_info = socket.getaddrinfo(
            hostname,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except (socket.gaierror, UnicodeError) as error:
        _debug(scan_id, hostname, "DNS LOOKUP FAILED", started, exception=type(error).__name__)
        raise URLValidationError("Unable to resolve hostname.") from error
    _debug(scan_id, hostname, "DNS LOOKUP COMPLETE", started, resolved_addresses=len(address_info))

    addresses = []
    seen = set()
    for family, socktype, protocol, _canonical_name, sockaddr in address_info:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue

        ip = _validate_ip(sockaddr[0])
        key = (family, ip, port)
        if key in seen:
            continue
        seen.add(key)

        if family == socket.AF_INET6:
            normalized_sockaddr = (ip, port, sockaddr[2], sockaddr[3])
        else:
            normalized_sockaddr = (ip, port)

        addresses.append(
            ResolvedAddress(
                ip=ip,
                family=family,
                socktype=socktype,
                protocol=protocol,
                sockaddr=normalized_sockaddr,
            )
        )

    if not addresses:
        raise URLValidationError("Unable to resolve hostname.")

    display_host = f"[{hostname}]" if ":" in hostname else hostname
    path = parsed.path or "/"
    normalized_url = urlunsplit(
        (scheme, display_host, path, parsed.query, "")
    )

    target = ValidatedTarget(
        normalized_url=normalized_url,
        scheme=scheme,
        hostname=hostname,
        port=port,
        addresses=tuple(addresses),
    )
    _debug(scan_id, hostname, "URL VALIDATED", started)
    return target
