import http.client
import logging
import socket
import ssl
import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from services.url_validator import (
    URLValidationError,
    ValidatedTarget,
    validate_url,
)


logger = logging.getLogger(__name__)

# Conservative upper bounds for slow but legitimate public sites. These are
# still finite and apply to every connection/read attempt.
CONNECT_TIMEOUT = 10
READ_TIMEOUT = 15
OVERALL_TIMEOUT = 45
MAX_REDIRECTS = 5
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
ACCEPT_HEADER = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
ACCEPT_LANGUAGE = "en-US,en;q=0.9"
REDIRECT_STATUSES = {301, 302, 303, 307, 308}


class WebsiteRequestError(Exception):
    """Raised when the website cannot be reached safely."""

    def __init__(self, message, *, redirect_chain=None, loop_detected=False):
        super().__init__(message)
        self.redirect_chain = redirect_chain or []
        self.loop_detected = loop_detected


class _RequestTimeout(Exception):
    pass


class _TLSFailure(Exception):
    pass


class _ConnectionFailure(Exception):
    pass


@dataclass
class _ResponseMetadata:
    status_code: int
    headers: dict
    body: str = ""


def _remaining(deadline: float, limit: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _RequestTimeout
    return min(limit, remaining)


def _host_header(target: ValidatedTarget) -> str:
    hostname = f"[{target.hostname}]" if ":" in target.hostname else target.hostname
    return hostname


def _request_once(target: ValidatedTarget, deadline: float, *, scan_id=None, started=None) -> _ResponseMetadata:
    """Connect directly to a vetted IP while retaining Host and TLS SNI."""
    last_error = None

    for address in target.addresses:
        raw_socket = None
        connection = None
        response = None
        try:
            _stage(scan_id, target.hostname, "TCP CONNECTION START", started)
            raw_socket = socket.socket(
                address.family,
                address.socktype,
                address.protocol,
            )
            raw_socket.settimeout(_remaining(deadline, CONNECT_TIMEOUT))
            raw_socket.connect(address.sockaddr)
            _stage(scan_id, target.hostname, "TCP CONNECTION COMPLETE", started)

            connection = raw_socket
            if target.scheme == "https":
                context = ssl.create_default_context()
                connection = context.wrap_socket(
                    raw_socket,
                    server_hostname=target.hostname,
                )
                _stage(scan_id, target.hostname, "TLS HANDSHAKE COMPLETE", started)

            connection.settimeout(_remaining(deadline, READ_TIMEOUT))
            parsed = urlsplit(target.normalized_url)
            request_target = parsed.path or "/"
            if parsed.query:
                request_target = f"{request_target}?{parsed.query}"

            request = (
                f"GET {request_target} HTTP/1.1\r\n"
                f"Host: {_host_header(target)}\r\n"
                f"User-Agent: {USER_AGENT}\r\n"
                f"Accept: {ACCEPT_HEADER}\r\n"
                f"Accept-Language: {ACCEPT_LANGUAGE}\r\n"
                'Sec-CH-UA: "Chromium";v="122", "Not(A:Brand";v="24"\r\n'
                "Sec-CH-UA-Mobile: ?0\r\n"
                'Sec-CH-UA-Platform: "Windows"\r\n'
                "Range: bytes=0-0\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            connection.sendall(request)
            _stage(scan_id, target.hostname, "HTTP REQUEST SENT", started)

            response = http.client.HTTPResponse(connection)
            response.begin()
            _stage(scan_id, target.hostname, "FIRST RESPONSE BYTE RECEIVED", started)
            _stage(scan_id, target.hostname, "RESPONSE HEADERS RECEIVED", started, status_code=response.status)
            headers = {
                name.lower(): value
                for name, value in response.getheaders()
            }
            # Keep the transport bounded: analyzers only ever receive a small
            # textual sample and never the live HTTPResponse object.
            # Read only a small sample.  Some servers ignore the Range header
            # and keep the connection open; waiting for a multi-megabyte body
            # makes an otherwise healthy website appear to have timed out.
            body = response.read(1)
            _stage(scan_id, target.hostname, "BODY COMPLETE", started)
            return _ResponseMetadata(
                response.status,
                headers,
                body.decode("utf-8", errors="replace"),
            )

        except socket.timeout as error:
            last_error = error
        except ssl.SSLError as error:
            raise _TLSFailure from error
        except (OSError, http.client.HTTPException) as error:
            last_error = error
        finally:
            if response is not None:
                response.close()
            if connection is not None:
                connection.close()
            elif raw_socket is not None:
                raw_socket.close()

    if isinstance(last_error, socket.timeout):
        raise _RequestTimeout from last_error
    raise _ConnectionFailure from last_error


def _request_error(message, error, redirect_chain):
    logger.warning(
        "Outbound website request failed (%s).",
        type(error).__name__,
    )
    return WebsiteRequestError(message, redirect_chain=redirect_chain)


def _stage(scan_id, hostname, stage, started, **extra):
    if scan_id is None:
        return
    elapsed = round((time.monotonic() - started) * 1000) if started else 0
    logger.info("TEMPORARY DEBUG LOGGING stage=%s scan_uuid=%s hostname=%s elapsed_ms=%s %s", stage, scan_id, hostname, elapsed, " ".join(f"{k}={v}" for k,v in extra.items()))


def fetch_website(target: ValidatedTarget | str, *, scan_id=None) -> dict:
    started = time.monotonic()
    original = target if isinstance(target, str) else target.normalized_url
    _stage(scan_id, urlsplit(original).hostname or "", "url_received", started)
    if isinstance(target, str):
        try:
            target = validate_url(target, scan_id=scan_id)
        except URLValidationError as error:
            raise WebsiteRequestError(str(error)) from error
        _stage(scan_id, target.hostname, "url_normalized", started)
    _stage(scan_id, target.hostname, "URL VALIDATED", started)
    _stage(scan_id, target.hostname, "DNS LOOKUP COMPLETE", started, resolved_addresses=len(target.addresses))

    deadline = time.monotonic() + OVERALL_TIMEOUT
    redirect_chain = []
    visited = {target.normalized_url}
    current = target

    while True:
        try:
            response = _request_once(current, deadline, scan_id=scan_id, started=started)
        except _RequestTimeout as error:
            _stage(scan_id, current.hostname, "EXCEPTION", started, exception=type(error).__name__)
            raise _request_error(
                "The website took too long to respond.",
                error,
                redirect_chain,
            )
        except _TLSFailure as error:
            raise _request_error(
                "The website has an SSL/TLS connection problem.",
                error,
                redirect_chain,
            )
        except _ConnectionFailure as error:
            _stage(scan_id, current.hostname, "EXCEPTION", started, exception=type(error).__name__)
            _stage(scan_id, current.hostname, "total_elapsed", started)
            raise _request_error(
                "CyberShield AI could not connect to the website.",
                error,
                redirect_chain,
            )

        if response.status_code not in REDIRECT_STATUSES:
            _stage(scan_id, current.hostname, "final_url", started)
            _stage(scan_id, current.hostname, "total_elapsed", started)
            return {
                "status_code": response.status_code,
                "final_url": current.normalized_url,
                "redirect_count": len(redirect_chain),
                "headers": response.headers,
                "body_text": getattr(response, "body", ""),
                "content_type": response.headers.get("content-type", ""),
                "redirect_chain": redirect_chain,
                "redirect_cross_host_count": sum(
                    item["source_host"] != item["destination_host"]
                    for item in redirect_chain
                ),
                "redirect_has_scheme_downgrade": any(
                    item["scheme_downgrade"] for item in redirect_chain
                ),
                "redirect_loop_detected": False,
            }

        location = response.headers.get("location", "").strip()
        if (
            not location
            or any(ord(character) < 32 or ord(character) == 127 for character in location)
        ):
            raise WebsiteRequestError(
                "The website returned a malformed redirect destination.",
                redirect_chain=redirect_chain,
            )

        destination_url = urljoin(current.normalized_url, location)
        try:
            destination = validate_url(destination_url)
        except URLValidationError as error:
            logger.warning(
                "Blocked unsafe redirect destination (%s).",
                type(error).__name__,
            )
            raise WebsiteRequestError(
                "The website redirected to an unsafe or invalid destination.",
                redirect_chain=redirect_chain,
            ) from error

        entry = {
            "source_url": current.normalized_url,
            "status_code": response.status_code,
            "destination_url": destination.normalized_url,
            "source_host": current.hostname,
            "destination_host": destination.hostname,
            "scheme_downgrade": (
                current.scheme == "https" and destination.scheme == "http"
            ),
        }
        redirect_chain.append(entry)
        _stage(scan_id, destination.hostname, "REDIRECT FOLLOWED", started)

        if destination.normalized_url in visited:
            raise WebsiteRequestError(
                "The website contains a redirect loop.",
                redirect_chain=redirect_chain,
                loop_detected=True,
            )

        if len(redirect_chain) > MAX_REDIRECTS:
            raise WebsiteRequestError(
                "The website has too many redirects.",
                redirect_chain=redirect_chain,
            )

        visited.add(destination.normalized_url)
        current = destination


def analyze_redirects(result: dict):
    redirects = result["redirect_count"]
    cross_host_count = result.get("redirect_cross_host_count", 0)
    downgrade = result.get("redirect_has_scheme_downgrade", False)

    if downgrade:
        risk = "high"
        message = "The redirect chain downgrades HTTPS to unencrypted HTTP."
    elif redirects > 2:
        risk = "medium"
        message = f"{redirects} redirects detected. The chain is longer than normal."
    elif cross_host_count:
        risk = "low"
        message = (
            f"{redirects} redirect(s) detected, including "
            f"{cross_host_count} cross-host redirect(s)."
        )
    elif redirects:
        risk = "low"
        message = f"{redirects} redirect(s) detected."
    else:
        risk = "low"
        message = "No redirects detected."

    return {"risk": risk, "message": message}
