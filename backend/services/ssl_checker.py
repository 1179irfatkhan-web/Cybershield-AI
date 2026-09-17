import logging
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlsplit


logger = logging.getLogger(__name__)


class SSLCheckError(Exception):
    """Raised when TLS metadata cannot be collected safely."""


def _name(value):
    pairs = []
    for group in value or []:
        if len(group) == 2 and isinstance(group[0], str):
            pairs.append(group)
        else:
            pairs.extend(item for item in group if len(item) == 2)
    return ", ".join(f"{key}={item}" for key, item in pairs)


def _sans(cert):
    return [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]


def analyze_ssl(url: str) -> dict:
    parsed = urlsplit(url)
    hostname = parsed.hostname
    if not hostname:
        raise SSLCheckError("The TLS hostname could not be identified.")

    port = parsed.port or 443
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                cert = secure_sock.getpeercert()
                if not cert:
                    raise SSLCheckError("The server did not provide a certificate.")
                not_before = datetime.fromtimestamp(
                    ssl.cert_time_to_seconds(cert["notBefore"]), timezone.utc
                )
                not_after = datetime.fromtimestamp(
                    ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc
                )
                now = datetime.now(timezone.utc)
                expired = now >= not_after
                not_yet_valid = now < not_before
                return {
                    "certificate_present": True,
                    "valid": not expired and not not_yet_valid,
                    "expired": expired,
                    "not_yet_valid": not_yet_valid,
                    "days_remaining": (not_after - now).days,
                    "tls_version": secure_sock.version() or "Unknown",
                    "cipher": (secure_sock.cipher() or ("Unknown",))[0],
                    "issuer": _name(cert.get("issuer")),
                    "subject": _name(cert.get("subject")),
                    "subject_alt_names": _sans(cert),
                    "signature_algorithm": cert.get("signatureAlgorithm", "Unknown"),
                    "message": "The TLS certificate is valid.",
                }
    except SSLCheckError:
        raise
    except (socket.timeout, TimeoutError) as error:
        logger.warning("TLS analysis timed out (%s).", type(error).__name__)
        raise SSLCheckError("The TLS connection timed out.") from error
    except ssl.CertificateError as error:
        logger.warning("TLS hostname verification failed (%s).", type(error).__name__)
        raise SSLCheckError("The TLS certificate hostname could not be verified.") from error
    except ssl.SSLCertVerificationError as error:
        logger.warning("TLS certificate verification failed (%s).", type(error).__name__)
        raise SSLCheckError("The TLS certificate could not be verified.") from error
    except ssl.SSLError as error:
        logger.warning("TLS handshake failed (%s).", type(error).__name__)
        raise SSLCheckError("The TLS handshake failed.") from error
    except OSError as error:
        logger.warning("TLS connection failed (%s).", type(error).__name__)
        raise SSLCheckError("The TLS connection could not be established.") from error
