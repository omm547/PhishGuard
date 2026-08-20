from ipaddress import ip_address
import ssl
import socket
import time
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = ("login", "verify", "account", "update", "password", "secure")
LONG_URL_LENGTH = 75
NETWORK_LOOKUP_SKIPPED_MESSAGE = (
    "Network lookup skipped because the URL has elevated risk indicators."
)
TLS_LOOKUP_SKIPPED_MESSAGE = (
    "SSL/TLS lookup skipped because the URL has elevated risk indicators."
)
TLS_HTTPS_ONLY_MESSAGE = "SSL/TLS information is only available for HTTPS URLs."
TLS_LOOKUP_TIMEOUT_SECONDS = 5


def analyze_url(url_text):
    """Analyze a URL as text and return a beginner-friendly risk result."""
    cleaned_url = url_text.strip()

    if not cleaned_url:
        return _build_result(
            original_url=cleaned_url,
            parsed_url=None,
            score=100,
            reasons=["Missing or invalid URL: please enter an HTTP or HTTPS URL."],
        )

    parsed_url = urlparse(cleaned_url)

    if _is_invalid_http_url(parsed_url, cleaned_url):
        return _build_result(
            original_url=cleaned_url,
            parsed_url=parsed_url,
            score=100,
            reasons=["Missing or invalid URL: enter a complete URL such as https://example.com."],
        )

    score = 0
    reasons = []

    if parsed_url.scheme.lower() == "http":
        score += 25
        reasons.append("HTTP is used instead of HTTPS, so the connection is not encrypted.")

    found_keywords = _find_suspicious_keywords(cleaned_url)
    if found_keywords:
        score += 20
        reasons.append(
            "Suspicious keyword found in the URL: "
            + ", ".join(found_keywords)
            + "."
        )

    if _hostname_is_ip_address(parsed_url.hostname):
        score += 35
        reasons.append("The hostname is a direct IP address instead of a normal domain name.")

    if "@" in cleaned_url:
        score += 15
        reasons.append(
            "The URL contains an @ character, which can be used to make a URL look misleading."
        )

    subdomain_count = _count_subdomain_labels(parsed_url.hostname)
    if subdomain_count > 3:
        score += 10
        reasons.append(
            "The hostname has many subdomain levels, so its complex structure deserves additional inspection."
        )

    if len(cleaned_url) > LONG_URL_LENGTH:
        score += 20
        reasons.append(
            f"The URL is unusually long ({len(cleaned_url)} characters), which can hide suspicious details."
        )

    if not reasons:
        reasons.append("No basic warning signs were found by these Day 2 checks.")

    return _build_result(
        original_url=cleaned_url,
        parsed_url=parsed_url,
        score=min(score, 100),
        reasons=reasons,
        include_network_info=True,
    )


def _is_invalid_http_url(parsed_url, original_url):
    if any(character.isspace() for character in original_url):
        return True

    if parsed_url.scheme.lower() not in ("http", "https"):
        return True

    if not parsed_url.netloc or not parsed_url.hostname:
        return True

    try:
        parsed_url.port
    except ValueError:
        return True

    hostname = parsed_url.hostname
    if hostname == "localhost":
        return False

    if _hostname_is_ip_address(hostname):
        return False

    return "." not in hostname


def _hostname_is_ip_address(hostname):
    if not hostname:
        return False

    try:
        ip_address(hostname)
    except ValueError:
        return False

    return True


def _count_subdomain_labels(hostname):
    """Count labels before the main domain, using the final two labels as the main domain."""
    if not hostname or _hostname_is_ip_address(hostname):
        return 0

    labels = [label for label in hostname.rstrip(".").split(".") if label]
    if len(labels) <= 2:
        return 0

    return len(labels) - 2


def _find_suspicious_keywords(url_text):
    lower_url = url_text.lower()
    return [keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in lower_url]


def _build_result(original_url, parsed_url, score, reasons, include_network_info=False):
    network_info = None
    tls_info = None
    if include_network_info:
        # Only validated URLs reach this point. Keep DNS resolution behind the
        # final Low Risk threshold so elevated-risk URLs never trigger lookup.
        network_info = (
            _network_information(parsed_url)
            if score <= 29
            else _skipped_network_information(parsed_url)
        )
        if score > 29:
            tls_info = _unavailable_tls_information(TLS_LOOKUP_SKIPPED_MESSAGE)
        elif parsed_url.scheme.lower() != "https":
            tls_info = _unavailable_tls_information(TLS_HTTPS_ONLY_MESSAGE)
        elif not network_info.get("available"):
            tls_info = _unavailable_tls_information(
                "SSL/TLS information unavailable because no public network target was found."
            )
        else:
            tls_info = _tls_information(parsed_url, network_info)

    return {
        "url": original_url,
        "score": score,
        "category": _risk_category(score),
        "reasons": reasons,
        "details": _url_details(parsed_url),
        "network_info": network_info,
        "tls_info": tls_info,
    }


def _risk_category(score):
    if score <= 29:
        return "Low Risk"

    if score <= 59:
        return "Suspicious"

    return "High Risk"


def _url_details(parsed_url):
    if not parsed_url:
        return {
            "scheme": "Not available",
            "hostname": "Not available",
            "path": "Not available",
        }

    return {
        "scheme": parsed_url.scheme or "Not available",
        "hostname": parsed_url.hostname or "Not available",
        "path": parsed_url.path or "/",
    }


def _network_information(parsed_url):
    """Return public IP information without making an HTTP request."""
    hostname = parsed_url.hostname if parsed_url else None
    if not hostname:
        return _unavailable_network_information()

    # A literal IP is handled locally and is never passed to the DNS resolver.
    if _hostname_is_ip_address(hostname):
        address = ip_address(hostname)
        if not address.is_global:
            return _unavailable_network_information(hostname)

        return {
            "hostname": hostname,
            "ipv4": [hostname] if address.version == 4 else [],
            "ipv6": [hostname] if address.version == 6 else [],
            "available": True,
        }

    try:
        address_records = socket.getaddrinfo(
            hostname,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except (OSError, ValueError):
        return _unavailable_network_information(hostname)

    ipv4_addresses = set()
    ipv6_addresses = set()
    for family, _, _, _, sockaddr in address_records:
        try:
            address = ip_address(sockaddr[0])
        except (IndexError, ValueError):
            continue

        # is_global excludes private, loopback, link-local, multicast,
        # unspecified, reserved, and other non-public address ranges.
        if not address.is_global:
            continue

        if family == socket.AF_INET and address.version == 4:
            ipv4_addresses.add(str(address))
        elif family == socket.AF_INET6 and address.version == 6:
            ipv6_addresses.add(str(address))

    ipv4 = sorted(ipv4_addresses)
    ipv6 = sorted(ipv6_addresses)
    return {
        "hostname": hostname,
        "ipv4": ipv4,
        "ipv6": ipv6,
        "available": bool(ipv4 or ipv6),
    }


def _unavailable_network_information(hostname="Not available"):
    return {
        "hostname": hostname,
        "ipv4": [],
        "ipv6": [],
        "available": False,
    }


def _skipped_network_information(parsed_url):
    return {
        "hostname": parsed_url.hostname if parsed_url else "Not available",
        "ipv4": [],
        "ipv6": [],
        "available": False,
        "skipped": True,
        "message": NETWORK_LOOKUP_SKIPPED_MESSAGE,
    }


def _tls_information(parsed_url, network_info):
    """Return verified certificate information without fetching page content."""
    hostname = parsed_url.hostname if parsed_url else None
    if not hostname:
        return _unavailable_tls_information()

    port = parsed_url.port or 443
    public_targets = network_info.get("ipv4", []) + network_info.get("ipv6", [])
    context = ssl.create_default_context()

    for target in public_targets:
        try:
            with socket.create_connection(
                (target, port), timeout=TLS_LOOKUP_TIMEOUT_SECONDS
            ) as connection:
                with context.wrap_socket(connection, server_hostname=hostname) as tls_socket:
                    certificate = tls_socket.getpeercert()
            return _certificate_information(certificate)
        except (OSError, ssl.SSLError, ValueError):
            continue

    return _unavailable_tls_information()


def _certificate_information(certificate):
    subject = _certificate_name(certificate.get("subject", ()), "commonName")
    issuer = _certificate_name(certificate.get("issuer", ()), "commonName")
    valid_from = certificate.get("notBefore")
    valid_until = certificate.get("notAfter")

    try:
        currently_valid = (
            bool(valid_from and valid_until)
            and ssl.cert_time_to_seconds(valid_from) <= time.time() <= ssl.cert_time_to_seconds(valid_until)
        )
    except (TypeError, ValueError):
        currently_valid = False

    return {
        "available": True,
        "status": "Certificate verified",
        "subject": subject or "Not available",
        "issuer": issuer or "Not available",
        "valid_from": valid_from or "Not available",
        "valid_until": valid_until or "Not available",
        "currently_valid": currently_valid,
    }


def _certificate_name(name_parts, name_key):
    for name_part in name_parts:
        for key, value in name_part:
            if key == name_key:
                return value
    return None


def _unavailable_tls_information(message="SSL/TLS information unavailable"):
    return {
        "available": False,
        "message": message,
    }
