"""Beginner-friendly batch URL validation and analysis helpers."""

import ipaddress
from urllib.parse import urlparse

from url_analyzer import analyze_url


MAX_BATCH_URLS = 20


class BatchScanError(Exception):
    """A user-facing batch input problem."""


def scan_batch(url_text):
    """Validate and analyze each non-empty URL line independently."""
    lines = url_text.splitlines()
    entries = [(line_number, line.strip()) for line_number, line in enumerate(lines, 1) if line.strip()]

    if not entries:
        raise BatchScanError("Paste at least one HTTP or HTTPS URL, one per line.")
    if len(entries) > MAX_BATCH_URLS:
        raise BatchScanError(f"Please submit no more than {MAX_BATCH_URLS} URLs per batch.")

    results = []
    errors = []
    analyzed_by_url = {}
    first_line_by_url = {}

    for line_number, url in entries:
        validation_error = validate_batch_url(url)
        if validation_error:
            errors.append({"line_number": line_number, "url": url, "message": validation_error})
            continue

        if url in analyzed_by_url:
            analysis = analyzed_by_url[url]
            duplicate_of = first_line_by_url[url]
        else:
            # analyze_url keeps its existing risk rules and network safeguards:
            # elevated-risk entries skip DNS/TLS/IP-reputation lookups.
            analysis = analyze_url(url)
            analyzed_by_url[url] = analysis
            first_line_by_url[url] = line_number
            duplicate_of = None

        results.append({
            "line_number": line_number,
            "url": url,
            "analysis": analysis,
            "duplicate_of": duplicate_of,
        })

    return {"results": results, "errors": errors, "total_count": len(entries)}


def validate_batch_url(url_text):
    """Return a clear validation message, or None when the URL is acceptable."""
    try:
        parsed = urlparse(url_text)
        hostname = parsed.hostname
    except ValueError:
        return "URL contains malformed host or port information."

    if any(character.isspace() for character in url_text):
        return "URL contains whitespace."
    if parsed.scheme.lower() not in ("http", "https"):
        return "Only HTTP and HTTPS URLs are supported."
    if not parsed.netloc or not hostname:
        return "Enter a complete URL with a hostname."
    try:
        parsed.port
    except ValueError:
        return "URL contains an invalid port."

    hostname = hostname.rstrip(".")
    if hostname == "localhost":
        return None
    try:
        ipaddress.ip_address(hostname)
        return None
    except ValueError:
        pass
    if "." not in hostname:
        return "Hostname must be a domain name or IP address."
    return None
