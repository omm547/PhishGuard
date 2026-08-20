"""Safety-focused redirect expansion for known URL shorteners."""

import ipaddress
import socket
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


KNOWN_SHORTENER_HOSTNAMES = {
    "amzn.to",
    "bit.ly",
    "buff.ly",
    "goo.gl",
    "is.gd",
    "lnkd.in",
    "ow.ly",
    "rb.gy",
    "rebrand.ly",
    "s.id",
    "shorturl.at",
    "t.co",
    "tiny.cc",
    "tinyurl.com",
}
MAX_REDIRECTS = 5
REQUEST_TIMEOUT_SECONDS = 5


class LinkExpansionError(Exception):
    """A safe, user-facing link-expansion problem."""


class _NoRedirectHandler(HTTPRedirectHandler):
    """Return redirect responses to our code instead of following them."""

    def redirect_request(self, request, file, code, msg, headers, new_url):
        return None


def is_known_shortener(url_text):
    """Return whether the URL host belongs to our small known list."""
    parsed = _validate_http_url(url_text)
    return _hostname_without_www(parsed.hostname) in KNOWN_SHORTENER_HOSTNAMES


def expand_short_url(url_text):
    """Safely resolve a known short URL and return a display-ready result."""
    parsed = _validate_http_url(url_text)
    original_url = parsed.geturl()
    if _hostname_without_www(parsed.hostname) not in KNOWN_SHORTENER_HOSTNAMES:
        return {
            "original_url": original_url,
            "redirect_chain": [original_url],
            "final_url": original_url,
            "redirect_count": 0,
            "succeeded": False,
            "message": "This hostname is not in PhishGuard's supported shortener list, so no expansion was attempted.",
        }

    chain = [original_url]
    visited = {original_url}
    current_url = original_url
    # Do not inherit a proxy that could make destination handling opaque.
    opener = build_opener(_NoRedirectHandler(), ProxyHandler({}))

    for _redirect_number in range(MAX_REDIRECTS + 1):
        _ensure_public_destination(current_url)
        response = _request_headers(opener, current_url)
        try:
            status = response.getcode()
            location = response.headers.get("Location")
        finally:
            response.close()

        if status not in (301, 302, 303, 307, 308):
            return {
                "original_url": original_url,
                "redirect_chain": chain,
                "final_url": current_url,
                "redirect_count": len(chain) - 1,
                "succeeded": 200 <= status < 400,
                "message": "Expansion completed. The final URL was analyzed separately; success does not mean the destination is safe.",
            }

        if not location:
            raise LinkExpansionError("The shortener returned a redirect without a destination.")
        if len(chain) - 1 >= MAX_REDIRECTS:
            raise LinkExpansionError("The redirect chain exceeded the maximum of 5 redirects.")

        next_url = _validate_http_url(urljoin(current_url, location)).geturl()
        _ensure_public_destination(next_url)
        if next_url in visited:
            raise LinkExpansionError("A redirect loop was detected.")
        visited.add(next_url)
        chain.append(next_url)
        current_url = next_url

    raise LinkExpansionError("The redirect chain could not be completed safely.")


def _request_headers(opener, url):
    """Use HEAD first and a one-byte ranged GET only when HEAD is unsupported."""
    head_request = Request(
        url,
        method="HEAD",
        headers={"User-Agent": "PhishGuard-LinkExpander/1.0"},
    )
    try:
        return opener.open(head_request, timeout=REQUEST_TIMEOUT_SECONDS)
    except HTTPError as error:
        if error.code in (301, 302, 303, 307, 308):
            return error
        if error.code not in (400, 405, 501):
            raise LinkExpansionError(_network_error_message(error)) from error
    except (URLError, TimeoutError, socket.timeout, OSError) as error:
        raise LinkExpansionError(_network_error_message(error)) from error

    get_request = Request(
        url,
        method="GET",
        headers={
            "Range": "bytes=0-0",
            "User-Agent": "PhishGuard-LinkExpander/1.0",
        },
    )
    try:
        return opener.open(get_request, timeout=REQUEST_TIMEOUT_SECONDS)
    except HTTPError as error:
        if error.code in (301, 302, 303, 307, 308):
            return error
        raise LinkExpansionError(_network_error_message(error)) from error
    except (URLError, TimeoutError, socket.timeout, OSError) as error:
        raise LinkExpansionError(_network_error_message(error)) from error


def _validate_http_url(url_text):
    cleaned_url = (url_text or "").strip()
    parsed = urlparse(cleaned_url)
    if (
        any(character.isspace() for character in cleaned_url)
        or parsed.scheme.lower() not in ("http", "https")
        or not parsed.netloc
        or not parsed.hostname
    ):
        raise LinkExpansionError("Enter a complete HTTP or HTTPS URL.")
    try:
        parsed.port
    except ValueError as error:
        raise LinkExpansionError("The URL contains an invalid port.") from error
    return parsed


def _ensure_public_destination(url_text):
    parsed = _validate_http_url(url_text)
    hostname = parsed.hostname.lower().rstrip(".")
    blocked_suffixes = (".localhost", ".local", ".internal", ".home.arpa")
    blocked_names = {"localhost", "localhost.localdomain", "broadcasthost"}
    if hostname in blocked_names or hostname.endswith(blocked_suffixes):
        raise LinkExpansionError("Redirects to internal or local destinations are blocked.")

    try:
        literal_address = ipaddress.ip_address(hostname)
    except ValueError:
        literal_address = None
    if literal_address is not None:
        if _is_blocked_address(literal_address):
            raise LinkExpansionError("Redirects to internal or reserved IP addresses are blocked.")
        return

    try:
        addresses = {
            result[4][0]
            for result in socket.getaddrinfo(
                hostname,
                parsed.port or (443 if parsed.scheme.lower() == "https" else 80),
                type=socket.SOCK_STREAM,
            )
        }
    except (socket.gaierror, OSError) as error:
        raise LinkExpansionError("The redirect destination could not be resolved safely.") from error
    if not addresses:
        raise LinkExpansionError("The redirect destination could not be resolved safely.")
    if any(_is_blocked_address(ipaddress.ip_address(address)) for address in addresses):
        raise LinkExpansionError("Redirects to internal or reserved IP addresses are blocked.")


def _is_blocked_address(address):
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or not address.is_global
    )


def _hostname_without_www(hostname):
    normalized = hostname.lower().rstrip(".")
    return normalized[4:] if normalized.startswith("www.") else normalized


def _network_error_message(error):
    if isinstance(error, HTTPError):
        return f"The destination returned HTTP status {error.code}."
    if isinstance(error, (TimeoutError, socket.timeout)) or isinstance(getattr(error, "reason", None), TimeoutError):
        return "The request timed out before the redirect chain could be resolved."
    return "The redirect destination could not be reached."
