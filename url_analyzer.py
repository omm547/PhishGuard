from ipaddress import ip_address
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = ("login", "verify", "account", "update", "password", "secure")
LONG_URL_LENGTH = 75


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


def _find_suspicious_keywords(url_text):
    lower_url = url_text.lower()
    return [keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in lower_url]


def _build_result(original_url, parsed_url, score, reasons):
    return {
        "url": original_url,
        "score": score,
        "category": _risk_category(score),
        "reasons": reasons,
        "details": _url_details(parsed_url),
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
