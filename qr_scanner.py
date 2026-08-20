"""Small, local QR-code decoding helpers for the PhishGuard upload form."""

import cv2
import numpy as np
from urllib.parse import urlparse


MAX_QR_IMAGE_BYTES = 5 * 1024 * 1024


class QRScanError(Exception):
    """A user-facing QR scanning problem that should not expose a traceback."""


def decode_qr_image(image_bytes):
    """Decode one QR code from image bytes without saving or opening it."""
    if not image_bytes:
        raise QRScanError("Please choose an image containing a QR code.")
    if len(image_bytes) > MAX_QR_IMAGE_BYTES:
        raise QRScanError("That image is too large. Please upload an image under 5 MB.")

    image = cv2.imdecode(np.frombuffer(image_bytes, dtype=np.uint8), cv2.IMREAD_COLOR)
    if image is None:
        raise QRScanError("The uploaded file is not a readable image.")

    detector = cv2.QRCodeDetector()
    try:
        found, decoded_info, points, _ = detector.detectAndDecodeMulti(image)
    except cv2.error as error:
        raise QRScanError("We couldn't read that QR image. Please try a clearer image.") from error

    decoded_values = [value.strip() for value in (decoded_info or []) if value and value.strip()]
    # ``decoded_info`` can contain only readable payloads. Checking the
    # detected points as well catches multiple QR regions when one payload is
    # unreadable.
    detected_code_count = len(points) if points is not None else 0
    if found and (len(decoded_values) > 1 or detected_code_count > 1):
        raise QRScanError(
            "Multiple QR codes were detected. Please upload an image with one QR code."
        )
    if decoded_values:
        return decoded_values[0]

    value, _, _ = detector.detectAndDecode(image)
    if value and value.strip():
        return value.strip()
    raise QRScanError("We couldn't find a readable QR code in that image.")


def is_supported_url(value):
    """Return true only for complete HTTP/HTTPS URLs."""
    parsed = urlparse(value.strip())
    return (
        parsed.scheme.lower() in ("http", "https")
        and bool(parsed.netloc)
        and bool(parsed.hostname)
    )
