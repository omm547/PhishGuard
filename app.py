from flask import Flask, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge

from qr_scanner import QRScanError, decode_qr_image, is_supported_url
from url_analyzer import analyze_url


# Create the Flask application object.
# Flask uses this object to know where the app starts.
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024


@app.route("/", methods=["GET", "POST"])
def home():
    """Show the PhishGuard homepage.

    GET requests display the page normally.
    POST requests happen when the URL analysis form is submitted.
    """
    analysis_result = None
    submitted_url = ""
    error_message = None
    qr_analysis_result = None
    qr_error_message = None
    qr_filename = ""
    qr_decoded_value = ""

    if request.method == "POST":
        if request.form.get("form_type") == "qr":
            uploaded_file = request.files.get("qr_image")
            qr_filename = uploaded_file.filename if uploaded_file else ""
            if not uploaded_file or not uploaded_file.filename:
                qr_error_message = "Please choose an image containing a QR code."
            else:
                try:
                    qr_decoded_value = decode_qr_image(uploaded_file.read())
                    if not is_supported_url(qr_decoded_value):
                        qr_error_message = (
                            "QR code decoded, but it does not contain a supported "
                            "HTTP/HTTPS URL."
                        )
                    else:
                        qr_analysis_result = analyze_url(qr_decoded_value)
                except QRScanError as error:
                    qr_error_message = str(error)
                except Exception:
                    app.logger.exception("Unexpected error while scanning uploaded QR image")
                    qr_error_message = (
                        "We couldn't complete the QR scan. Please try a valid, clearer image."
                    )
        else:
            submitted_url = request.form.get("url", "").strip()
            try:
                analysis_result = analyze_url(submitted_url)
            except Exception:
                app.logger.exception("Unexpected error while analyzing submitted URL")
                error_message = (
                    "We couldn't complete the analysis right now. Please check the URL "
                    "and try again."
                )

    return render_template(
        "index.html",
        analysis_result=analysis_result,
        submitted_url=submitted_url,
        error_message=error_message,
        qr_analysis_result=qr_analysis_result,
        qr_error_message=qr_error_message,
        qr_filename=qr_filename,
        qr_decoded_value=qr_decoded_value,
    )


@app.errorhandler(RequestEntityTooLarge)
def handle_large_upload(_error):
    """Keep Flask's upload-size error beginner-friendly."""
    return render_template(
        "index.html",
        analysis_result=None,
        submitted_url="",
        error_message=None,
        qr_analysis_result=None,
        qr_error_message="That image is too large. Please upload an image under 5 MB.",
        qr_filename="",
        qr_decoded_value="",
    ), 413


# This block runs the development server only when this file is executed directly.
if __name__ == "__main__":
    app.run(debug=True)
