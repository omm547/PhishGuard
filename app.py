from flask import Flask, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge

from batch_scanner import BatchScanError, scan_batch
from qr_scanner import QRScanError, decode_qr_image, is_supported_url
from safe_link_expander import LinkExpansionError, expand_short_url
from scan_history import HistoryError, clear_history, get_recent_scans, save_scan
from url_analyzer import analyze_url


# Create the Flask application object.
# Flask uses this object to know where the app starts.
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024


def _save_completed_scan(analysis_result):
    """Keep history failures separate from the scan that produced the result."""
    return save_scan(analysis_result["url"], analysis_result)


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
    expander_result = None
    expander_analysis_result = None
    expander_error_message = None
    expander_submitted_url = ""
    batch_scan_result = None
    batch_submitted_urls = ""
    batch_error_message = None
    history_save_error = None

    if request.method == "POST":
        form_type = request.form.get("form_type")
        if form_type == "qr":
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
                        if not _save_completed_scan(qr_analysis_result):
                            history_save_error = "The QR scan completed, but it could not be added to Scan History."
                except QRScanError as error:
                    qr_error_message = str(error)
                except Exception:
                    app.logger.exception("Unexpected error while scanning uploaded QR image")
                    qr_error_message = (
                        "We couldn't complete the QR scan. Please try a valid, clearer image."
                    )
        elif form_type == "expander":
            expander_submitted_url = request.form.get("expander_url", "").strip()
            try:
                expander_result = expand_short_url(expander_submitted_url)
                if expander_result["succeeded"]:
                    expander_analysis_result = analyze_url(expander_result["final_url"])
                    if not _save_completed_scan(expander_analysis_result):
                        history_save_error = "The link analysis completed, but it could not be added to Scan History."
            except LinkExpansionError as error:
                expander_error_message = str(error)
            except Exception:
                app.logger.exception("Unexpected error while expanding submitted link")
                expander_error_message = (
                    "We couldn't complete the link expansion. Please check the URL and try again."
                )
        elif form_type == "batch":
            batch_submitted_urls = request.form.get("batch_urls", "")
            try:
                batch_scan_result = scan_batch(batch_submitted_urls)
                for item in batch_scan_result["results"]:
                    if not _save_completed_scan(item["analysis"]):
                        history_save_error = "The batch scan completed, but some results could not be added to Scan History."
            except BatchScanError as error:
                batch_error_message = str(error)
            except Exception:
                app.logger.exception("Unexpected error while scanning the URL batch")
                batch_error_message = (
                    "We couldn't complete the batch scan right now. Please check the submitted lines and try again."
                )
        else:
            submitted_url = request.form.get("url", "").strip()
            try:
                analysis_result = analyze_url(submitted_url)
                if not _save_completed_scan(analysis_result):
                    history_save_error = "The scan completed, but it could not be added to Scan History."
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
        expander_result=expander_result,
        expander_analysis_result=expander_analysis_result,
        expander_error_message=expander_error_message,
        expander_submitted_url=expander_submitted_url,
        batch_scan_result=batch_scan_result,
        batch_submitted_urls=batch_submitted_urls,
        batch_error_message=batch_error_message,
        history_save_error=history_save_error,
    )


@app.route("/history", methods=["GET", "POST"])
def history():
    """Display or clear the recent local scan history."""
    history_error_message = None
    history_action_message = None

    if request.method == "POST" and request.form.get("action") == "clear":
        try:
            clear_history()
            history_action_message = "Scan History has been cleared."
        except HistoryError:
            history_error_message = "Scan History could not be cleared right now. Please try again."

    try:
        history_records = get_recent_scans()
    except HistoryError:
        history_records = []
        history_error_message = "Scan History is temporarily unavailable. Please try again later."

    return render_template(
        "history.html",
        history_records=history_records,
        history_error_message=history_error_message,
        history_action_message=history_action_message,
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
        expander_result=None,
        expander_analysis_result=None,
        expander_error_message=None,
        expander_submitted_url="",
        batch_scan_result=None,
        batch_submitted_urls="",
        batch_error_message=None,
        history_save_error=None,
    ), 413


# This block runs the development server only when this file is executed directly.
if __name__ == "__main__":
    app.run(debug=True)
