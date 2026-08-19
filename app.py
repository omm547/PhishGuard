from flask import Flask, render_template, request

from url_analyzer import analyze_url


# Create the Flask application object.
# Flask uses this object to know where the app starts.
app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def home():
    """Show the PhishGuard homepage.

    GET requests display the page normally.
    POST requests happen when the URL analysis form is submitted.
    """
    analysis_result = None
    submitted_url = ""
    error_message = None

    if request.method == "POST":
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
    )


# This block runs the development server only when this file is executed directly.
if __name__ == "__main__":
    app.run(debug=True)
