from flask import Flask, render_template, request


# Create the Flask application object.
# Flask uses this object to know where the app starts.
app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def home():
    """Show the PhishGuard homepage.

    GET requests display the page normally.
    POST requests happen when the demo URL form is submitted.
    Real URL analysis will be added in a later development phase.
    """
    demo_message = None
    submitted_url = ""

    if request.method == "POST":
        submitted_url = request.form.get("url", "").strip()

        if submitted_url:
            demo_message = (
                "Demo mode: URL analysis for this website will be added "
                "in the next development phase."
            )
        else:
            demo_message = "Please enter a URL before analyzing."

    return render_template(
        "index.html",
        demo_message=demo_message,
        submitted_url=submitted_url,
    )


# This block runs the development server only when this file is executed directly.
if __name__ == "__main__":
    app.run(debug=True)
