from dotenv import load_dotenv
load_dotenv()
from app import create_app
from werkzeug.serving import WSGIRequestHandler
app = create_app()


class WebGuardRequestHandler(WSGIRequestHandler):
    """Avoid advertising the Werkzeug and Python versions in local responses."""

    server_version = "WebGuard"
    sys_version = ""

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False, request_handler=WebGuardRequestHandler)
