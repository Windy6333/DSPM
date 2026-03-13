r"""
app.py — Flask application entry point.

Endpoints
POST /api/sftp/upload-event   EFT sends upload notifications
GET  /api/status              statistics
GET  /health                  health check
"""

import json
import logging
import threading
from datetime import datetime, timezone

from flask import Flask, request, jsonify

import storage
import scheduler
from config import Config
from path_utils import normalise_upload_path


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

logger = logging.getLogger(__name__)

app = Flask(__name__)


@app.post("/api/sftp/upload-event")
def upload_event():
    """
    Receive upload notifications from EFT.

    Accepts:
    - JSON
    - form data
    - raw body
    """

    raw_body = request.data.decode("utf-8", errors="ignore")

    logger.info("Incoming request from %s", request.remote_addr)
    logger.info("Headers: %s", dict(request.headers))
    logger.info("Raw body: %s", raw_body)

    data = None

    # Try JSON first
    try:
        data = request.get_json(force=False, silent=True)
    except Exception:
        pass

    # Try form data
    if not data and request.form:
        data = request.form.to_dict()

    # Try parsing raw body JSON
    if not data and raw_body:
        try:
            data = json.loads(raw_body)
        except Exception:
            pass

    # fallback
    if not data:
        data = {}

    username = (data.get("username") or "").strip()
    raw_path = (data.get("filepath") or "").strip()
    user_email = (data.get("user_email") or "").strip()

    upload_time = (data.get("upload_time") or "").strip()

    if not upload_time:
        upload_time = datetime.now(timezone.utc).isoformat()

    # Validate required fields
    if not username or not raw_path:

        logger.warning("Invalid upload event payload received: %s", data)

        return jsonify({
            "status": "error",
            "message": "username and filepath required"
        }), 400

    # Normalize path
    filepath = normalise_upload_path(raw_path)

    # Save asynchronously
    threading.Thread(
        target=_save_upload_event,
        args=(filepath, username, user_email, upload_time),
        daemon=True,
    ).start()

    logger.info(
        "Upload event stored | user=%s | file=%s",
        username,
        filepath
    )

    return jsonify({"status": "accepted"}), 202


def _save_upload_event(filepath, username, user_email, upload_time):

    try:

        storage.save_upload_event(
            filepath,
            username,
            user_email,
            upload_time
        )

    except Exception:

        logger.exception(
            "Failed to save upload event for %s",
            filepath
        )


@app.get("/api/status")
def status():

    return jsonify(
        status="running",
        stats=storage.get_stats(),
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@app.get("/health")
def health():

    return jsonify(ok=True), 200


if __name__ == "__main__":

    logger.info("Starting PII Notification System...")

    storage.init_db()

    scheduler.start()

    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=False,
        threaded=True,
    )
