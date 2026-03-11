"""
app.py — Flask application entry point.

Endpoints:
  POST /api/sftp/upload-event   EFT fires this on every file upload
  GET  /api/status              stats
  GET  /health                  liveness probe
"""

import logging
import threading
from datetime import datetime, timezone

from flask import Flask, request, jsonify

import storage
import scheduler
from config     import Config
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
    Receive upload notifications from GlobalSCAPE EFT Event Rules.

    EFT Event Rule body:
      {
        "username":    "%Username%",
        "filepath":    "%TargetPath%",
        "upload_time": "%DateTime%",
        "user_email":  "%UserEmail%"
      }

    filepath arrives as a Windows path with server prefix:
      \\\\i:\\sftp\\DR-EFTRoot\\DR-SFTP-IDFCBANK\\Usr\\folder\\file.csv

    We normalise it before storing:
      /usr/folder/file.csv

    user_email may be comma-separated (multiple uploader emails).
    We store it as-is and handle splitting in alerter.py.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify(error="Expected JSON body"), 400

    username    = (data.get("username")    or "").strip()
    raw_path    = (data.get("filepath")    or "").strip()
    user_email  = (data.get("user_email")  or "").strip()
    upload_time = (data.get("upload_time") or datetime.now(timezone.utc).isoformat()).strip()

    if not username or not raw_path:
        return jsonify(error="username and filepath are required"), 400

    # normalise Windows path → clean Unix path
    filepath = normalise_upload_path(raw_path)

    threading.Thread(
        target=_save_upload_event,
        args=(filepath, username, user_email, upload_time),
        daemon=True,
    ).start()

    logger.info("Upload event: %s → %s by %s", raw_path, filepath, username)
    return jsonify(status="accepted"), 202


def _save_upload_event(filepath, username, user_email, upload_time):
    try:
        storage.save_upload_event(filepath, username, user_email, upload_time)
    except Exception:
        logger.exception("Failed to save upload event for %s", filepath)


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
    storage.init_db()
    scheduler.start()
    app.run(host=Config.HOST, port=Config.PORT, debug=False, threaded=True)
