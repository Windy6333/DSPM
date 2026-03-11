import os
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.abspath(os.path.dirname(__file__)), ".env"))


class Config:
    # ── DSPM ──────────────────────────────────────────────────────
    DSPM_API_URL = os.getenv("DSPM_API_URL")
    DSPM_API_KEY = os.getenv("DSPM_API_KEY")

    # ── GlobalSCAPE EFT ───────────────────────────────────────────
    SFTP_API_URL  = os.getenv("SFTP_API_URL")
    SFTP_USERNAME = os.getenv("SFTP_USERNAME")
    SFTP_PASSWORD = os.getenv("SFTP_PASSWORD")

    # Fixed Windows path prefix that EFT prepends to all upload filepaths.
    # Stripped and normalised before storing in DB.
    SFTP_PATH_PREFIX = os.getenv("SFTP_PATH_PREFIX", "")

    # ── Email ─────────────────────────────────────────────────────
    SMTP_HOST           = os.getenv("SMTP_HOST")
    SMTP_PORT           = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USE_TLS        = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
    SMTP_USER           = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD       = os.getenv("SMTP_PASSWORD", "")
    SMTP_FROM           = os.getenv("SMTP_FROM")
    SECURITY_TEAM_EMAIL = os.getenv("SECURITY_TEAM_EMAIL")

    # ── App ───────────────────────────────────────────────────────
    HOST    = os.getenv("HOST", "0.0.0.0")
    PORT    = int(os.getenv("PORT", "5000"))
    DB_PATH = os.getenv("DB_PATH", "pii_notifier.db")
