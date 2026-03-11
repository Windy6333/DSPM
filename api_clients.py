from __future__ import annotations
"""
api_clients.py — HTTP clients for DSPM and GlobalSCAPE EFT.

EFT auth flow:
  1. POST /admin/v1/authentication  → get token (valid 15 mins)
  2. GET  /api/v1/users             → pass token as EFTAdminAuthToken header

Token is fetched fresh on each daily sync — no caching needed since
the user API call happens immediately after auth within the 15 min window.
"""

import logging
import requests
from config     import Config
from path_utils import normalise_folder_path

logger   = logging.getLogger(__name__)
_TIMEOUT = 30


def _dspm_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "Authorization": f"Bearer {Config.DSPM_API_KEY}",
        "Accept":        "application/json",
    })
    s.verify = False
    return s


# ── EFT authentication ─────────────────────────────────────────────────────────

def _get_eft_token() -> str | None:
    """
    Authenticate with EFT admin API and return a session token.

    curl equivalent:
      curl -sk -H "content-type: application/json" \
           -d '{"userName":"--","password":"--","authType":"EFT"}' \
           http://ip/admin/v1/authentication
    """
    try:
        resp = requests.post(
            f"{Config.SFTP_API_URL.rstrip('/')}/admin/v1/authentication",
            json={
                "userName": Config.SFTP_USERNAME,
                "password": Config.SFTP_PASSWORD,
                "authType": "EFT",
            },
            headers={"content-type": "application/json"},
            timeout=_TIMEOUT,
            verify=False,
        )
        resp.raise_for_status()
        data  = resp.json()

        # adapt field name if your EFT returns a different key for the token
        token = data.get("token") or data.get("authToken") or data.get("access_token")
        if not token:
            logger.error("EFT auth response did not contain a token: %s", data)
            return None

        logger.info("EFT auth token obtained successfully.")
        return token

    except Exception as e:
        logger.error("EFT authentication failed: %s", e)
        return None


# ── EFT user API ───────────────────────────────────────────────────────────────

def fetch_external_user_folders() -> list[str]:
    """
    1. Authenticate → get token
    2. Fetch all users → filter external → extract and normalise folder paths

    curl equivalent:
      curl -sk -H "content-type: json" \
           -H "Authorization: EFTAdminAuthToken <token>" \
           https://ip/api/v1/users

    Expected response:
    [
        {"name": "user1", "email": "u@company.com", "type": "internal", "folder": "/Usr/internal/"},
        {"name": "user2", "email": "x@partner.com", "type": "external", "folder": "/Usr/clients/acme/"},
        ...
    ]

    Returns normalised folder paths for external users only:
    ["/usr/clients/acme/", "/usr/partners/xyz/"]
    """
    token = _get_eft_token()
    if not token:
        logger.error("Skipping user sync — could not obtain EFT token.")
        return []

    try:
        resp = requests.get(
            f"{Config.SFTP_API_URL.rstrip('/')}/admin/v2/sites/a223c2aa-1a00-42c4-8831-1f3cec746684/users",
            headers={
                "content-type":  "application/json",
                "Authorization": f"EFTAdminAuthToken {token}",
            },
            timeout=_TIMEOUT,
            verify=False,
        )
        resp.raise_for_status()
        users = resp.json()

        folders = []
        for u in users:
            if not isinstance(u, dict):
                continue
            if u.get("type", "").lower() != "external":
                continue
            folder = _parse_folder(u)
            if folder:
                folders.append(folder)

        logger.info("EFT user sync: %d external folders fetched.", len(folders))
        return folders

    except Exception as e:
        logger.error("EFT user API error: %s", e)
        return []


def _parse_folder(user: dict) -> str | None:
    """
    Extract and normalise folder path from a user record.
    Adapt field name here if your EFT uses a different key.
    """
    raw = user.get("folder") or user.get("home_folder") or user.get("root_folder")
    if not raw:
        return None
    return normalise_folder_path(raw)


# ── DSPM API ───────────────────────────────────────────────────────────────────

def fetch_pii_filepaths() -> list[str]:
    """
    Fetch all files classified as PII by DSPM.

    Expected response:
    {
        "findings": [
            {"file_path": "/usr/clients/acme/invoices/data.csv"},
            ...
        ]
    }

    Returns flat list of filepaths.
    DSPM paths are already Unix-style so no prefix stripping needed here.
    """
    try:
        resp = _dspm_session().get(
            f"{Config.DSPM_API_URL.rstrip('/')}/api/v1/findings",
            params={"has_pii": "true", "limit": 10000},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

        raw   = data.get("findings", data if isinstance(data, list) else [])
        paths = [_parse_filepath(item) for item in raw]
        paths = [p for p in paths if p]

        logger.info("DSPM sync: %d PII filepaths fetched.", len(paths))
        return paths

    except Exception as e:
        logger.error("DSPM API error: %s", e)
        return []


def _parse_filepath(item: dict) -> str | None:
    """Extract filepath from DSPM finding. Adapt field name here if needed."""
    path = item.get("file_path") or item.get("filepath") or item.get("path")
    return path.strip().lower() if path else None
