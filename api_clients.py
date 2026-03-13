from __future__ import annotations

"""
api_clients.py — HTTP clients for DSPM and GlobalSCAPE EFT
"""

import logging
import requests

from config import Config
from path_utils import normalise_folder_path

logger = logging.getLogger(__name__)

_TIMEOUT = 30


# ─────────────────────────────────────────────
# DSPM session
# ─────────────────────────────────────────────

def _dspm_session():

    s = requests.Session()

    s.headers.update({
        "Authorization": f"Bearer {Config.DSPM_API_KEY}",
        "Accept": "application/json"
    })

    s.verify = False

    return s


# ─────────────────────────────────────────────
# EFT Authentication
# ─────────────────────────────────────────────

def _get_eft_token():

    try:

        resp = requests.post(
            f"{Config.SFTP_API_URL.rstrip('/')}/admin/v1/authentication",
            json={
                "userName": Config.SFTP_USERNAME,
                "password": Config.SFTP_PASSWORD,
                "authType": "EFT"
            },
            headers={"content-type": "application/json"},
            timeout=_TIMEOUT,
            verify=False
        )

        resp.raise_for_status()

        data = resp.json()

        token = (
            data.get("token")
            or data.get("authToken")
            or data.get("access_token")
        )

        if not token:
            logger.error("EFT auth response missing token: %s", data)
            return None

        logger.info("EFT auth token obtained successfully.")

        return token

    except Exception as e:

        logger.error("EFT authentication failed: %s", e)

        return None


# ─────────────────────────────────────────────
# Fetch External User Folders
# ─────────────────────────────────────────────

def fetch_external_user_folders():

    token = _get_eft_token()

    if not token:
        logger.error("Skipping user sync — no EFT token.")
        return []

    try:

        resp = requests.get(
            f"{Config.SFTP_API_URL.rstrip('/')}/admin/v2/sites/a223c2aa-1a00-42c4-8831-1f3cec746684/users",
            headers={
                "content-type": "application/json",
                "Authorization": f"EFTAdminAuthToken {token}"
            },
            timeout=_TIMEOUT,
            verify=False
        )

        resp.raise_for_status()

        data = resp.json()

        users = data.get("data", [])

        folders = []

        for u in users:

            template_name = (
                u.get("relationships", {})
                .get("userTemplate", {})
                .get("data", {})
                .get("meta", {})
                .get("name", "")
            )

            if template_name.lower() != "external user":
                continue

            home = u.get("attributes", {}).get("homeFolder", {})

            if home.get("enabled") != "yes":
                continue

            raw = home.get("value", {}).get("path")

            if raw:

                folders.append(normalise_folder_path(raw))

        logger.info("EFT user sync: %d external folders fetched.", len(folders))

        return folders

    except Exception as e:

        logger.error("EFT user API error: %s", e)

        return []


# ─────────────────────────────────────────────
# DSPM API
# ─────────────────────────────────────────────

def fetch_pii_filepaths() -> list[dict]:
    """
    Fetch files classified as PII from DSPM.

    Returns:
    [
        {
            "filepath": "/usr/test/file.csv",
            "dlp_profiles": [
                {"type": "Email Addresses", "sensitivity": "Medium", "count": 10},
                {"type": "Taxpayer IDs", "sensitivity": "High", "count": 2}
            ]
        }
    ]
    """

    try:

        resp = _dspm_session().get(
            f"{Config.DSPM_API_URL.rstrip('/')}/api/v1/findings",
            params={"has_pii": "true", "limit": 10000},
            timeout=_TIMEOUT
        )

        resp.raise_for_status()

        data = resp.json()

        # Supports:
        # real DSPM → data.results
        # mock DSPM → findings
        results = (
            data.get("data", {}).get("results")
            or data.get("findings")
            or data
        )

        findings = []

        for item in results:

            filepath = (
                item.get("file_path")
                or item.get("filepath")
                or item.get("path")
                or item.get("file_name")
            )

            if not filepath:
                continue

            filepath = filepath.strip().lower()

            profiles = []

            sensitive = item.get("sensitive_data_types", [])

            for s in sensitive:

                dtype = (
                    s.get("data_type", {}).get("name")
                    or s.get("type")
                )

                sensitivity = (
                    s.get("sensitivity_level", {}).get("name")
                    or s.get("sensitivity")
                )

                count = (
                    s.get("occurence_count")
                    or s.get("occurrence_count")
                    or 0
                )

                profiles.append({
                    "type": dtype,
                    "sensitivity": sensitivity,
                    "count": count
                })

            findings.append({
                "filepath": filepath,
                "dlp_profiles": profiles
            })

        logger.info("DSPM sync: %d PII files fetched.", len(findings))

        return findings

    except Exception as e:

        logger.error("DSPM API error: %s", e)

        return []
