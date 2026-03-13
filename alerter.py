"""
alerter.py — Correlation engine and email dispatch.
"""

import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timezone

import storage
import access_cache
from config import Config

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# Correlation
# ──────────────────────────────────────────────

def correlate_and_alert(pii_files: list[dict]):

    if access_cache.is_empty():
        logger.warning("Access cache empty — waiting for user sync.")
        return

    if not pii_files:
        logger.info("No PII files to correlate.")
        return

    logger.info("Correlating %d PII files...", len(pii_files))

    for item in pii_files:

        filepath = item.get("filepath")
        dlp_profiles = item.get("dlp_profiles", [])

        if not filepath:
            continue

        if not access_cache.has_external_access(filepath):
            continue

        incident = storage.get_incident(filepath)

        if incident and incident["notified"] == 1:
            continue

        event = storage.get_upload_event(filepath)

        username = event["username"] if event else "UNKNOWN"
        user_email = event["user_email"] if event else ""
        detected_at = event["upload_time"] if event else datetime.now(timezone.utc).isoformat()

        if not incident:

            incident_id = storage.create_incident(
                filepath=filepath,
                username=username,
                user_email=user_email,
                detected_at=detected_at,
                dlp_profiles=dlp_profiles
            )

        else:

            incident_id = incident["incident_id"]

        ok = _send_alert(
            incident_id,
            filepath,
            username,
            user_email,
            detected_at,
            dlp_profiles
        )

        if ok:

            storage.mark_notified(incident_id)

            logger.warning(
                "Alert SENT | incident=%s | file=%s | uploader=%s",
                incident_id, filepath, username
            )

        else:

            logger.error(
                "Alert FAILED | incident=%s | file=%s",
                incident_id, filepath
            )


# ──────────────────────────────────────────────
# Email Sending
# ──────────────────────────────────────────────

def _recipient_list(user_email: str):

    if not user_email:
        return []

    return [e.strip() for e in user_email.split(",") if e.strip()]


def _send_alert(
    incident_id,
    filepath,
    username,
    user_email,
    detected_at,
    dlp_profiles
):

    filename = filepath.split("/")[-1]

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    recipients = [e.strip() for e in Config.SECURITY_TEAM_EMAIL.split(",")]

    try:

        msg = MIMEMultipart("alternative")

        msg["Subject"] = f"[PII ALERT] External access detected: {filename}"
        msg["From"] = Config.SMTP_FROM
        msg["To"] = ", ".join(recipients)

        msg.attach(MIMEText(
            _build_text(
                incident_id,
                filepath,
                filename,
                username,
                user_email,
                detected_at,
                now,
                dlp_profiles
            ),
            "plain"
        ))

        msg.attach(MIMEText(
            _build_html(
                incident_id,
                filepath,
                filename,
                username,
                user_email,
                detected_at,
                now,
                dlp_profiles
            ),
            "html"
        ))

        with smtplib.SMTP(Config.SMTP_HOST, Config.SMTP_PORT) as s:

            s.ehlo()

            if Config.SMTP_USE_TLS:
                s.starttls()

            if Config.SMTP_USER:
                s.login(Config.SMTP_USER, Config.SMTP_PASSWORD)

            s.sendmail(Config.SMTP_FROM, recipients, msg.as_string())

        return True

    except Exception as e:

        logger.error("Email failed for incident %s: %s", incident_id, e)

        return False


# ──────────────────────────────────────────────
# HTML Email Template
# ──────────────────────────────────────────────

def _build_html(
    incident_id,
    filepath,
    filename,
    username,
    user_email,
    detected_at,
    now,
    dlp_profiles
):

    emails = _recipient_list(user_email)

    email_badges = "".join(
        f"<span style='display:inline-block;background:#f1f5f9;border:1px solid #e2e8f0;"
        f"border-radius:4px;padding:2px 10px;font-size:13px;margin:2px 4px 2px 0'>{e}</span>"
        for e in emails
    ) if emails else "<span style='color:#94a3b8'>—</span>"

    dlp_rows = ""

    for p in dlp_profiles:

        dlp_rows += f"""
        <tr>
            <td style="padding:8px;border-bottom:1px solid #e2e8f0">{p.get('type')}</td>
            <td style="padding:8px;border-bottom:1px solid #e2e8f0">{p.get('count')}</td>
            <td style="padding:8px;border-bottom:1px solid #e2e8f0">{p.get('sensitivity')}</td>
        </tr>
        """

    dlp_section = ""

    if dlp_rows:

        dlp_section = f"""
        <tr>
        <td style="padding:20px 36px 0">

        <div style="background:#ffffff;border:1px solid #e2e8f0;border-radius:8px;padding:18px">

        <p style="margin:0 0 10px;font-weight:600;color:#0f172a">
        Detected Sensitive Data
        </p>

        <table width="100%" style="border-collapse:collapse;font-size:14px">

        <tr style="background:#f8fafc">
            <th align="left" style="padding:8px">Data Type</th>
            <th align="left" style="padding:8px">Occurrences</th>
            <th align="left" style="padding:8px">Sensitivity</th>
        </tr>

        {dlp_rows}

        </table>

        </div>

        </td>
        </tr>
        """

    return f"""
<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:'Segoe UI',Arial">

<table width="100%" cellpadding="0" cellspacing="0">
<tr>
<td align="center" style="padding:36px 16px">

<table width="580" style="background:#ffffff;border-radius:10px">

<tr>
<td style="background:#b91c1c;color:white;padding:28px;border-radius:10px 10px 0 0">
<strong>⚠ PII File Exposed to External Users</strong>
</td>
</tr>

<tr>
<td style="padding:20px 36px">

<div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:18px">

<p><b>Incident ID:</b> {incident_id}</p>

<p><b>File:</b> {filename}</p>

<p><b>Full Path:</b> {filepath}</p>

<p><b>Uploaded By:</b> {username}</p>

<p><b>Uploader Email:</b> {email_badges}</p>

<p><b>Detected At:</b> {detected_at}</p>

</div>

</td>
</tr>

<tr>
<td style="padding:0 36px">

<div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:18px">

<b>Finding</b>

<p style="margin-top:8px">
This file has been classified as containing
<b>Personally Identifiable Information (PII)</b>
by the DSPM scanner and is located in a folder accessible
to one or more <b>external SFTP users</b>.
</p>

</div>

</td>
</tr>

{dlp_section}

<tr>
<td style="padding:20px 36px">

<div style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;padding:18px">

<b>Action Required</b>

<p style="margin-top:8px">
Verify whether external access to this file is authorised.
If not, revoke folder permissions immediately and review
the file contents with the uploader.
</p>

</div>

</td>
</tr>

<tr>
<td style="padding:16px;text-align:center;color:#94a3b8;font-size:12px">
PII Notification System · {now}
</td>
</tr>

</table>

</td>
</tr>
</table>

</body>
</html>
"""


# ──────────────────────────────────────────────
# Text Email
# ──────────────────────────────────────────────

def _build_text(
    incident_id,
    filepath,
    filename,
    username,
    user_email,
    detected_at,
    now,
    dlp_profiles
):

    uploader = username if not user_email else f"{username} ({user_email})"

    dlp_lines = ""

    for p in dlp_profiles:
        dlp_lines += f"{p.get('type')} — {p.get('count')} ({p.get('sensitivity')})\n"

    if not dlp_lines:
        dlp_lines = "No sensitive data details available."

    return f"""
PII SECURITY ALERT
==================

Incident ID : {incident_id}

File        : {filename}
Full path   : {filepath}

Uploaded by : {uploader}
Detected at : {detected_at}

Detected Sensitive Data
-----------------------
{dlp_lines}

Action Required
---------------
Verify whether external access is authorised.
If not, revoke folder permissions immediately.

-- PII Notification System | {now}
"""
