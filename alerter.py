"""
alerter.py — Correlation engine and email dispatch.

Called after every hourly DSPM sync.

For each PII filepath:
  Case 1 — No incident exists:
    → create incident (notified=0)
    → send email
    → mark notified=1 if successful, leave 0 to retry next hour

  Case 2 — Incident exists, notified=0 (previous email failed):
    → retry email
    → mark notified=1 if successful

  Case 3 — Incident exists, notified=1:
    → skip

user_email may be a comma-separated string of multiple addresses.
All are shown in the alert email and all receive the notification.
resolved is never read here — managed via future incident webpage only.
"""

import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text       import MIMEText
from datetime              import datetime, timezone

import storage
import access_cache
from config import Config

logger = logging.getLogger(__name__)


def correlate_and_alert(pii_filepaths: list[str]):
    if access_cache.is_empty():
        logger.warning(
            "Access cache is empty — skipping correlation. "
            "Waiting for first user sync to complete."
        )
        return

    if not pii_filepaths:
        logger.info("No PII filepaths — nothing to correlate.")
        return

    logger.info("Correlating %d PII filepaths...", len(pii_filepaths))
    sent = retried = skipped = no_access = no_uploader = 0

    for filepath in pii_filepaths:

        # O(depth) cache lookup — no DB read
        if not access_cache.has_external_access(filepath):
            no_access += 1
            continue

        incident = storage.get_incident(filepath)

        if incident and incident["notified"] == 1:
            skipped += 1
            continue

        # get uploader from upload_events
        event = storage.get_upload_event(filepath)
        if not event:
            logger.warning("No upload event found for PII file: %s", filepath)
            no_uploader += 1

        username    = event["username"]    if event else "UNKNOWN"
        user_email  = event["user_email"]  if event else ""
        detected_at = event["upload_time"] if event else datetime.now(timezone.utc).isoformat()

        # create incident if first time
        if not incident:
            incident_id = storage.create_incident(
                filepath    = filepath,
                username    = username,
                user_email  = user_email,
                detected_at = detected_at,
            )
            is_retry = False
        else:
            incident_id = incident["incident_id"]
            is_retry    = True
            retried    += 1
            logger.info("Retrying failed alert for incident %s", incident_id)

        ok = _send_alert(incident_id, filepath, username, user_email, detected_at)

        if ok:
            storage.mark_notified(incident_id)
            sent += 1
            logger.warning(
                "Alert SENT | incident=%s | file=%s | uploader=%s%s",
                incident_id, filepath, username, " [retry]" if is_retry else ""
            )
        else:
            logger.error(
                "Alert FAILED (will retry next hour) | incident=%s | file=%s",
                incident_id, filepath
            )

    logger.info(
        "Correlation done — sent: %d | retried: %d | skipped: %d | "
        "no external access: %d | missing upload event: %d",
        sent, retried, skipped, no_access, no_uploader
    )


# ── email ──────────────────────────────────────────────────────────────────────

def _recipient_list(user_email: str) -> list[str]:
    """
    Split comma-separated uploader emails into a clean list.
    e.g. "a@x.com, b@x.com" → ["a@x.com", "b@x.com"]
    """
    if not user_email:
        return []
    return [e.strip() for e in user_email.split(",") if e.strip()]


def _send_alert(
    incident_id: str,
    filepath:    str,
    username:    str,
    user_email:  str,
    detected_at: str,
) -> bool:
    filename   = filepath.split("/")[-1]
    now        = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    recipients = [Config.SECURITY_TEAM_EMAIL]

    try:
        msg            = MIMEMultipart("alternative")
        msg["Subject"] = f"[PII ALERT] External access detected: {filename}"
        msg["From"]    = Config.SMTP_FROM
        msg["To"]      = Config.SECURITY_TEAM_EMAIL

        msg.attach(MIMEText(
            _build_text(incident_id, filepath, filename, username, user_email, detected_at, now),
            "plain"
        ))
        msg.attach(MIMEText(
            _build_html(incident_id, filepath, filename, username, user_email, detected_at, now),
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


def _format_uploader(username: str, user_email: str) -> str:
    """Format uploader line — handles multiple comma-separated emails."""
    emails = _recipient_list(user_email)
    if not emails:
        return username
    return f"{username} ({', '.join(emails)})"


def _build_html(
    incident_id, filepath, filename, username, user_email, detected_at, now
) -> str:
    emails        = _recipient_list(user_email)
    email_badges  = "".join(
        f"<span style='display:inline-block;background:#f1f5f9;border:1px solid #e2e8f0;"
        f"border-radius:4px;padding:2px 10px;font-size:13px;margin:2px 4px 2px 0'>"
        f"{e}</span>"
        for e in emails
    ) if emails else "<span style='color:#94a3b8'>—</span>"

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#f1f5f9;
             font-family:'Segoe UI',Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0">
<tr><td align="center" style="padding:36px 16px">
<table width="580" cellpadding="0" cellspacing="0"
       style="background:#fff;border-radius:10px;
              box-shadow:0 2px 8px rgba(0,0,0,.08)">

  <!-- header -->
  <tr>
    <td style="background:#b91c1c;border-radius:10px 10px 0 0;padding:28px 36px">
      <p style="margin:0 0 4px;color:rgba(255,255,255,.65);font-size:11px;
                text-transform:uppercase;letter-spacing:1.5px">Security Alert</p>
      <h1 style="margin:0;color:#fff;font-size:20px;font-weight:700">
        ⚠️&nbsp; PII File Exposed to External Users
      </h1>
    </td>
  </tr>

  <!-- incident id -->
  <tr>
    <td style="padding:20px 36px 0">
      <span style="display:inline-block;background:#f1f5f9;
                   border:1px solid #e2e8f0;border-radius:6px;
                   padding:6px 14px;font-family:monospace;
                   font-size:12px;color:#475569">
        Incident ID: {incident_id}
      </span>
    </td>
  </tr>

  <!-- file details -->
  <tr><td style="padding:20px 36px 0">
    <table width="100%" cellpadding="0" cellspacing="0"
           style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px">
      <tr><td style="padding:20px 24px">
        <table width="100%" cellpadding="7">
          <tr>
            <td style="color:#94a3b8;font-size:12px;text-transform:uppercase;
                       letter-spacing:.5px;white-space:nowrap;width:120px">File</td>
            <td style="font-weight:600;color:#0f172a;font-size:15px">{filename}</td>
          </tr>
          <tr>
            <td style="color:#94a3b8;font-size:12px;text-transform:uppercase;
                       letter-spacing:.5px">Full Path</td>
            <td style="font-family:monospace;font-size:13px;color:#334155;
                       word-break:break-all">{filepath}</td>
          </tr>
          <tr>
            <td style="color:#94a3b8;font-size:12px;text-transform:uppercase;
                       letter-spacing:.5px">Uploaded By</td>
            <td style="color:#0f172a;font-weight:600">{username}</td>
          </tr>
          <tr>
            <td style="color:#94a3b8;font-size:12px;text-transform:uppercase;
                       letter-spacing:.5px;vertical-align:top;padding-top:10px">
              Uploader Email
            </td>
            <td style="padding-top:6px">{email_badges}</td>
          </tr>
          <tr>
            <td style="color:#94a3b8;font-size:12px;text-transform:uppercase;
                       letter-spacing:.5px">Detected At</td>
            <td style="color:#475569">{detected_at}</td>
          </tr>
        </table>
      </td></tr>
    </table>
  </td></tr>

  <!-- finding -->
  <tr><td style="padding:20px 36px 0">
    <div style="background:#fef2f2;border:1px solid #fecaca;
                border-radius:8px;padding:18px 22px">
      <p style="margin:0;color:#991b1b;font-weight:600;font-size:14px">Finding</p>
      <p style="margin:8px 0 0;color:#7f1d1d;font-size:14px;line-height:1.6">
        This file has been classified as containing
        <strong>Personally Identifiable Information (PII)</strong>
        by the DSPM scanner and is located in a folder accessible
        to one or more <strong>external SFTP users</strong>.
      </p>
    </div>
  </td></tr>

  <!-- action -->
  <tr><td style="padding:20px 36px">
    <div style="background:#eff6ff;border:1px solid #bfdbfe;
                border-radius:8px;padding:18px 22px">
      <p style="margin:0;color:#1e40af;font-weight:600;font-size:14px">
        Action Required
      </p>
      <p style="margin:8px 0 0;color:#1e3a8a;font-size:14px;line-height:1.6">
        Verify whether external access to this file is authorised.
        If not, revoke folder permissions immediately and review
        the file contents with the uploader.
      </p>
    </div>
  </td></tr>

  <!-- footer -->
  <tr>
    <td style="border-top:1px solid #f1f5f9;padding:16px 36px;
               text-align:center;border-radius:0 0 10px 10px">
      <p style="margin:0;color:#94a3b8;font-size:12px">
        PII Notification System &nbsp;·&nbsp; {now}
      </p>
    </td>
  </tr>

</table>
</td></tr>
</table>
</body>
</html>"""


def _build_text(
    incident_id, filepath, filename, username, user_email, detected_at, now
) -> str:
    uploader = _format_uploader(username, user_email)
    return f"""PII SECURITY ALERT
==================
Incident ID  : {incident_id}
File         : {filename}
Full path    : {filepath}
Uploaded by  : {uploader}
Detected at  : {detected_at}

Finding:
  This file contains PII (confirmed by DSPM) and is located in a
  folder accessible to one or more external SFTP users.

Action required:
  Verify whether external access is authorised.
  If not, revoke folder permissions immediately.

-- PII Notification System | {now}
"""
