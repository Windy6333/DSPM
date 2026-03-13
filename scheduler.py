"""
scheduler.py — Background job orchestration.

  user_sync   daily at 02:00 UTC
                → EFT auth → fetch users → filter external
                → normalise folders → rebuild access_cache

  dspm_sync   every 10 minutes
                → fetch DSPM PII filepaths → correlate → alert
"""

import logging
import threading

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron         import CronTrigger
from apscheduler.triggers.interval     import IntervalTrigger

logger     = logging.getLogger(__name__)
_scheduler = None


def run_user_sync():
    logger.info("=== User Sync: started ===")
    try:
        import api_clients
        import access_cache

        folders = api_clients.fetch_external_user_folders()
        if not folders:
            logger.warning("User sync: no external folders returned — cache not updated.")
            return

        access_cache.rebuild(folders)

    except Exception:
        logger.exception("User sync failed.")
    logger.info("=== User Sync: complete ===")


def run_dspm_sync():
    logger.info("=== DSPM Sync: started ===")
    try:
        import api_clients
        from alerter import correlate_and_alert

        pii_filepaths = api_clients.fetch_pii_filepaths()
        correlate_and_alert(pii_filepaths)

    except Exception:
        logger.exception("DSPM sync failed.")
    logger.info("=== DSPM Sync: complete ===")


def start():
    global _scheduler

    _scheduler = BackgroundScheduler(
        job_defaults={"coalesce": True, "max_instances": 1},
        timezone="UTC",
    )

    _scheduler.add_job(
        run_user_sync,
        trigger=CronTrigger(hour=2, minute=0),
        id="user_sync",
        name="SFTP External User Sync",
        replace_existing=True,
    )

    _scheduler.add_job(
        run_dspm_sync,
        trigger=IntervalTrigger(minutes=3),
        id="dspm_sync",
        name="DSPM PII Sync + Correlation",
        replace_existing=True,
    )

    _scheduler.start()
    logger.info("Scheduler running — user sync: daily 02:00 UTC | dspm sync: every 10 mins")

    threading.Thread(target=_startup_sync, daemon=True).start()


def _startup_sync():
    import time
    time.sleep(2)
    logger.info("Running startup sync...")
    run_user_sync()
    run_dspm_sync()
