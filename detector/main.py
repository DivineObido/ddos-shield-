import os
import sys
import time
import signal
import logging
import yaml
from typing import Optional

from monitor import LogMonitor
from baseline import BaselineTracker
from detector import AnomalyDetector
from blocker import Blocker
from unbanner import Unbanner
from notifier import Notifier
from dashboard import Dashboard
from audit import AuditLogger

# Configure logging so every module's output goes to stdout with a consistent format.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout
)

logger = logging.getLogger("main")

# This function loads the configuration from the YAML file.
def load_config(path: str = "config.yaml") -> dict:
    with open(path, "r") as f:
        config = yaml.safe_load(f)
    logger.info("Configuration loaded from %s", path)
    return config

# The main function that starts the entire detection daemon.
def main():
    logger.info("DDoS Shield starting up...")

    # Load config
    config = load_config()

    log_cfg        = config["log"]
    slack_cfg      = config["slack"]
    detection_cfg  = config["detection"]
    baseline_cfg   = config["baseline"]
    blocking_cfg   = config["blocking"]
    dashboard_cfg  = config["dashboard"]

    # Ensure audit log directory exists.
    # The directory is created in the Dockerfile but we check
    # here too in case someone runs the daemon outside Docker.
    audit_path = log_cfg["audit_path"]
    os.makedirs(os.path.dirname(audit_path), exist_ok=True)

    
    # Audit logger — needs to exist first so everything else can log to it from the moment they start operating.
    audit = AuditLogger(audit_path=audit_path)

    # Sends notifications to Slack.
    notifier = Notifier(webhook_url=slack_cfg["webhook_url"])

    # Baseline tracker that learns what normal traffic looks like.
    baseline = BaselineTracker(
        window_minutes=baseline_cfg["window_minutes"],
        recalc_interval=baseline_cfg["recalc_interval_seconds"],
        min_samples=baseline_cfg["min_samples"],
        floor_rps=baseline_cfg["floor_rps"]
    )

    # Blocker which manages iptables bans.
    # Callbacks are defined inline here so they have access to both the audit logger and the notifier without either
    # needing to know about the other directly.
    def on_ban(ip, duration_minutes, offense_count, reason, rate, baseline_mean):
        # Write to audit log
        audit.log_ban(
            ip=ip,
            reason=reason,
            rate=rate,
            baseline_mean=baseline_mean,
            duration_minutes=duration_minutes,
            offense_count=offense_count
        )
        # Send Slack alert
        notifier.send_ban_alert(
            ip=ip,
            duration_minutes=duration_minutes,
            offense_count=offense_count,
            reason=reason,
            rate=rate,
            baseline_mean=baseline_mean
        )
        # Tell the detector this IP is now banned
        detector.mark_banned(ip)

    def on_unban(ip, offense_count):
        # Write to audit log
        audit.log_unban(ip=ip, offense_count=offense_count)
        # Send Slack alert
        notifier.send_unban_alert(ip=ip, offense_count=offense_count)
        # Tell the detector this IP is active again
        detector.mark_unbanned(ip)

    blocker = Blocker(
        ban_schedule_minutes=blocking_cfg["ban_schedule_minutes"],
        on_ban=on_ban,
        on_unban=on_unban
    )

    # Anomaly detector — the brain.
    # Callbacks wire detection events to the blocker and notifier.
    def on_ip_anomaly(ip, rate, baseline_mean, reason):
        blocker.ban(
            ip=ip,
            reason=reason,
            rate=rate,
            baseline_mean=baseline_mean
        )

    def on_global_anomaly(rate, baseline_mean, reason):
        # Global anomaly — alert only, no ban.
        audit.log_global_anomaly(
            rate=rate,
            baseline_mean=baseline_mean,
            reason=reason
        )
        notifier.send_global_alert(
            rate=rate,
            baseline_mean=baseline_mean,
            reason=reason
        )

    detector = AnomalyDetector(
        baseline=baseline,
        zscore_threshold=detection_cfg["zscore_threshold"],
        spike_multiplier=detection_cfg["spike_multiplier"],
        error_rate_multiplier=detection_cfg["error_rate_multiplier"],
        window_seconds=detection_cfg["sliding_window_seconds"],
        on_ip_anomaly=on_ip_anomaly,
        on_global_anomaly=on_global_anomaly
    )

    # Unbanner — releases bans on schedule.
    unbanner = Unbanner(blocker=blocker)

    # Dashboard — live metrics web UI.
    dashboard = Dashboard(
        detector=detector,
        blocker=blocker,
        baseline=baseline,
        port=dashboard_cfg["port"],
        top_ips_count=dashboard_cfg["top_ips_count"]
    )

    # Log monitor — tails the Nginx log and feeds entries
    # into the detector which feeds the baseline.
    monitor = LogMonitor(
        log_path=log_cfg["path"],
        callback=detector.process
    )

    # Hook baseline recalculation into the audit log.
    # We wrap the baseline's _recalculate method to also write
    # an audit entry every time a recalculation happens.
    _original_recalculate = baseline._recalculate

    def _audited_recalculate(now: int):
        _original_recalculate(now)
        import time as _time
        hour = int(_time.strftime("%H"))
        audit.log_baseline_recalc(
            mean=baseline.effective_mean,
            std=baseline.effective_std,
            sample_count=len(baseline._rolling),
            hour=hour
        )

    baseline._recalculate = _audited_recalculate

    # Start all components 
    logger.info("Starting all components...")

    monitor.start()
    unbanner.start()
    dashboard.start()

    logger.info("DDoS Shield is fully operational.")
    logger.info("Dashboard available at http://0.0.0.0:%d", dashboard_cfg["port"])

    # Handle graceful shutdown on SIGINT (Ctrl+C) and SIGTERM
    # (Docker stop). When either signal arrives we stop the
    # monitor and unbanner cleanly before exiting.
    def shutdown(signum, frame):
        logger.info("Shutdown signal received — stopping...")
        monitor.stop()
        unbanner.stop()
        logger.info("DDoS Shield stopped cleanly.")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Keep the main thread alive.
    # Everything runs in background threads — the main thread
    # just needs to stay alive so the process does not exit.
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()