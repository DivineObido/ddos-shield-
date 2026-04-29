import os
import sys
import time
import signal
import logging
import yaml

from monitor import LogMonitor
from baseline import BaselineTracker
from detector import AnomalyDetector
from blocker import Blocker
from unbanner import Unbanner
from notifier import Notifier
from dashboard import Dashboard
from audit import AuditLogger

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout
)

logger = logging.getLogger("main")


def load_config(path: str = "config.yaml") -> dict:
    with open(path, "r") as f:
        config = yaml.safe_load(f)
    logger.info("Configuration loaded from %s", path)
    return config


def main():
    logger.info("DDoS Shield starting up...")

    config = load_config()

    log_cfg       = config["log"]
    slack_cfg     = config["slack"]
    detection_cfg = config["detection"]
    baseline_cfg  = config["baseline"]
    blocking_cfg  = config["blocking"]
    dashboard_cfg = config["dashboard"]

    audit_path = log_cfg["audit_path"]
    os.makedirs(os.path.dirname(audit_path), exist_ok=True)

    # --- Create components ---

    audit = AuditLogger(audit_path=audit_path)

    notifier = Notifier(webhook_url=slack_cfg["webhook_url"])

    baseline = BaselineTracker(
        window_minutes=baseline_cfg["window_minutes"],
        recalc_interval=baseline_cfg["recalc_interval_seconds"],
        min_samples=baseline_cfg["min_samples"],
        floor_rps=baseline_cfg["floor_rps"]
    )

    # Detector is created FIRST with no callbacks yet.
    # Callbacks are wired in after blocker is created below.
    # This avoids the circular reference where on_ban references
    # detector before detector exists.
    detector = AnomalyDetector(
        baseline=baseline,
        zscore_threshold=detection_cfg["zscore_threshold"],
        spike_multiplier=detection_cfg["spike_multiplier"],
        error_rate_multiplier=detection_cfg["error_rate_multiplier"],
        window_seconds=detection_cfg["sliding_window_seconds"],
        on_ip_anomaly=None,
        on_global_anomaly=None
    )

    # Now blocker is created — on_ban and on_unban can safely
    # reference detector because it already exists above.
    def on_ban(ip, duration_minutes, offense_count, reason, rate, baseline_mean):
        audit.log_ban(
            ip=ip,
            reason=reason,
            rate=rate,
            baseline_mean=baseline_mean,
            duration_minutes=duration_minutes,
            offense_count=offense_count
        )
        notifier.send_ban_alert(
            ip=ip,
            duration_minutes=duration_minutes,
            offense_count=offense_count,
            reason=reason,
            rate=rate,
            baseline_mean=baseline_mean
        )
        detector.mark_banned(ip)

    def on_unban(ip, offense_count):
        audit.log_unban(ip=ip, offense_count=offense_count)
        notifier.send_unban_alert(ip=ip, offense_count=offense_count)
        detector.mark_unbanned(ip)

    blocker = Blocker(
        ban_schedule_minutes=blocking_cfg["ban_schedule_minutes"],
        on_ban=on_ban,
        on_unban=on_unban
    )

    # Now wire the anomaly callbacks into the detector.
    # These reference blocker which is now defined above.
    def on_ip_anomaly(ip, rate, baseline_mean, reason):
        blocker.ban(
            ip=ip,
            reason=reason,
            rate=rate,
            baseline_mean=baseline_mean
        )

    def on_global_anomaly(rate, baseline_mean, reason):
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

    # Attach callbacks to the detector now that everything exists
    detector.on_ip_anomaly = on_ip_anomaly
    detector.on_global_anomaly = on_global_anomaly

    unbanner = Unbanner(blocker=blocker)

    dashboard = Dashboard(
        detector=detector,
        blocker=blocker,
        baseline=baseline,
        port=dashboard_cfg["port"],
        top_ips_count=dashboard_cfg["top_ips_count"]
    )

    monitor = LogMonitor(
        log_path=log_cfg["path"],
        callback=detector.process
    )

    # Wrap baseline recalculate to also write audit entries
    _original_recalculate = baseline._recalculate

    def _audited_recalculate(now: int):
        _original_recalculate(now)
        hour = int(time.strftime("%H"))
        audit.log_baseline_recalc(
            mean=baseline.effective_mean,
            std=baseline.effective_std,
            sample_count=len(baseline._rolling),
            hour=hour
        )

    baseline._recalculate = _audited_recalculate

    # --- Start all components ---
    logger.info("Starting all components...")

    monitor.start()
    unbanner.start()
    dashboard.start()

    logger.info("DDoS Shield is fully operational.")
    logger.info("Dashboard available at http://0.0.0.0:%d", dashboard_cfg["port"])

    def shutdown(signum, frame):
        logger.info("Shutdown signal received — stopping...")
        monitor.stop()
        unbanner.stop()
        logger.info("DDoS Shield stopped cleanly.")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()