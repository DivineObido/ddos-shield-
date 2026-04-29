import time
import logging
import threading
import requests
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("notifier")


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


class Notifier:
    # This class is responsible for sending notifications to Slack when certain events occur.
    def __init__(self, webhook_url: str, timeout: int = 10):
        self.webhook_url = webhook_url
        self.timeout = timeout
    
    # This internal method sends a payload to the configured Slack webhook URL in a background thread.
    def _send(self, payload: dict):
        def _do_send():
            try:
                response = requests.post(
                    self.webhook_url,
                    json=payload,
                    timeout=self.timeout
                )
                if response.status_code != 200:
                    logger.error(
                        "Slack returned %d: %s",
                        response.status_code, response.text
                    )
                else:
                    logger.info("Slack alert sent successfully.")
            except requests.exceptions.Timeout:
                logger.error("Slack webhook timed out after %ds.", self.timeout)
            except requests.exceptions.RequestException as e:
                logger.error("Failed to send Slack alert: %s", e)

        thread = threading.Thread(target=_do_send, daemon=True)
        thread.start()
    
    # This method sends a Slack alert when an IP address is banned, including details about the ban and the traffic that triggered it.
    def send_ban_alert(self,
                       ip: str,
                       duration_minutes: Optional[int],
                       offense_count: int,
                       reason: str,
                       rate: float,
                       baseline_mean: float):
    
        duration_label = f"{duration_minutes} minutes" if duration_minutes else "PERMANENT"
        offense_label = f"{offense_count} (permanent threshold reached)" \
            if not duration_minutes else str(offense_count)

        payload = {
            "text": f":rotating_light: *IP BANNED* — `{ip}`",
            "attachments": [
                {
                    "color": "#FF0000",
                    "fields": [
                        {
                            "title": "Banned IP",
                            "value": f"`{ip}`",
                            "short": True
                        },
                        {
                            "title": "Ban Duration",
                            "value": duration_label,
                            "short": True
                        },
                        {
                            "title": "Offense Count",
                            "value": offense_label,
                            "short": True
                        },
                        {
                            "title": "Current Rate",
                            "value": f"{rate:.2f} req/s",
                            "short": True
                        },
                        {
                            "title": "Baseline Mean",
                            "value": f"{baseline_mean:.2f} req/s",
                            "short": True
                        },
                        {
                            "title": "Condition Fired",
                            "value": reason,
                            "short": False
                        },
                        {
                            "title": "Timestamp",
                            "value": _now_utc(),
                            "short": False
                        }
                    ]
                }
            ]
        }
        logger.info("Sending ban alert for %s to Slack.", ip)
        self._send(payload)
    # This method sends a Slack alert when an IP address is unbanned, including details
    # about the unban and the offense history of that IP.
    def send_unban_alert(self, ip: str, offense_count: int):
        payload = {
            "text": f":white_check_mark: *IP UNBANNED* — `{ip}`",
            "attachments": [
                {
                    "color": "#36A64F",
                    "fields": [
                        {
                            "title": "Released IP",
                            "value": f"`{ip}`",
                            "short": True
                        },
                        {
                            "title": "Total Offenses",
                            "value": str(offense_count),
                            "short": True
                        },
                        {
                            "title": "Status",
                            "value": "Ban expired — traffic allowed again",
                            "short": False
                        },
                        {
                            "title": "Timestamp",
                            "value": _now_utc(),
                            "short": False
                        }
                    ]
                }
            ]
        }
        logger.info("Sending unban alert for %s to Slack.", ip)
        self._send(payload)
    # This method sends a Slack alert when overall traffic across all IPs spikes to anomalous levels,
    # including details about the spike and the baseline for comparison.
    def send_global_alert(self, rate: float, baseline_mean: float, reason: str):
        payload = {
            "text": ":warning: *GLOBAL TRAFFIC ANOMALY DETECTED*",
            "attachments": [
                {
                    "color": "#FFA500",
                    "fields": [
                        {
                            "title": "Global Request Rate",
                            "value": f"{rate:.2f} req/s",
                            "short": True
                        },
                        {
                            "title": "Baseline Mean",
                            "value": f"{baseline_mean:.2f} req/s",
                            "short": True
                        },
                        {
                            "title": "Condition Fired",
                            "value": reason,
                            "short": False
                        },
                        {
                            "title": "Action Taken",
                            "value": "Alert only — no automatic block for global anomalies",
                            "short": False
                        },
                        {
                            "title": "Timestamp",
                            "value": _now_utc(),
                            "short": False
                        }
                    ]
                }
            ]
        }
        logger.info("Sending global anomaly alert to Slack.")
        self._send(payload)