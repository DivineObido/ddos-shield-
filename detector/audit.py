import logging
import threading
import time
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("audit")


class AuditLogger:
    def __init__(self, audit_path: str):
        self.audit_path = audit_path
        self._lock = threading.Lock()

        # Set up a dedicated file handler for the audit log.
        # Separate from the main application log so audit entries are easy to find and parse independently.
        self._file_logger = logging.getLogger("audit.file")
        self._file_logger.setLevel(logging.INFO)
        self._file_logger.propagate = False

        try:
            handler = logging.FileHandler(audit_path)
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._file_logger.addHandler(handler)
            logger.info("Audit log initialized at %s", audit_path)
        except Exception as e:
            logger.error("Could not open audit log at %s: %s", audit_path, e)

    def _now(self) -> str:
       
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    # This method logs a ban event to the audit log.
    def log_ban(self,
                ip: str,
                reason: str,
                rate: float,
                baseline_mean: float,
                duration_minutes: Optional[int],
                offense_count: int):
        
        duration_label = f"{duration_minutes}m" if duration_minutes else "permanent"
        entry = (
            f"[{self._now()}] BAN ip={ip} | "
            f"condition={reason} | "
            f"rate={rate:.2f}req/s | "
            f"baseline={baseline_mean:.2f}req/s | "
            f"duration={duration_label} | "
            f"offense={offense_count}"
        )
        self._write(entry)
    # This method logs an unban event to the audit log.
    def log_unban(self, ip: str, offense_count: int):
        entry = (
            f"[{self._now()}] UNBAN ip={ip} | "
            f"offense_count={offense_count}"
        )
        self._write(entry)
   
    def log_baseline_recalc(self,
                             mean: float,
                             std: float,
                             sample_count: int,
                             hour: int):
        entry = (
            f"[{self._now()}] BASELINE_RECALC | "
            f"mean={mean:.4f} | "
            f"std={std:.4f} | "
            f"samples={sample_count} | "
            f"hour={hour}"
        )
        self._write(entry)
     # This method logs a global anomaly event to the audit log.
    def log_global_anomaly(self, rate: float, baseline_mean: float, reason: str):

        entry = (
            f"[{self._now()}] GLOBAL_ANOMALY | "
            f"rate={rate:.2f}req/s | "
            f"baseline={baseline_mean:.2f}req/s | "
            f"condition={reason}"
        )
        self._write(entry)

    def _write(self, entry: str):
    
        with self._lock:
            try:
                self._file_logger.info(entry)
            except Exception as e:
                logger.error("Failed to write audit entry: %s", e)