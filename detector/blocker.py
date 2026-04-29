"""
blocker.py — The enforcer. Bans IP addresses using iptables when
the detector flags them as anomalous.

When an IP is banned, a kernel-level firewall rule is added that
drops all its packets before they even reach Nginx. This is more
efficient than blocking at the application level because the server
never has to process the connection at all — the traffic is killed
the moment it arrives at the network layer.

Bans follow an escalating backoff schedule:
  First offense  → 10 minutes
  Second offense → 30 minutes
  Third offense  → 2 hours
  Fourth+        → permanent
"""

import subprocess
import threading
import logging
import time
from typing import Dict, List, Optional, Callable

logger = logging.getLogger("blocker")


class BanRecord:

    def __init__(self):
        self.offense_count: int = 0
        self.ban_expires_at: Optional[float] = None
        self.permanent: bool = False
        self.last_banned_at: Optional[float] = None
        self.last_reason: str = ""


class Blocker:

    def __init__(self,
                 ban_schedule_minutes: List[int],
                 on_ban: Optional[Callable] = None,
                 on_unban: Optional[Callable] = None):

        self.ban_schedule_minutes = ban_schedule_minutes
        self.on_ban = on_ban
        self.on_unban = on_unban

        self._lock = threading.Lock()
        self._registry: Dict[str, BanRecord] = {}

    def ban(self, ip: str, reason: str, rate: float, baseline_mean: float):

        with self._lock:
            if ip not in self._registry:
                self._registry[ip] = BanRecord()

            record = self._registry[ip]

            # If already permanently banned, nothing more to do.
            if record.permanent:
                logger.info("IP %s is already permanently banned — skipping.", ip)
                return

            # If currently banned and not yet expired, skip re-banning.
            if record.ban_expires_at and record.ban_expires_at > time.time():
                logger.info("IP %s is already banned — skipping duplicate.", ip)
                return

            record.offense_count += 1
            record.last_banned_at = time.time()
            record.last_reason = reason

            # Pick the ban duration from the escalating schedule.
            offense_index = record.offense_count - 1
            if offense_index >= len(self.ban_schedule_minutes):
                duration_minutes = None
                record.permanent = True
                record.ban_expires_at = None
            else:
                duration_minutes = self.ban_schedule_minutes[offense_index]
                record.ban_expires_at = time.time() + (duration_minutes * 60)

        self._add_iptables_rule(ip)

        duration_label = f"{duration_minutes} minutes" if duration_minutes else "permanent"
        logger.warning(
            "Banned %s | offense=%d | duration=%s | reason=%s | rate=%.2f | mean=%.2f",
            ip, record.offense_count, duration_label, reason, rate, baseline_mean
        )

        if self.on_ban:
            self.on_ban(
                ip=ip,
                duration_minutes=duration_minutes,
                offense_count=record.offense_count,
                reason=reason,
                rate=rate,
                baseline_mean=baseline_mean
            )
    # This method unbans an IP address by removing the corresponding iptables rule and updating the registry.
    def unban(self, ip: str):
        with self._lock:
            record = self._registry.get(ip)
            if not record:
                logger.warning("Tried to unban unknown IP: %s", ip)
                return
            record.ban_expires_at = None

        self._remove_iptables_rule(ip)

        logger.info(
            "Unbanned %s | total offenses so far=%d",
            ip, record.offense_count
        )

        if self.on_unban:
            self.on_unban(ip=ip, offense_count=record.offense_count)
            
   # This method adds an iptables rule to drop all incoming packets from the specified IP address.
    def _add_iptables_rule(self, ip: str):
        try:
            subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True,
                timeout=5
            )
            logger.info("iptables DROP rule added for %s", ip)
        except subprocess.CalledProcessError as e:
            logger.error(
                "Failed to add iptables rule for %s: %s", ip, e.stderr
            )
        except subprocess.TimeoutExpired:
            logger.error("iptables command timed out for %s", ip)
   # This method removes the iptables rule for a given IP address, effectively unbanning it.
    def _remove_iptables_rule(self, ip: str):
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True,
                timeout=5
            )
            logger.info("iptables DROP rule removed for %s", ip)
        except subprocess.CalledProcessError as e:
            logger.warning(
                "Could not remove iptables rule for %s (may not exist): %s",
                ip, e.stderr
            )
        except subprocess.TimeoutExpired:
            logger.error("iptables remove command timed out for %s", ip)

    def get_banned_ips(self) -> List[dict]:
        """
        Returns a list of all currently banned IPs with their details.
        Used by the dashboard and audit logger.
        """
        now = time.time()
        with self._lock:
            banned = []
            for ip, record in self._registry.items():
                is_active = (
                    record.permanent or
                    (record.ban_expires_at and record.ban_expires_at > now)
                )
                if is_active:
                    banned.append({
                        "ip": ip,
                        "offense_count": record.offense_count,
                        "permanent": record.permanent,
                        "expires_at": record.ban_expires_at,
                        "reason": record.last_reason,
                        "banned_at": record.last_banned_at,
                    })
            return banned

    def get_record(self, ip: str) -> Optional[BanRecord]:
        """
        Returns the full ban record for one IP address.
        Used by the unbanner to check expiry times.
        """
        with self._lock:
            return self._registry.get(ip)