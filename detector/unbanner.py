import time
import threading
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from blocker import Blocker

logger = logging.getLogger("unbanner")


class Unbanner:
   # This class is responsible for automatically unbanning IP addresses after their ban duration has expired.
    def __init__(self, blocker: "Blocker", check_interval: int = 30):
        self.blocker = blocker
        self.check_interval = check_interval
        self._stop_event = threading.Event()
        self._thread: threading.Thread = None
    # This method starts the background thread that periodically checks for expired bans and unbans them.
    def start(self):
        self._thread = threading.Thread(
            target=self._run_loop,
            name="unbanner",
            daemon=True
        )
        self._thread.start()
        logger.info("Unbanner started — checking every %ds", self.check_interval)
    
    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)
        logger.info("Unbanner stopped.")

    def _run_loop(self):
        while not self._stop_event.is_set():
            # Wait first, then check — avoids a pointless run at startup.
            self._stop_event.wait(timeout=self.check_interval)

            if self._stop_event.is_set():
                break

            self._check_expired_bans()

    def _check_expired_bans(self):
        now = time.time()

        # Get the current list of active bans from the blocker.
        banned_ips = self.blocker.get_banned_ips()

        for ban_info in banned_ips:
            ip = ban_info["ip"]

            # Never touch permanent bans — they stay until a human
            # manually intervenes.
            if ban_info["permanent"]:
                continue

            expires_at = ban_info.get("expires_at")
            if expires_at is None:
                continue

            if now >= expires_at:
                # This ban has expired — release it.
                logger.info(
                    "Ban expired for %s — releasing after %d offenses.",
                    ip, ban_info["offense_count"]
                )
                try:
                    self.blocker.unban(ip)
                except Exception as e:
                    logger.error(
                        "Error while unbanning %s: %s", ip, e
                    )