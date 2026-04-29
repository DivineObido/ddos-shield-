import json
import os
import time
import threading
import logging
from typing import Callable, Optional

logger = logging.getLogger("monitor")


class LogEntry:
    """
    A single HTTP request captured from the Nginx log.
    This class holds all the relevant information about one request, such
    as the source IP, timestamp, and HTTP status.
    """
    __slots__ = (
        "source_ip", "timestamp", "method", "path",
        "status", "response_size", "raw"
    )

    def __init__(self, source_ip: str, timestamp: str, method: str,
                 path: str, status: int, response_size: int, raw: str):
        self.source_ip = source_ip      # Who made the request
        self.timestamp = timestamp      # When it happened
        self.method = method            # What kind of request (GET, POST etc)
        self.path = path                # What page or resource they asked for
        self.status = status            # What the server replied (200 = ok, 404 = not found etc)
        self.response_size = response_size  # How big the response was in bytes
        self.raw = raw                  # The original unmodified log line

    def is_error(self) -> bool:
        # Returns True if the server replied with an error.
        # Status codes 400 and above mean something went wrong
        return self.status >= 400


def parse_line(line: str) -> Optional[LogEntry]:
    """
    Parse a single JSON log line from Nginx into a LogEntry object.

    Nginx writes each request as a JSON line to the log file.
    This function reads that line and pulls out the fields we care about.
    If the line is empty or can't be parsed, it returns None.
    """
    line = line.strip()
    if not line:
        return None
    try:
        data = json.loads(line)
        return LogEntry(
            source_ip=data.get("source_ip", "0.0.0.0"),
            timestamp=data.get("timestamp", ""),
            method=data.get("method", "GET"),
            path=data.get("path", "/"),
            status=int(data.get("status", 0)),
            response_size=int(data.get("response_size", 0)),
            raw=line,
        )
    except (json.JSONDecodeError, ValueError, KeyError) as e:
        logger.debug("Failed to parse log line: %s | error: %s", line[:120], e)
        return None


class LogMonitor:
    """
    Watches the Nginx log file continuously and reacts to every new line.

    The moment Nginx writes a new request, this class reads it, parses it, and passes it
    on to the rest of the system via a callback function.

    It also handles log rotation, when the log file gets replaced with
    a fresh one, the monitor detects this and switches to reading the
    new file automatically without missing any requests.
    """

    def __init__(self, log_path: str, callback: Callable[[LogEntry], None],
                 poll_interval: float = 0.1):
    
        self.log_path = log_path
        self.callback = callback
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self):
        """
        Starts watching the log file in the background.
        """
        self._thread = threading.Thread(
            target=self._tail_loop, name="log-monitor", daemon=True
        )
        self._thread.start()
        logger.info("LogMonitor started — watching %s", self.log_path)

    def stop(self):
        """
        Stops watching the log file cleanly.
        """
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("LogMonitor stopped")

    def _wait_for_file(self):
        """
        Waits patiently until the log file exists before starting to read.

        When the system first starts up, Nginx might take a few seconds
        to create the log file. Instead of crashing immediately, we just
        wait and keep checking until the file appears.
        """
        while not self._stop_event.is_set():
            if os.path.exists(self.log_path):
                return
            logger.warning("Waiting for log file to appear: %s", self.log_path)
            time.sleep(2)

    def _tail_loop(self):
        """
        The main reading loop. This runs forever until stop() is called.

        It waits for the log file to exist
        Open it and jump to the end (ignore old history)
        Keep reading new lines as they appear
        If the file gets rotated, reopen the new file automatically

        """
        self._wait_for_file()

        current_inode = os.stat(self.log_path).st_ino
        file = open(self.log_path, "r", encoding="utf-8", errors="replace")

        file.seek(0, 2)
        logger.info("Tailing log from end of file.")

        while not self._stop_event.is_set():
            line = file.readline()

            if line:
                # A new request came in — parse it and pass it on
                logger.info("Read new log line from nginx")
                entry = parse_line(line)
                if entry:
                    try:
                        self.callback(entry)
                    except Exception as e:
                        logger.error("Callback error: %s", e)
            else:
                # No new lines yet — rest briefly then check for rotation
                time.sleep(self.poll_interval)
                try:
                    stat = os.stat(self.log_path)
                    if stat.st_ino != current_inode or stat.st_size < file.tell():
                        # The file was rotated — switch to the new one
                        logger.info("Log rotation detected — reopening file.")
                        file.close()
                        file = open(self.log_path, "r", encoding="utf-8", errors="replace")
                        current_inode = os.stat(self.log_path).st_ino
                except FileNotFoundError:
                    logger.warning("Log file disappeared — waiting for it to return.")
                    time.sleep(2)

        file.close()