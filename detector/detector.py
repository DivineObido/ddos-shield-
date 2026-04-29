import time
import threading
import logging
from collections import deque, defaultdict
from typing import Dict, Optional, Callable

from baseline import BaselineTracker
from monitor import LogEntry

logger = logging.getLogger("detector")

class SlidingWindow:

    def __init__(self, window_seconds: int = 60):
       
        self._window = window_seconds
        self._timestamps: deque = deque()
        self._lock = threading.Lock()

    def add(self, ts: float):
        with self._lock:
            self._timestamps.append(ts)
            self._evict(ts)

    def _evict(self, now: float):
        cutoff = now - self._window
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()

    def count(self) -> int:
        now = time.time()
        with self._lock:
            self._evict(now)
            return len(self._timestamps)

    def rate(self) -> float:
        return self.count() / self._window

# The main class that detects anomalies in the traffic.
class AnomalyDetector:
  
    def __init__(self,
                 baseline: BaselineTracker,
                 zscore_threshold: float = 3.0,
                 spike_multiplier: float = 5.0,
                 error_rate_multiplier: float = 3.0,
                 window_seconds: int = 60,
                 on_ip_anomaly: Optional[Callable] = None,
                 on_global_anomaly: Optional[Callable] = None):

        self.baseline = baseline
        self.zscore_threshold = zscore_threshold
        self.spike_multiplier = spike_multiplier
        self.error_rate_multiplier = error_rate_multiplier
        self.window_seconds = window_seconds
        self.on_ip_anomaly = on_ip_anomaly
        self.on_global_anomaly = on_global_anomaly
    
        self._lock = threading.Lock()

        # One sliding window per IP address.
        self._ip_windows: Dict[str, SlidingWindow] = defaultdict(
            lambda: SlidingWindow(window_seconds)
        )

        # One sliding window for all traffic combined.
        self._global_window = SlidingWindow(window_seconds)


        self._ip_error_windows: Dict[str, SlidingWindow] = defaultdict(
            lambda: SlidingWindow(window_seconds)
        )


        self._banned_ips: set = set()

        self._last_global_alert: float = 0.0
        self._global_alert_cooldown: float = 60.0

        self._ip_request_counts: Dict[str, int] = defaultdict(int)
        
    # This is the main method that gets called for every new request.
    def process(self, entry: LogEntry):
        WHITELISTED = {"127.0.0.1", "100.55.26.39"}
        if entry.source_ip in WHITELISTED:
            self.baseline.record(is_error=entry.is_error())
            return
    
        now = time.time()
        ip = entry.source_ip
        is_error = entry.is_error()

        # Feed into the baseline so it keeps learning from this request.
        self.baseline.record(is_error=is_error)

        # Add to both sliding windows.
        self._global_window.add(now)
        with self._lock:
            self._ip_windows[ip].add(now)
            self._ip_request_counts[ip] += 1
            if is_error:
                self._ip_error_windows[ip].add(now)

        # Skip detection for already-banned IPs.
        if ip in self._banned_ips:
            return

        # Run both anomaly checks.
        self._check_ip(ip, now)
        self._check_global(now)
    # This method parses a raw log line from Nginx into a structured LogEntry object.
    def _get_effective_threshold(self, ip: str) -> float:
    
        snapshot = self.baseline.get_snapshot()
        error_mean = snapshot["error_mean"]

        with self._lock:
            error_window = self._ip_error_windows.get(ip)

        if error_window is None:
            return self.zscore_threshold

        ip_error_rate = error_window.rate()

        if error_mean > 0 and ip_error_rate > error_mean * self.error_rate_multiplier:
            logger.debug(
                "Tightened threshold for %s — error rate %.2f vs baseline %.2f",
                ip, ip_error_rate, error_mean
            )
            return 2.0

        return self.zscore_threshold
    
    # This method checks if a single IP address is behaving anomalously.
    def _check_ip(self, ip: str, now: float):
        with self._lock:
            ip_rate = self._ip_windows[ip].rate()

        snapshot = self.baseline.get_snapshot()
        mean = snapshot["effective_mean"]
        std = snapshot["effective_std"]
        threshold = self._get_effective_threshold(ip)

        reason = self._anomaly_reason(ip_rate, mean, std, threshold)
        if reason:
            logger.warning(
                "IP anomaly — %s | rate=%.2f req/s | mean=%.2f | std=%.2f | %s",
                ip, ip_rate, mean, std, reason
            )
            if self.on_ip_anomaly:
                self.on_ip_anomaly(ip, ip_rate, mean, reason)
                
    # This method checks whether the overall traffic from ALL sources combined
    # looks like an attack.
    def _check_global(self, now: float):

        if now - self._last_global_alert < self._global_alert_cooldown:
            return

        global_rate = self._global_window.rate()
        snapshot = self.baseline.get_snapshot()
        mean = snapshot["effective_mean"]
        std = snapshot["effective_std"]

        reason = self._anomaly_reason(
            global_rate, mean, std, self.zscore_threshold
        )
        if reason:
            logger.warning(
                "Global anomaly — rate=%.2f req/s | mean=%.2f | std=%.2f | %s",
                global_rate, mean, std, reason
            )
            self._last_global_alert = now
            if self.on_global_anomaly:
                self.on_global_anomaly(global_rate, mean, reason)
                
    # This is the core decision function. Given a rate and a baseline, it decides if the rate is anomalous and explains why.
    def _anomaly_reason(self, rate: float, mean: float,
                        std: float, threshold: float) -> Optional[str]:
    
        # Test 1 — spike multiplier
        if mean > 0 and rate > mean * self.spike_multiplier:
            return (
                f"spike: rate={rate:.2f} > "
                f"{self.spike_multiplier}x mean={mean:.2f}"
            )

        # Test 2 — z-score (only meaningful when stddev is above zero)
        if std > 0:
            zscore = (rate - mean) / std
            if zscore > threshold:
                return (
                    f"zscore={zscore:.2f} > threshold={threshold:.2f} "
                    f"(rate={rate:.2f} mean={mean:.2f} std={std:.2f})"
                )

        return None
    # If an IP is detected as anomalous, this method is called to mark it as banned.
    def mark_banned(self, ip: str):
        with self._lock:
            self._banned_ips.add(ip)
            
    # This method is called to mark a previously banned IP as unbanned, allowing it to be monitored again.
    def mark_unbanned(self, ip: str):
        with self._lock:
            self._banned_ips.discard(ip)
    
    # This method returns the top N IP addresses by total request count.
    def get_top_ips(self, n: int = 10) -> list:

        with self._lock:
            sorted_ips = sorted(
                self._ip_request_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )
            return sorted_ips[:n]
    
    # This method returns the current global request rate in requests per second.
    def get_global_rate(self) -> float:

        return self._global_window.rate()
    
    