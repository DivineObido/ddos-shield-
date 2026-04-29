import math
import time
import threading
import logging
from collections import deque
from typing import Dict, Tuple

logger = logging.getLogger("baseline")

# Helper function to compute mean and stddev from a list of samples.
def _compute_mean_stddev(samples: list) -> Tuple[float, float]:
    n = len(samples)
    if n == 0:
        return 0.0, 0.0
    mean = sum(samples) / n
    if n == 1:
        return mean, 0.0
    variance = sum((x - mean) ** 2 for x in samples) / n
    return mean, math.sqrt(variance)

# The main class that tracks the baseline of normal traffic.
class BaselineTracker:

    def __init__(self,
                 window_minutes: int = 30,
                 recalc_interval: int = 60,
                 min_samples: int = 10,
                 floor_rps: float = 1.0):
        
        self.window_minutes = window_minutes
        self.recalc_interval = recalc_interval
        self.min_samples = min_samples
        self.floor_rps = floor_rps

        self._lock = threading.Lock()
        self._window_seconds = window_minutes * 60

        self._rolling: deque = deque()

        self._error_rolling: deque = deque()
        self._hourly: Dict[int, dict] = {}

        self._current_second: int = int(time.time())
        self._current_count: int = 0
        self._current_errors: int = 0

    
        self.effective_mean: float = floor_rps
        self.effective_std: float = 0.0
        self.error_mean: float = 0.0
        self.error_std: float = 0.0

        self._last_recalc: float = time.time()

        self.history: deque = deque(maxlen=200)
    # This is the main method that gets called for every new request.
    # It updates the current second's count and error count, and if a new
    # second has started, it flushes the old second into the rolling window.
    def record(self, is_error: bool = False):
        now = int(time.time())
        with self._lock:
            if now != self._current_second:
                self._flush_second(
                    self._current_second,
                    self._current_count,
                    self._current_errors
                )
                self._current_second = now
                self._current_count = 0
                self._current_errors = 0

            self._current_count += 1
            if is_error:
                self._current_errors += 1

            # Check if it is time to recalculate the baseline.
            # We do this inside record() so it runs naturally as
            # traffic flows — no separate timer thread needed.
            if now - self._last_recalc >= self.recalc_interval:
                self._recalculate(now)
                self._last_recalc = float(now)
    # Flushes one completed second of traffic into the rolling window.
    # Each entry remembers when it should expire so eviction knows
    def _flush_second(self, ts: int, count: int, errors: int):
    
        expiry = ts + self._window_seconds
        self._rolling.append((expiry, count))
        self._error_rolling.append((expiry, errors))
        self._evict_old_entries(ts)
        
    # Evicts old entries from the rolling window that have expired by now.
    def _evict_old_entries(self, now: int):
        while self._rolling and self._rolling[0][0] <= now:
            self._rolling.popleft()
        while self._error_rolling and self._error_rolling[0][0] <= now:
            self._error_rolling.popleft()
            
    # Recalculates the baseline values based on the current rolling window.
    def _recalculate(self, now: int):
    
        samples = [count for _, count in self._rolling]
        error_samples = [count for _, count in self._error_rolling]

        rolling_mean, rolling_std = _compute_mean_stddev(samples)
        error_mean, error_std = _compute_mean_stddev(error_samples)

        # Update the per-hour slot for right now.
        current_hour = int(time.strftime("%H"))
        if current_hour not in self._hourly:
            self._hourly[current_hour] = {
                "mean": rolling_mean,
                "std": rolling_std,
                "n": 1
            }
        else:
            slot = self._hourly[current_hour]
            n = slot["n"] + 1
            slot["mean"] = (slot["mean"] * slot["n"] + rolling_mean) / n
            slot["std"] = (slot["std"] * slot["n"] + rolling_std) / n
            slot["n"] = n

        hourly_slot = self._hourly.get(current_hour, {})
        if hourly_slot.get("n", 0) >= self.min_samples:
            chosen_mean = hourly_slot["mean"]
            chosen_std = hourly_slot["std"]
            logger.debug("Using hourly baseline for hour %d", current_hour)
        else:
            chosen_mean = rolling_mean
            chosen_std = rolling_std
            logger.debug("Using rolling baseline (%d samples)", len(samples))


        self.effective_mean = max(chosen_mean, self.floor_rps)
        self.effective_std = chosen_std
        self.error_mean = max(error_mean, 0.0)
        self.error_std = error_std

        self.history.append((now, self.effective_mean, self.effective_std))

        logger.info(
            "Baseline recalculated — mean=%.2f std=%.2f samples=%d hour=%d",
            self.effective_mean, self.effective_std, len(samples), current_hour
        )
    # This method returns the current baseline values as a clean dictionary.
    # The detector uses this to check if current traffic is anomalous,
    def get_snapshot(self) -> dict:
    
        with self._lock:
            return {
                "effective_mean": self.effective_mean,
                "effective_std": self.effective_std,
                "error_mean": self.error_mean,
                "error_std": self.error_std,
                "sample_count": len(self._rolling),
                "hourly_slots": dict(self._hourly),
                "history": list(self.history),
            }