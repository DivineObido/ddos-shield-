import time
import psutil
import logging
import os
import threading
from flask import Flask, render_template, jsonify
from flask_cors import CORS
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from detector import AnomalyDetector
    from blocker import Blocker
    from baseline import BaselineTracker

logger = logging.getLogger("dashboard")


class Dashboard:

    def __init__(self,
                 detector: "AnomalyDetector",
                 blocker: "Blocker",
                 baseline: "BaselineTracker",
                 port: int = 8080,
                 top_ips_count: int = 10):
        self.detector = detector
        self.blocker = blocker
        self.baseline = baseline
        self.port = port
        self.top_ips_count = top_ips_count
        self._start_time = time.time()

        self._app = Flask(
            __name__,
            template_folder=os.path.join(os.path.dirname(__file__), "templates"),
            static_folder=os.path.join(os.path.dirname(__file__), "static")
        )
        CORS(self._app)
        self._register_routes()
    # This internal method registers the routes for the Flask web server,
    # including the main dashboard page and an API endpoint for fetching metrics.
    def _register_routes(self):
        app = self._app

        @app.route("/")
        def index():
            # Flask looks for index.html inside the templates/ folder automatically.
            return render_template("index.html")

        @app.route("/api/metrics")
        def metrics():
            snapshot = self.baseline.get_snapshot()
            banned_ips = self.blocker.get_banned_ips()
            top_ips = self.detector.get_top_ips(self.top_ips_count)
            global_rate = self.detector.get_global_rate()

            return jsonify({
                "global_rate": global_rate,
                "baseline": {
                    "effective_mean": snapshot["effective_mean"],
                    "effective_std": snapshot["effective_std"],
                    "sample_count": snapshot["sample_count"],
                },
                "banned_ips": banned_ips,
                "top_ips": top_ips,
                "cpu_percent": psutil.cpu_percent(interval=None),
                "memory_percent": psutil.virtual_memory().percent,
                "uptime_seconds": time.time() - self._start_time,
            })
    # This method starts the Flask web server in a background thread, allowing the dashboard
    # to run concurrently with the main application.
    def start(self):
        
        thread = threading.Thread(
            target=lambda: self._app.run(
                host="0.0.0.0",
                port=self.port,
                debug=False,
                use_reloader=False
            ),
            name="dashboard",
            daemon=True
        )
        thread.start()
        logger.info("Dashboard running on port %d", self.port)
        