/*
 * dashboard.js — Fetches live metrics from the API every 3 seconds
 * and updates the dashboard page without a full reload.
 *
 * Every refresh cycle it hits /api/metrics, gets back a JSON object,
 * and updates each part of the page with the fresh numbers.
 */

const REFRESH_MS = 3000;

function fmtTime(ts) {
    if (!ts) return "—";
    return new Date(ts * 1000).toUTCString();
}

function fmtUptime(seconds) {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    return `${h}h ${m}m ${s}s`;
}

function colorClass(value, warnThreshold, dangerThreshold) {
    if (value >= dangerThreshold) return "danger";
    if (value >= warnThreshold)   return "warn";
    return "ok";
}

async function refresh() {
    try {
        const res = await fetch("/api/metrics");
        const d = await res.json();

        // Global request rate
        document.getElementById("global-rate").textContent =
            d.global_rate.toFixed(2) + " r/s";

        // Baseline numbers
        document.getElementById("baseline-mean").textContent =
            d.baseline.effective_mean.toFixed(2) + " r/s";
        document.getElementById("baseline-std").textContent =
            d.baseline.effective_std.toFixed(2);

        // Banned IP count
        const bannedCount = d.banned_ips.length;
        const bannedEl = document.getElementById("banned-count");
        bannedEl.textContent = bannedCount;
        bannedEl.className = "value " + (bannedCount > 0 ? "danger" : "ok");

        // CPU usage
        const cpuEl = document.getElementById("cpu");
        cpuEl.textContent = d.cpu_percent.toFixed(1) + "%";
        cpuEl.className = "value " + colorClass(d.cpu_percent, 50, 80);

        // Memory usage
        const memEl = document.getElementById("memory");
        memEl.textContent = d.memory_percent.toFixed(1) + "%";
        memEl.className = "value " + colorClass(d.memory_percent, 50, 80);

        // Uptime
        document.getElementById("uptime").textContent =
            "Uptime: " + fmtUptime(d.uptime_seconds);

        // Banned IPs table
        const bannedBody = document.getElementById("banned-table");
        if (d.banned_ips.length === 0) {
            bannedBody.innerHTML =
                '<tr><td colspan="5" style="color:#37474f">No active bans.</td></tr>';
        } else {
            bannedBody.innerHTML = d.banned_ips.map(b => `
                <tr>
                    <td>${b.ip}</td>
                    <td>${b.offense_count}</td>
                    <td>
                        <span class="badge ${b.permanent ? "perm" : "banned"}">
                            ${b.permanent ? "PERMANENT" : "BANNED"}
                        </span>
                    </td>
                    <td>${b.permanent ? "—" : fmtTime(b.expires_at)}</td>
                    <td style="color:#607d8b;font-size:0.75rem">${b.reason}</td>
                </tr>
            `).join("");
        }

        // Top IPs table
        const bannedSet = new Set(d.banned_ips.map(b => b.ip));
        const topBody = document.getElementById("top-ips-table");
        if (d.top_ips.length === 0) {
            topBody.innerHTML =
                '<tr><td colspan="3" style="color:#37474f">No traffic yet.</td></tr>';
        } else {
            topBody.innerHTML = d.top_ips.map(([ip, count]) => `
                <tr>
                    <td>${ip}</td>
                    <td>${count}</td>
                    <td>
                        <span class="badge ${bannedSet.has(ip) ? "banned" : "active"}">
                            ${bannedSet.has(ip) ? "BANNED" : "ACTIVE"}
                        </span>
                    </td>
                </tr>
            `).join("");
        }

        document.getElementById("last-updated").textContent =
            new Date().toUTCString();

    } catch (e) {
        console.error("Failed to fetch metrics:", e);
    }
}

// Run immediately then repeat every 3 seconds
refresh();
setInterval(refresh, REFRESH_MS);