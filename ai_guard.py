from flask import Flask, request, jsonify, render_template_string
import sqlite3
import time
from datetime import datetime
import os
import numpy as np
import pandas as pd
import joblib

DB_PATH = "login.db"
MODEL_PATH = "model.joblib"

# simple demo admin "password" – use env var in real deployment
ADMIN_KEY = os.environ.get("AI_GUARD_ADMIN_KEY", "changeme")

app = Flask(__name__)

# -------- DB helpers --------

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()

    # login attempts table
    c.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER,
            ip TEXT,
            username TEXT,
            success INTEGER,
            user_agent TEXT,
            app TEXT
        )
    """)

    # decisions per IP
    c.execute("""
        CREATE TABLE IF NOT EXISTS ip_decisions (
            ip TEXT PRIMARY KEY,
            decision TEXT,
            last_update INTEGER
        )
    """)

    conn.commit()
    conn.close()

# -------- ML model --------

def load_model():
    if os.path.exists(MODEL_PATH):
        print(f"[+] Loading model from {MODEL_PATH}")
        return joblib.load(MODEL_PATH)
    else:
        print("[!] model.joblib not found, running in 'allow-all' mode")
        return None

model = load_model()

FEATURE_NAMES = ["total_attempts", "failed_attempts", "success_rate", "unique_usernames", "min_delta"]

def log_attempt(ip, username, success, user_agent, app_name=None, ts=None):
    if ts is None:
        ts = int(time.time())
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO login_attempts (timestamp, ip, username, success, user_agent, app) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (ts, ip, username, int(success), user_agent, app_name),
    )
    conn.commit()
    conn.close()

def set_ip_decision(ip, decision):
    conn = get_db_connection()
    c = conn.cursor()
    now_ts = int(time.time())
    c.execute(
        "INSERT INTO ip_decisions (ip, decision, last_update) VALUES (?, ?, ?) "
        "ON CONFLICT(ip) DO UPDATE SET decision=excluded.decision, last_update=excluded.last_update",
        (ip, decision, now_ts),
    )
    conn.commit()
    conn.close()

def get_ip_decision(ip):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT decision FROM ip_decisions WHERE ip = ?", (ip,))
    row = c.fetchone()
    conn.close()
    if row:
        return row["decision"]
    return "allow"

def compute_features_for_ip(ip, window_minutes=10):
    """
    Aggregate login attempts for this IP in the last `window_minutes` minutes
    and compute the same features used during training.
    """
    conn = get_db_connection()
    c = conn.cursor()
    now = int(time.time())
    window_start = now - window_minutes * 60

    c.execute(
        "SELECT timestamp, username, success FROM login_attempts "
        "WHERE ip = ? AND timestamp >= ? ORDER BY timestamp ASC",
        (ip, window_start),
    )
    rows = c.fetchall()
    conn.close()

    if not rows:
        # No history -> represent innocuous behaviour
        return np.array([0, 0, 1.0, 1, window_minutes * 60])

    timestamps = [r["timestamp"] for r in rows]
    usernames = [r["username"] for r in rows]
    successes = [r["success"] for r in rows]

    total_attempts = len(rows)
    failed_attempts = sum(1 for s in successes if s == 0)
    success_rate = (total_attempts - failed_attempts) / total_attempts if total_attempts > 0 else 0.0
    unique_usernames = len(set(usernames))

    if len(timestamps) > 1:
        deltas = [t2 - t1 for t1, t2 in zip(timestamps, timestamps[1:])]
        min_delta = min(deltas)
        # avg_delta = sum(deltas) / len(deltas)  # you can add if needed
    else:
        min_delta = window_minutes * 60

    return np.array([total_attempts, failed_attempts, success_rate, unique_usernames, min_delta])

def predict_decision(ip):
    """
    Use the trained model (if available) to decide allow/challenge/block
    + return score (probability it's an attacker).
    """
    if model is None:
        # no model – allow all
        return "allow", 0.0

    X_raw = compute_features_for_ip(ip)
    X = pd.DataFrame([X_raw], columns=FEATURE_NAMES)
    prob_attack = model.predict_proba(X)[0][1]

    # thresholds – tune for your demo
    if prob_attack > 0.9:
        decision = "block"
    elif prob_attack > 0.6:
        decision = "challenge"
    else:
        decision = "allow"

    return decision, float(prob_attack)

# -------- API for websites --------

@app.route("/api/log_and_decide", methods=["POST"])
def api_log_and_decide():
    """
    Websites call this after each login attempt.
    JSON body:
      {
        "ip": "1.2.3.4",
        "username": "alice",
        "success": true/false,
        "user_agent": "...",
        "app": "my-site-1"   # optional
      }
    """
    data = request.get_json(force=True, silent=True) or {}

    ip = data.get("ip") or request.remote_addr or "unknown"
    username = data.get("username", "")
    success = bool(data.get("success", False))
    user_agent = data.get("user_agent", request.headers.get("User-Agent", "unknown"))
    app_name = data.get("app", "default")

    # 1) log the attempt
    log_attempt(ip, username, success, user_agent, app_name=app_name)

    # 2) get AI-based decision
    decision, score = predict_decision(ip)
    set_ip_decision(ip, decision)

    return jsonify({
        "decision": decision,
        "score": score
    })

# -------- Admin Dashboard --------

ADMIN_TEMPLATE = """
<!doctype html>
<html>
<head>
  <title>AI Login Guard - Admin</title>
  <style>
    body { font-family: sans-serif; margin: 20px; }
    h1 { margin-bottom: 5px; }
    table { border-collapse: collapse; width: 100%%; margin-top: 20px; }
    th, td { border: 1px solid #ccc; padding: 6px 8px; font-size: 13px; }
    th { background: #f0f0f0; }
    .badge { padding: 2px 6px; border-radius: 4px; color: #fff; font-size: 11px; }
    .allow { background: #4caf50; }
    .challenge { background: #ff9800; }
    .block { background: #f44336; }
  </style>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
  <h1>AI Login Guard - Admin Dashboard</h1>
  <p>Key: <code>{{ admin_key }}</code> (query ?key=... to protect access in demos)</p>

  <h2>Per-IP Anomaly Score (live)</h2>
  <canvas id="scoreChart" width="800" height="300"></canvas>

  <h2>Recent Login Attempts</h2>
  <table id="attemptsTable">
    <thead>
      <tr>
        <th>Time</th>
        <th>IP</th>
        <th>Username</th>
        <th>Success</th>
        <th>App</th>
        <th>Decision</th>
      </tr>
    </thead>
    <tbody></tbody>
  </table>

<script>
  const adminKey = "{{ admin_key }}";
  const scoreCtx = document.getElementById('scoreChart').getContext('2d');

  let scoreChart = new Chart(scoreCtx, {
    type: 'bar',
    data: {
      labels: [],
      datasets: [{
        label: 'Attack Probability',
        data: [],
        borderWidth: 1
      }]
    },
    options: {
      scales: {
        y: { beginAtZero: true, max: 1.0 }
      }
    }
  });

  async function fetchAdminData() {
    const res = await fetch('/api/admin/scores?key=' + encodeURIComponent(adminKey));
    if (!res.ok) {
      console.error("Failed to fetch admin data");
      return;
    }
    const data = await res.json();

    // Update chart
    const labels = data.ip_scores.map(item => item.ip);
    const scores = data.ip_scores.map(item => item.score);

    scoreChart.data.labels = labels;
    scoreChart.data.datasets[0].data = scores;
    scoreChart.update();

    // Update table
    const tbody = document.querySelector('#attemptsTable tbody');
    tbody.innerHTML = '';
    data.recent_attempts.forEach(row => {
      const tr = document.createElement('tr');

      const tdTime = document.createElement('td');
      tdTime.textContent = row.time_str;
      tr.appendChild(tdTime);

      const tdIp = document.createElement('td');
      tdIp.textContent = row.ip;
      tr.appendChild(tdIp);

      const tdUser = document.createElement('td');
      tdUser.textContent = row.username;
      tr.appendChild(tdUser);

      const tdSuccess = document.createElement('td');
      tdSuccess.textContent = row.success ? '✔' : '✖';
      tr.appendChild(tdSuccess);

      const tdApp = document.createElement('td');
      tdApp.textContent = row.app;
      tr.appendChild(tdApp);

      const tdDecision = document.createElement('td');
      const span = document.createElement('span');
      span.classList.add('badge', row.decision);
      span.textContent = row.decision;
      tdDecision.appendChild(span);
      tr.appendChild(tdDecision);

      tbody.appendChild(tr);
    });
  }

  // Fetch every 5 seconds
  fetchAdminData();
  setInterval(fetchAdminData, 5000);
</script>

</body>
</html>
"""

@app.route("/admin")
def admin():
    key = request.args.get("key", "")
    if key != ADMIN_KEY:
        return "Forbidden (invalid key)", 403
    return render_template_string(ADMIN_TEMPLATE, admin_key=ADMIN_KEY)

@app.route("/api/admin/scores")
def api_admin_scores():
    key = request.args.get("key", "")
    if key != ADMIN_KEY:
        return jsonify({"error": "forbidden"}), 403

    conn = get_db_connection()
    c = conn.cursor()

    # 1) get recent attempts
    c.execute("""
        SELECT id, timestamp, ip, username, success, app
        FROM login_attempts
        ORDER BY timestamp DESC
        LIMIT 50
    """)
    rows = c.fetchall()

    # 2) build list of IPs seen recently
    ips = sorted({r["ip"] for r in rows})

    ip_scores = []
    for ip in ips:
        decision, score = predict_decision(ip)
        ip_scores.append({
            "ip": ip,
            "decision": decision,
            "score": score
        })

    # 3) attach decision for each row (current decision)
    recent_attempts = []
    for r in rows:
        ip = r["ip"]
        dec = get_ip_decision(ip)
        ts = r["timestamp"]
        time_str = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
        recent_attempts.append({
            "time_str": time_str,
            "ip": ip,
            "username": r["username"],
            "success": bool(r["success"]),
            "app": r["app"],
            "decision": dec
        })

    conn.close()

    return jsonify({
        "ip_scores": ip_scores,
        "recent_attempts": recent_attempts
    })

# -------- main --------

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5001, debug=True)
