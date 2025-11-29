from flask import Flask, request, render_template_string
import sqlite3
import time
from datetime import datetime, timedelta
import joblib
import os
import numpy as np

DB_PATH = "login.db"
MODEL_PATH = "model.joblib"   # will be created later

app = Flask(__name__)

# Hardcoded "database" of users
VALID_USERS = {
    "alice": "password123"
}

# HTML template (very simple)
LOGIN_PAGE = """
<!doctype html>
<title>AI Login Demo</title>
<h2>Login</h2>
<p style="color:red;">{{ message }}</p>
<form method="POST">
  <label>Username:</label><br>
  <input type="text" name="username"><br>
  <label>Password:</label><br>
  <input type="password" name="password"><br>
  {% if challenge %}
    <p>Please answer: {{ challenge_question }}</p>
    <input type="text" name="challenge_answer">
    <input type="hidden" name="challenge_expected" value="{{ challenge_expected }}">
  {% endif %}
  <br><br>
  <button type="submit">Login</button>
</form>
"""

SUCCESS_PAGE = """
<!doctype html>
<title>AI Login Demo</title>
<h2>Welcome, {{ username }}!</h2>
<p>You logged in successfully.</p>
"""

BLOCK_PAGE = """
<!doctype html>
<title>Blocked</title>
<h2>Access temporarily blocked</h2>
<p>Suspicious activity detected from your IP. Try again later.</p>
"""

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def log_attempt(ip, username, success, user_agent):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO login_attempts (timestamp, ip, username, success, user_agent) VALUES (?, ?, ?, ?, ?)",
        (int(time.time()), ip, username, int(success), user_agent),
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
        return row[0]
    return "allow"

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

def load_model():
    if os.path.exists(MODEL_PATH):
        return joblib.load(MODEL_PATH)
    return None

model = load_model()

def compute_features_for_ip(ip, window_minutes=10):
    """
    Aggregate login attempts for this IP in the last `window_minutes` minutes
    and compute the same features we use for training.
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
        # No history: represent as "benign" behaviour
        # (use same number of features as training!)
        return np.array([0, 0, 1.0, 1, window_minutes * 60])

    timestamps = [r["timestamp"] for r in rows]
    usernames = [r["username"] for r in rows]
    successes = [r["success"] for r in rows]

    total_attempts = len(rows)
    failed_attempts = sum(1 for s in successes if s == 0)
    success_rate = (total_attempts - failed_attempts) / total_attempts
    unique_usernames = len(set(usernames))

    # time deltas
    if len(timestamps) > 1:
        deltas = [t2 - t1 for t1, t2 in zip(timestamps, timestamps[1:])]
        min_delta = min(deltas)
        avg_delta = sum(deltas) / len(deltas)
    else:
        # Only one attempt → approximate with window duration
        min_delta = window_minutes * 60
        avg_delta = window_minutes * 60

    # Example feature vector:
    # [total_attempts, failed_attempts, success_rate, unique_usernames, min_delta]
    return np.array([total_attempts, failed_attempts, success_rate, unique_usernames, min_delta])

def predict_decision(ip):
    """
    Use the trained model (if available) to decide allow/challenge/block.
    """
    if model is None:
        # No model yet → allow everyone
        return "allow"

    X = compute_features_for_ip(ip).reshape(1, -1)
    prob_attack = model.predict_proba(X)[0][1]  # probability of class "1" (attack)

    # thresholds can be tuned
    if prob_attack > 0.9:
        return "block"
    elif prob_attack > 0.6:
        return "challenge"
    else:
        return "allow"

@app.route("/login", methods=["GET", "POST"])
def login():
    ip = request.remote_addr or "unknown"
    user_agent = request.headers.get("User-Agent", "unknown")

    # Check if this IP is already in decision table
    decision = get_ip_decision(ip)

    # Recompute decision using AI each time (optional but nice for demo)
    decision = predict_decision(ip)
    set_ip_decision(ip, decision)

    if decision == "block":
        return BLOCK_PAGE, 403

    message = ""
    challenge = False
    challenge_question = ""
    challenge_expected = ""

    if decision == "challenge":
        challenge = True
        # simple fake CAPTCHA: 4 + 7
        challenge_question = "4 + 7 = ?"
        challenge_expected = "11"

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # If challenge is required, validate it
        if challenge:
            answer = request.form.get("challenge_answer", "")
            expected = request.form.get("challenge_expected", "")
            if answer.strip() != expected:
                message = "Failed challenge."
                log_attempt(ip, username, False, user_agent)
                return render_template_string(
                    LOGIN_PAGE,
                    message=message,
                    challenge=challenge,
                    challenge_question=challenge_question,
                    challenge_expected=challenge_expected,
                )

        # Check credentials
        success = False
        if username in VALID_USERS and VALID_USERS[username] == password:
            success = True

        # Log this attempt
        log_attempt(ip, username, success, user_agent)

        if success:
            return render_template_string(SUCCESS_PAGE, username=username)
        else:
            message = "Invalid credentials."

    return render_template_string(
        LOGIN_PAGE,
        message=message,
        challenge=challenge,
        challenge_question=challenge_question,
        challenge_expected=challenge_expected,
    )

if __name__ == "__main__":
    # For demo only – do NOT use debug=True in real production
    app.run(host="0.0.0.0", port=5000, debug=True)
