from flask import Flask, request, render_template_string
import os
import requests

app = Flask(__name__)

# URL of your external AI Guard service
AI_GUARD_URL = os.environ.get(
    "AI_GUARD_URL",
    "http://127.0.0.1:5001/api/log_and_decide"
)

# Demo user database
VALID_USERS = {
    "alice": "password123"
}

# ------------------------------------------------------------
# Global CSS (no Python formatting here)
# ------------------------------------------------------------

BASE_STYLE = """
<style>
  :root {
    --bg-gradient: linear-gradient(135deg, #1e293b, #0f172a 60%, #020617);
    --accent: #38bdf8;
    --accent-soft: rgba(56, 189, 248, 0.16);
    --accent-strong: #0ea5e9;
    --danger: #f97373;
    --danger-soft: rgba(248, 113, 113, 0.15);
    --text-main: #e5e7eb;
    --text-muted: #9ca3af;
    --card-bg: rgba(15, 23, 42, 0.9);
    --card-border: rgba(148, 163, 184, 0.35);
    --radius-xl: 18px;
    --shadow-soft: 0 24px 60px rgba(15, 23, 42, 0.9);
    --transition-fast: 0.18s ease-out;
  }

  * {
    box-sizing: border-box;
  }

  body {
    margin: 0;
    min-height: 100vh;
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", sans-serif;
    background:
      radial-gradient(circle at top left, rgba(56, 189, 248, 0.3), transparent 55%),
      radial-gradient(circle at bottom right, rgba(236, 72, 153, 0.25), transparent 55%),
      var(--bg-gradient);
    color: var(--text-main);
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
  }

  .page-shell {
    width: 100%;
    max-width: 420px;
  }

  .card {
    background: var(--card-bg);
    border-radius: var(--radius-xl);
    border: 1px solid var(--card-border);
    padding: 28px 26px 24px;
    box-shadow: var(--shadow-soft);
    backdrop-filter: blur(18px) saturate(140%);
    position: relative;
    overflow: hidden;
    animation: fadeIn 0.35s ease-out;
  }

  .card::before {
    content: "";
    position: absolute;
    inset: 0;
    background: radial-gradient(circle at top, rgba(56, 189, 248, 0.08), transparent 60%);
    pointer-events: none;
  }

  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(6px); }
    to   { opacity: 1; transform: translateY(0); }
  }

  .card-header {
    position: relative;
    margin-bottom: 22px;
  }

  .card-title-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
  }

  .card-title {
    margin: 0;
    font-size: 1.6rem;
    letter-spacing: 0.02em;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .logo-dot {
    height: 11px;
    width: 11px;
    border-radius: 999px;
    background: radial-gradient(circle at 30% 30%, #e0f2fe, #38bdf8);
    box-shadow: 0 0 0 4px rgba(56, 189, 248, 0.3);
  }

  .badge-soft {
    padding: 4px 10px;
    border-radius: 999px;
    border: 1px solid rgba(148, 163, 184, 0.5);
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-muted);
    background: rgba(15, 23, 42, 0.9);
  }

  .badge-soft span {
    color: var(--accent);
  }

  .card-subtitle {
    margin-top: 6px;
    font-size: 0.88rem;
    color: var(--text-muted);
  }

  .alert {
    position: relative;
    margin-bottom: 16px;
    padding: 11px 12px;
    border-radius: 12px;
    font-size: 0.82rem;
    line-height: 1.4;
    display: flex;
    align-items: flex-start;
    gap: 9px;
    border-left: 3px solid;
  }

  .alert-danger {
    background: var(--danger-soft);
    border-left-color: var(--danger);
    color: #fecaca;
  }

  .alert-info {
    background: var(--accent-soft);
    border-left-color: var(--accent-strong);
    color: #e0f2fe;
  }

  .alert-icon {
    font-size: 1.1rem;
    line-height: 1;
    margin-top: 1px;
  }

  .alert-text {
    flex: 1;
  }

  .form-group {
    margin-bottom: 16px;
  }

  .form-label {
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--text-muted);
    margin-bottom: 5px;
  }

  .form-label .req {
    padding: 2px 7px;
    border-radius: 999px;
    border: 1px solid rgba(148, 163, 184, 0.9);
    font-size: 0.68rem;
  }

  .input-wrapper {
    position: relative;
  }

  .input-field {
    width: 100%;
    border-radius: 999px;
    border: 1px solid rgba(148, 163, 184, 0.6);
    background: rgba(15, 23, 42, 0.9);
    padding: 10px 12px;
    padding-left: 36px;
    font-size: 0.9rem;
    color: var(--text-main);
    outline: none;
    transition: border-color var(--transition-fast), box-shadow var(--transition-fast), background var(--transition-fast), transform var(--transition-fast);
  }

  .input-field::placeholder {
    color: rgba(148, 163, 184, 0.8);
  }

  .input-field:focus {
    border-color: var(--accent-strong);
    box-shadow: 0 0 0 1px rgba(56, 189, 248, 0.8), 0 0 26px rgba(56, 189, 248, 0.4);
    background: rgba(15, 23, 42, 0.96);
    transform: translateY(-0.5px);
  }

  .input-icon {
    position: absolute;
    left: 12px;
    top: 50%;
    transform: translateY(-50%);
    font-size: 0.9rem;
    color: rgba(148, 163, 184, 0.95);
  }

  .btn-primary {
    width: 100%;
    border-radius: 999px;
    border: none;
    padding: 10px 14px;
    margin-top: 6px;
    font-size: 0.92rem;
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    cursor: pointer;
    color: #0b1120;
    background: radial-gradient(circle at 20% 0%, #e0f2fe, #38bdf8);
    box-shadow: 0 16px 32px rgba(56, 189, 248, 0.4);
    transition: transform var(--transition-fast), box-shadow var(--transition-fast), filter var(--transition-fast);
  }

  .btn-primary:hover {
    transform: translateY(-1px);
    box-shadow: 0 20px 40px rgba(56, 189, 248, 0.55);
    filter: brightness(1.02);
  }

  .btn-primary:active {
    transform: translateY(0);
    box-shadow: 0 12px 26px rgba(56, 189, 248, 0.45);
    filter: brightness(0.97);
  }

  .status-icon {
    font-size: 2.4rem;
    margin-bottom: 10px;
  }

  .status-success {
    color: #4ade80;
  }

  .status-block {
    color: #fb7185;
  }

  .status-title {
    margin: 0 0 8px;
    font-size: 1.45rem;
  }

  .status-text {
    margin: 0;
    font-size: 0.9rem;
    color: var(--text-muted);
  }
</style>
"""

# ------------------------------------------------------------
# HTML templates with __STYLE__ placeholder
# ------------------------------------------------------------

LOGIN_PAGE = """
<!doctype html>
<html>
<head>
  <title>AI Login</title>
  __STYLE__
</head>
<body>
  <div class="page-shell">
    <div class="card">
      <div class="card-header">
        <div class="card-title-row">
          <h1 class="card-title">
            <span class="logo-dot"></span>
            AI Login Portal
          </h1>
          <div class="badge-soft">
            Protected by <span>AI Guard</span>
          </div>
        </div>
        <p class="card-subtitle">
          Behaviour-aware protection against brute-force and credential stuffing attacks.
        </p>
      </div>

      {% if message %}
      <div class="alert alert-danger">
        <div class="alert-icon">⚠️</div>
        <div class="alert-text">{{ message }}</div>
      </div>
      {% endif %}

      {% if challenge %}
      <div class="alert alert-info">
        <div class="alert-icon">🧠</div>
        <div class="alert-text">
          Suspicious login pattern detected. Please solve the verification challenge.
        </div>
      </div>
      {% endif %}

      <form method="POST">
        <div class="form-group">
          <label class="form-label">
            <span>Username</span>
            <span class="req">required</span>
          </label>
          <div class="input-wrapper">
            <span class="input-icon">👤</span>
            <input
              type="text"
              name="username"
              class="input-field"
              placeholder="you@example.com"
              value="{{ username }}"
              autocomplete="username"
            >
          </div>
        </div>

        <div class="form-group">
          <label class="form-label">
            <span>Password</span>
            <span class="req">required</span>
          </label>
          <div class="input-wrapper">
            <span class="input-icon">🔒</span>
            <input
              type="password"
              name="password"
              class="input-field"
              placeholder="••••••••"
              autocomplete="current-password"
            >
          </div>
        </div>

        {% if challenge %}
        <div class="form-group">
          <label class="form-label">
            <span>Verification</span>
            <span class="req">security</span>
          </label>
          <div class="input-wrapper">
            <span class="input-icon">🤖</span>
            <input
              type="text"
              name="challenge_answer"
              class="input-field"
              placeholder="{{ challenge_question }}"
            >
            <input type="hidden" name="challenge_expected" value="{{ challenge_expected }}">
            <input type="hidden" name="challenge_stage" value="1">
          </div>
        </div>
        {% endif %}

        <button type="submit" class="btn-primary">Continue</button>
      </form>
    </div>
  </div>
</body>
</html>
"""

SUCCESS_PAGE = """
<!doctype html>
<html>
<head>
  <title>Login Successful</title>
  __STYLE__
</head>
<body>
  <div class="page-shell">
    <div class="card" style="text-align:center;">
      <div class="status-icon status-success">✅</div>
      <h2 class="status-title">Welcome, {{ username }}!</h2>
      <p class="status-text">
        You have successfully authenticated. Your session is now protected by AI Guard.
      </p>
    </div>
  </div>
</body>
</html>
"""

BLOCK_PAGE = """
<!doctype html>
<html>
<head>
  <title>Access Blocked</title>
  __STYLE__
</head>
<body>
  <div class="page-shell">
    <div class="card" style="text-align:center;">
      <div class="status-icon status-block">⛔</div>
      <h2 class="status-title">Access temporarily blocked</h2>
      <p class="status-text">
        Our AI detected highly suspicious activity from this IP address.
        Please try again later or contact support if you believe this is a mistake.
      </p>
    </div>
  </div>
</body>
</html>
"""

# ------------------------------------------------------------
# Helper: call external AI Guard
# ------------------------------------------------------------

def call_ai_guard(ip, username, success, user_agent):
    """
    Call the external AI Guard service and get:
      - decision: allow | challenge | block
      - score: anomaly probability (0..1)
    """
    payload = {
        "ip": ip,
        "username": username,
        "success": bool(success),
        "user_agent": user_agent,
    }

    try:
        resp = requests.post(AI_GUARD_URL, json=payload, timeout=1.0)
        resp.raise_for_status()
        data = resp.json()
        decision = data.get("decision", "allow")
        score = float(data.get("score", 0.0))
        print(f"[AI GUARD] ip={ip} user={username} success={success} decision={decision} score={score:.2f}")
        return decision, score
    except Exception as e:
        print(f"[AI GUARD ERROR] {e}")
        # Fail open: allow if AI service is down
        return "allow", 0.0

# ------------------------------------------------------------
# Routes
# ------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    ip = request.remote_addr or "unknown"
    user_agent = request.headers.get("User-Agent", "unknown")

    # --- NEW: Always ask AI Guard BEFORE doing anything ---
    # Use "success=False" for GET requests (neutral / unknown)
    initial_decision, initial_score = call_ai_guard(ip, "", False, user_agent)
    print(f"[WEB] initial_decision={initial_decision} score={initial_score:.2f}")

    # If already blocked -> BLOCK immediately (GET or POST)
    if initial_decision == "block":
        print("[WEB] IP is blocked on GET/POST:", ip)
        return BLOCK_PAGE.replace("__STYLE__", BASE_STYLE), 403

    # ---------------------------------------------
    # Normal login flow ONLY if not blocked
    # ---------------------------------------------
    message = ""
    challenge = False
    challenge_question = ""
    challenge_expected = ""
    username = ""

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        challenge_stage = request.form.get("challenge_stage")
        has_challenge_answer = (challenge_stage == "1")

        if has_challenge_answer:
            answer = request.form.get("challenge_answer", "")
            expected = request.form.get("challenge_expected", "")
            if answer.strip() != expected:
                decision, score = call_ai_guard(ip, username, False, user_agent)

                if decision == "block":
                    return BLOCK_PAGE.replace("__STYLE__", BASE_STYLE), 403

                message = "Failed verification challenge."
                return render_template_string(
                    LOGIN_PAGE.replace("__STYLE__", BASE_STYLE),
                    message=message,
                    challenge=False,
                    username=username,
                )

        # Check credentials
        success = (username in VALID_USERS and VALID_USERS[username] == password)

        # Ask guard again with real login data
        decision, score = call_ai_guard(ip, username, success, user_agent)

        if decision == "block":
            return BLOCK_PAGE.replace("__STYLE__", BASE_STYLE), 403

        if decision == "challenge" and not has_challenge_answer:
            return render_template_string(
                LOGIN_PAGE.replace("__STYLE__", BASE_STYLE),
                message="Additional verification required.",
                challenge=True,
                challenge_question="4 + 7 = ?",
                challenge_expected="11",
                username=username,
            )

        if success:
            return render_template_string(
                SUCCESS_PAGE.replace("__STYLE__", BASE_STYLE),
                username=username,
            )
        else:
            message = "Invalid credentials."

    # Render login form (only for allowed / challenged)
    return render_template_string(
        LOGIN_PAGE.replace("__STYLE__", BASE_STYLE),
        message=message,
        challenge=challenge,
        challenge_question=challenge_question,
        challenge_expected=challenge_expected,
        username=username,
    )


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

if __name__ == "__main__":
    print("[+] Web app running at http://127.0.0.1:5000/login")
    print(f"[+] Using AI Guard at {AI_GUARD_URL}")
    app.run(host="0.0.0.0", port=5000, debug=True)
