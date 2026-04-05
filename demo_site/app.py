"""
demo_site/app.py - Intentionally vulnerable demo web application
Used for testing WebSpidey v2 scanner locally.
Run on port 9000: python demo_site/app.py
"""

from flask import Flask, request, redirect, jsonify

app = Flask(__name__)

# ──────────────────────────────────────────
# HOME
# ──────────────────────────────────────────
@app.route("/")
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head><title>WebSpidey Demo App</title></head>
    <body>
    <h2>WebSpidey Demo Application</h2>
    <p>This app intentionally contains vulnerabilities for scanner testing.</p>
    <h3>Test Endpoints</h3>
    <ul>
      <li><a href="/login">Login (SQL Injection + Auth)</a></li>
      <li><a href="/search?q=hello">Search (XSS)</a></li>
      <li><a href="/contact">Contact (CSRF)</a></li>
      <li><a href="/redirect?next=https://example.com">Open Redirect</a></li>
      <li><a href="/fetch?url=http://example.com">Fetch URL (SSRF)</a></li>
      <li><a href="/admin">Admin Panel</a></li>
      <li><a href="/backup">Backup Files</a></li>
      <li><a href="/api/data">API Data (Sensitive Exposure)</a></li>
    </ul>
    </body>
    </html>
    """

# ──────────────────────────────────────────
# SQL INJECTION + AUTH WEAKNESS
# ──────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # Simulate SQL error on injection payload
        if "'" in username or "'" in password or "--" in username:
            return """
            <h3>Database Error</h3>
            <p>You have an error in your SQL syntax near '' OR '1'='1'</p>
            <p>mysql error: syntax error</p>
            """

        # Default creds accepted
        if username == "admin" and password in ("admin", "password", "123456"):
            return "<h3>Welcome to the dashboard! You are logged in.</h3><a href='/logout'>Logout</a>"

        return "<h3>Invalid username or password. Try again.</h3>"

    return """
    <h2>Login</h2>
    <form method="POST">
      <label>Username: <input name="username" type="text" autocomplete="on"></label><br><br>
      <label>Password: <input name="password" type="password" autocomplete="on"></label><br><br>
      <button type="submit">Login</button>
    </form>
    """

# ──────────────────────────────────────────
# XSS
# ──────────────────────────────────────────
@app.route("/search")
def search():
    term = request.args.get("q", "")
    # Deliberately reflects input without escaping
    return f"""
    <h2>Search Page</h2>
    <form>
      <input name="q" value="{term}" placeholder="Search something">
      <button type="submit">Search</button>
    </form>
    <h3>Results for: {term}</h3>
    """

# ──────────────────────────────────────────
# CSRF - POST form with no token
# ──────────────────────────────────────────
@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        message = request.form.get("message", "")
        return f"<p>Message received: {message}</p>"

    return """
    <h2>Contact Us</h2>
    <form method="POST">
      <textarea name="message" placeholder="Your message"></textarea><br>
      <button type="submit">Send</button>
    </form>
    """

# ──────────────────────────────────────────
# OPEN REDIRECT
# ──────────────────────────────────────────
@app.route("/redirect")
def open_redirect():
    target = request.args.get("next", "/")
    # No validation - vulnerable
    return redirect(target)

# ──────────────────────────────────────────
# SSRF
# ──────────────────────────────────────────
@app.route("/fetch")
def fetch_url():
    url = request.args.get("url", "")
    if not url:
        return "<p>Provide ?url=http://...</p>"

    try:
        import requests as req
        res = req.get(url, timeout=3)
        return f"<pre>Fetched ({res.status_code}):\n{res.text[:500]}</pre>"
    except Exception as e:
        return f"<p>Error fetching {url}: {e}</p>"

# ──────────────────────────────────────────
# EXPOSED DIRECTORIES
# ──────────────────────────────────────────
@app.route("/admin")
def admin():
    return "<h2>Admin Dashboard</h2><p>Admin panel accessible without auth.</p>"

@app.route("/backup")
def backup():
    return "<h2>Backup Files</h2><p>db_backup_2024.sql available here.</p>"

@app.route("/dashboard")
def dashboard():
    return "<h2>Dashboard</h2><p>Internal dashboard exposed.</p>"

# ──────────────────────────────────────────
# SENSITIVE DATA EXPOSURE
# ──────────────────────────────────────────
@app.route("/api/data")
def api_data():
    return jsonify({
        "user": "admin",
        "email": "admin@example.com",
        "api_key": "sk-12345SECRETKEY9876",
        "token": "Bearer abcdef123456xyz",
        "database_url": "postgres://admin:password@localhost/prod"
    })

@app.route("/logout")
def logout():
    return "<p>Logged out.</p>"


if __name__ == "__main__":
    app.run(port=9000, debug=True)
