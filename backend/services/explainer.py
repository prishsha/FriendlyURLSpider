"""
explainer.py - Rule-based Explainable AI for WebSpidey v2
No external APIs. Pure logic based on scan results.
Each finding gets a 'why', 'how_detected', and 'fix'.
"""

# Knowledge base for each vulnerability type
VULN_KNOWLEDGE = {
    "sqli": {
        "name": "SQL Injection",
        "severity": "Critical",
        "why": (
            "SQL Injection happens when user input is directly placed into a database query "
            "without proper sanitization. An attacker can manipulate the query to bypass login, "
            "extract data, or even delete the database."
        ),
        "how_detected": (
            "The scanner submitted payloads like `' OR '1'='1` into form fields and checked "
            "whether the response contained SQL error messages (like 'syntax error' or 'mysql') "
            "or whether the response size changed significantly compared to a normal request."
        ),
        "fix": (
            "1. Use parameterized queries or prepared statements (e.g., cursor.execute('SELECT * FROM users WHERE id = ?', (id,))). "
            "2. Never build queries by concatenating user input. "
            "3. Use an ORM like SQLAlchemy or Hibernate that handles this automatically. "
            "4. Validate and sanitize all inputs on the server side."
        ),
        "reference": "OWASP A03:2021 - Injection"
    },
    "xss": {
        "name": "Cross-Site Scripting (XSS)",
        "severity": "High",
        "why": (
            "XSS lets attackers inject malicious JavaScript into pages viewed by other users. "
            "This can steal session cookies, redirect users to phishing sites, or perform "
            "actions on behalf of the victim."
        ),
        "how_detected": (
            "The scanner injected `<script>alert(1)</script>` and similar HTML/JS payloads into "
            "form inputs and URL parameters. If the payload appeared unescaped in the response "
            "HTML, the page is considered vulnerable to reflected XSS."
        ),
        "fix": (
            "1. Escape all user-supplied output using HTML entity encoding (e.g., &lt; for <). "
            "2. Set a Content-Security-Policy header to restrict script sources. "
            "3. Use templating engines that auto-escape by default (Jinja2 with autoescape=True, React JSX). "
            "4. Never insert raw HTML from user input using innerHTML or dangerouslySetInnerHTML."
        ),
        "reference": "OWASP A03:2021 - Injection"
    },
    "csrf": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "severity": "Medium",
        "why": (
            "CSRF tricks a logged-in user's browser into making unintended requests to your server. "
            "For example, a user visits a malicious page that silently submits a form to transfer "
            "money on a banking site where the user is already authenticated."
        ),
        "how_detected": (
            "The scanner found POST forms that did not contain a hidden CSRF token field. "
            "CSRF tokens are random values the server issues and validates on each form submission "
            "to confirm the request came from your own site."
        ),
        "fix": (
            "1. Add a CSRF token to every state-changing form (e.g., Flask-WTF's {{ form.hidden_tag() }}). "
            "2. Verify the token on the server before processing any POST request. "
            "3. Set the SameSite=Strict or SameSite=Lax attribute on session cookies. "
            "4. Check the Origin/Referer header for AJAX requests."
        ),
        "reference": "OWASP A01:2021 - Broken Access Control"
    },
    "headers": {
        "name": "Security Misconfiguration (Headers)",
        "severity": "Medium",
        "why": (
            "Missing HTTP security headers leave the browser without important protection hints. "
            "For example, without Content-Security-Policy, XSS attacks are harder to mitigate. "
            "Without X-Frame-Options, the site can be embedded in an iframe for clickjacking."
        ),
        "how_detected": (
            "The scanner made an HTTP GET request to the target and checked the response headers "
            "against a list of recommended security headers. Any header not present was flagged."
        ),
        "fix": (
            "Add these headers in your server config or application middleware:\n"
            "- Content-Security-Policy: default-src 'self'\n"
            "- X-Frame-Options: DENY\n"
            "- X-Content-Type-Options: nosniff\n"
            "- Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
            "- Referrer-Policy: no-referrer-when-downgrade\n"
            "In Flask, use the flask-talisman library to add these automatically."
        ),
        "reference": "OWASP A05:2021 - Security Misconfiguration"
    },
    "open_redirect": {
        "name": "Open Redirect",
        "severity": "Medium",
        "why": (
            "Open redirects allow attackers to use your trusted domain as a relay to send users "
            "to malicious sites. Phishing attacks often use open redirects so links look legitimate "
            "(e.g., yourbank.com/redirect?to=evil.com)."
        ),
        "how_detected": (
            "The scanner injected a test external URL (https://evil-example.com) into URL parameters "
            "that looked like redirect targets (e.g., 'next', 'redirect', 'url'). If the server "
            "returned a 3xx redirect to the injected domain, the vulnerability is confirmed."
        ),
        "fix": (
            "1. Validate all redirect destinations against a whitelist of allowed URLs. "
            "2. Use relative paths for internal redirects instead of full URLs. "
            "3. If you must use user-supplied URLs, parse and verify the domain matches your own. "
            "4. Example: if redirect_url.startswith('/') or redirect_url.startswith('https://yourdomain.com')."
        ),
        "reference": "OWASP A01:2021 - Broken Access Control"
    },
    "directories": {
        "name": "Directory/Path Exposure",
        "severity": "High",
        "why": (
            "Sensitive paths being publicly accessible can give attackers direct access to admin panels, "
            "backup files, source code (.git), or configuration files (.env). "
            "A .git directory exposure can leak your entire codebase."
        ),
        "how_detected": (
            "The scanner probed a list of common sensitive paths by making HTTP GET requests. "
            "Any path that returned a 200 OK response was flagged as accessible."
        ),
        "fix": (
            "1. Remove or restrict access to .git, .env, backup/, admin/, config/ on production servers. "
            "2. Add authentication to admin and dashboard endpoints. "
            "3. Configure your web server to deny access to sensitive paths. "
            "4. Nginx example: location ~* /.git { deny all; return 403; }"
        ),
        "reference": "OWASP A05:2021 - Security Misconfiguration"
    },
    "ssrf": {
        "name": "Server-Side Request Forgery (SSRF)",
        "severity": "High",
        "why": (
            "SSRF lets attackers make the server perform requests to internal services that should "
            "not be publicly accessible. On cloud servers, this can expose AWS/GCP instance metadata "
            "including secret credentials at 169.254.169.254."
        ),
        "how_detected": (
            "The scanner identified parameters whose names suggest they accept URLs (like 'url', 'src', "
            "'fetch', 'proxy') and injected internal addresses (localhost, 127.0.0.1, metadata endpoint). "
            "Responses were checked for internal content or connection behavior."
        ),
        "fix": (
            "1. Validate and whitelist allowed domains for any server-side URL fetch. "
            "2. Block internal IP ranges (127.x.x.x, 169.254.x.x, 10.x.x.x, 192.168.x.x). "
            "3. Use a request library wrapper that rejects non-public IPs. "
            "4. If using cloud providers, disable IMDSv1 and require IMDSv2 (AWS)."
        ),
        "reference": "OWASP A10:2021 - Server-Side Request Forgery"
    },
    "auth": {
        "name": "Authentication Weaknesses",
        "severity": "Critical",
        "why": (
            "Weak authentication allows attackers to gain unauthorized access. Default credentials "
            "are the first thing automated tools try. Missing rate limiting allows unlimited password "
            "guessing (brute force attacks)."
        ),
        "how_detected": (
            "The scanner located login forms and attempted common default credential pairs "
            "(admin/admin, admin/password, etc.). It also sent 5 rapid login requests to check "
            "if the server returned HTTP 429 (Too Many Requests)."
        ),
        "fix": (
            "1. Immediately change any default credentials on deployment. "
            "2. Implement rate limiting on login endpoints (e.g., max 5 attempts per minute per IP). "
            "3. Add CAPTCHA after repeated failures. "
            "4. Use account lockout policies. "
            "5. Implement multi-factor authentication for sensitive accounts."
        ),
        "reference": "OWASP A07:2021 - Identification and Authentication Failures"
    }
}


def explain_vulnerability(results):
    """
    For each vulnerability category that has findings,
    return a full explanation dict.
    """
    explanations = {}

    category_map = {
        "sqli": "sqli",
        "xss": "xss",
        "csrf": "csrf",
        "headers": "headers",
        "open_redirect": "open_redirect",
        "directories": "directories",
        "ssrf": "ssrf",
        "auth": "auth",
    }

    for result_key, vuln_key in category_map.items():
        findings = results.get(result_key, [])
        if not findings:
            continue

        info = VULN_KNOWLEDGE.get(vuln_key, {})
        if not info:
            continue

        explanations[result_key] = {
            "name": info["name"],
            "severity": info["severity"],
            "count": len(findings),
            "why": info["why"],
            "how_detected": info["how_detected"],
            "fix": info["fix"],
            "reference": info.get("reference", ""),
        }

    return explanations
