"""
chatbot.py - Rule-based chatbot for WebSpidey v2
Answers questions about scan results, vulnerabilities, and fixes.
No external APIs. Pure keyword matching + rule logic.
"""

# Predefined knowledge for common questions (not scan-specific)
GENERAL_KNOWLEDGE = {
    "sql": {
        "keywords": ["sql", "sqli", "sql injection", "database", "query"],
        "answer": (
            "SQL Injection is when user input is unsafely included in a database query. "
            "An attacker can use payloads like `' OR '1'='1` to bypass login or extract data. "
            "Fix it by using parameterized queries or an ORM. Never concatenate user input into SQL strings."
        )
    },
    "xss": {
        "keywords": ["xss", "cross site scripting", "cross-site scripting", "script injection", "javascript injection"],
        "answer": (
            "XSS (Cross-Site Scripting) lets attackers inject JavaScript into pages other users visit. "
            "This can steal session cookies or redirect users to phishing sites. "
            "Fix: escape output, use Content-Security-Policy, and avoid innerHTML with user data."
        )
    },
    "csrf": {
        "keywords": ["csrf", "cross site request forgery", "request forgery", "token"],
        "answer": (
            "CSRF tricks your browser into submitting requests to a site where you're logged in. "
            "The attack works because browsers automatically include cookies. "
            "Fix: use CSRF tokens in forms and set SameSite=Strict on cookies."
        )
    },
    "ssrf": {
        "keywords": ["ssrf", "server side request forgery", "internal request", "metadata"],
        "answer": (
            "SSRF lets an attacker make the server send requests to internal services. "
            "On cloud platforms this can expose secret credentials via the metadata endpoint. "
            "Fix: validate and whitelist allowed URLs, block internal IP ranges."
        )
    },
    "headers": {
        "keywords": ["header", "headers", "csp", "content security policy", "x-frame", "hsts", "strict transport"],
        "answer": (
            "Security headers instruct the browser how to handle your site's content. "
            "Missing headers like CSP make XSS easier. Missing HSTS allows downgrade attacks. "
            "Fix: add Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, and X-Content-Type-Options."
        )
    },
    "redirect": {
        "keywords": ["redirect", "open redirect", "phishing", "redirect attack"],
        "answer": (
            "Open redirect means an attacker can use your domain to redirect users to a malicious site. "
            "For example: yoursite.com/redirect?to=evil.com - the link looks safe but leads elsewhere. "
            "Fix: only allow redirects to whitelisted paths or your own domain."
        )
    },
    "directory": {
        "keywords": ["directory", "path", "admin", "backup", "git", "env", "exposed path", "traversal"],
        "answer": (
            "Exposed directories like /admin, /.git, or /.env give attackers direct access to sensitive areas. "
            "A leaked .git folder exposes your entire codebase. A .env file may contain database passwords. "
            "Fix: restrict access in your server config and never deploy .git or .env to production."
        )
    },
    "auth": {
        "keywords": ["auth", "login", "password", "credentials", "brute force", "rate limit", "default password"],
        "answer": (
            "Authentication weaknesses include default credentials, no rate limiting, and no lockout policy. "
            "Attackers use automated tools to guess passwords. "
            "Fix: change defaults, add rate limiting (HTTP 429), lock accounts after failed attempts, and use MFA."
        )
    },
    "owasp": {
        "keywords": ["owasp", "owasp top 10", "owasp risk"],
        "answer": (
            "OWASP Top 10 is a standard list of the most critical web security risks. "
            "This scanner covers several of them: Injection (SQL/XSS), Broken Auth, CSRF, SSRF, and Security Misconfiguration. "
            "See owasp.org for the full list and detailed guidelines."
        )
    },
    "fix": {
        "keywords": ["fix", "remediation", "how to fix", "patch", "solve", "repair"],
        "answer": (
            "For specific fix suggestions, ask about a vulnerability type: "
            "'how to fix SQL injection', 'fix XSS', 'fix CSRF', etc. "
            "Or ask 'show recommendations' to see the suggestions from the last scan."
        )
    },
    "hello": {
        "keywords": ["hello", "hi", "hey", "start", "help", "what can you do"],
        "answer": (
            "Hi! I'm the WebSpidey assistant. I can answer questions about:\n"
            "- Scan results (ask 'show risk score', 'how many XSS issues')\n"
            "- Vulnerability explanations (ask 'what is SQL injection')\n"
            "- Fix suggestions (ask 'how to fix XSS')\n"
            "- General security concepts (ask 'what is OWASP')"
        )
    }
}


def chatbot_reply(message, results=None):
    """
    Generate a rule-based response. Checks scan results first if available,
    then falls back to general knowledge.
    """
    msg = message.lower().strip()

    if not msg:
        return "Please type a question. Try 'what is XSS' or 'show risk score'."

    # --- Scan-result-specific queries ---
    if results:
        risk = results.get("risk", {})
        sqli = results.get("sqli", [])
        xss = results.get("xss", [])
        csrf = results.get("csrf", [])
        headers = results.get("headers", [])
        dirs = results.get("directories", [])
        ssrf = results.get("ssrf", [])
        auth = results.get("auth", [])
        redirect = results.get("open_redirect", [])

        if any(w in msg for w in ["score", "risk", "level", "rating", "overall"]):
            score = risk.get("score", "N/A")
            level = risk.get("level", "N/A")
            return (
                f"The scan gave a risk score of {score}/10, rated as '{level}'.\n"
                f"SQL Injection: {len(sqli)}, XSS: {len(xss)}, CSRF: {len(csrf)}, "
                f"Header Issues: {len(headers)}, Exposed Paths: {len(dirs)}, "
                f"SSRF: {len(ssrf)}, Auth Issues: {len(auth)}, Open Redirects: {len(redirect)}."
            )

        if "sql" in msg and any(w in msg for w in ["found", "count", "many", "how", "result"]):
            if sqli:
                urls = ", ".join(f["url"] for f in sqli[:3])
                return f"SQL Injection was found on {len(sqli)} URL(s): {urls}. Use parameterized queries to fix."
            return "No SQL Injection vulnerabilities were detected in this scan."

        if "xss" in msg and any(w in msg for w in ["found", "count", "many", "how", "result"]):
            if xss:
                return f"XSS was found on {len(xss)} URL(s). Escape output and set a Content-Security-Policy header."
            return "No XSS vulnerabilities were detected in this scan."

        if "csrf" in msg and any(w in msg for w in ["found", "count", "result"]):
            if csrf:
                return f"CSRF issues found on {len(csrf)} form(s). Add CSRF tokens to all POST forms."
            return "No CSRF issues detected."

        if "header" in msg and any(w in msg for w in ["missing", "found", "which", "list"]):
            if headers:
                names = [h.get("header", "") for h in headers[:5]]
                return f"Missing/insecure headers: {', '.join(names)}. Add them in your server or middleware config."
            return "All common security headers are present."

        if any(w in msg for w in ["directory", "path", "admin", "exposed", "backup"]) and any(w in msg for w in ["found", "list", "which"]):
            if dirs:
                paths = [d["url"] for d in dirs[:4]]
                return f"Found {len(dirs)} exposed path(s): {', '.join(paths)}. Restrict access in your server config."
            return "No exposed sensitive directories found."

        if "ssrf" in msg:
            if ssrf:
                return f"Potential SSRF found on {len(ssrf)} URL(s). Validate and restrict server-side URL fetching."
            return "No SSRF vulnerabilities detected."

        if any(w in msg for w in ["auth", "login", "credential", "password", "brute"]):
            if auth:
                return f"Auth issues found: {len(auth)} problem(s). Issues include: {auth[0].get('issue', '')}."
            return "No obvious authentication weaknesses were detected."

        if any(w in msg for w in ["summary", "overview", "all", "everything"]):
            total = len(sqli) + len(xss) + len(csrf) + len(dirs) + len(ssrf) + len(auth) + len(redirect)
            return (
                f"Scan summary: {total} total findings. "
                f"SQL Injection: {len(sqli)}, XSS: {len(xss)}, CSRF: {len(csrf)}, "
                f"Open Redirect: {len(redirect)}, Directory Exposure: {len(dirs)}, "
                f"SSRF: {len(ssrf)}, Auth Issues: {len(auth)}, Header Issues: {len(headers)}. "
                f"Overall Risk: {risk.get('level', 'N/A')} ({risk.get('score', 'N/A')}/10)."
            )

    else:
        # No scan results available
        if any(w in msg for w in ["score", "risk", "result", "scan", "found", "summary", "how many"]):
            return "No scan results available yet. Run a scan first by entering a URL above."

    # --- General knowledge fallback ---
    for topic, info in GENERAL_KNOWLEDGE.items():
        if any(kw in msg for kw in info["keywords"]):
            return info["answer"]

    # --- Fallback default ---
    return (
        "I'm not sure about that. Try asking:\n"
        "- 'what is XSS' or 'what is SQL injection'\n"
        "- 'show risk score' or 'how many issues were found'\n"
        "- 'how to fix CSRF' or 'what is OWASP'\n"
        "- 'show summary' for a full scan overview"
    )
