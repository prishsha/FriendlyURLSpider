from services.gemini_handler import ask_gemini

"""
Rule-based chatbot for WebSpidey v2
Rule-first → Gemini fallback
"""

GENERAL_KNOWLEDGE = {
    "sql": {
        "keywords": ["sql", "sqli", "sql injection", "database", "query"],
        "answer": "SQL Injection is when user input is unsafely included in database queries. Fix it using parameterized queries."
    },
    "xss": {
        "keywords": ["xss", "cross site scripting", "script injection"],
        "answer": "XSS allows attackers to inject JavaScript into webpages. Fix it by escaping output and using CSP."
    },
    "csrf": {
        "keywords": ["csrf", "request forgery"],
        "answer": "CSRF tricks authenticated users into submitting malicious requests. Fix it using CSRF tokens."
    },
    "ssrf": {
        "keywords": ["ssrf", "server side request forgery"],
        "answer": "SSRF lets attackers force servers to make internal requests. Fix by validating URLs."
    },
    "hello": {
        "keywords": ["hello", "hi", "hey"],
        "answer": "Hi! I'm the WebSpidey assistant. Ask me about vulnerabilities, fixes, or scan summaries."
    }
}


def rule_based_reply(message, results=None):
    msg = message.lower().strip()

    if not msg:
        return None

    # -----------------------------
    # SCAN-SPECIFIC LOGIC FIRST
    # -----------------------------
    if results:
        risk = results.get("risk", {})
        sqli = results.get("sqli", [])
        xss = results.get("xss", [])
        csrf = results.get("csrf", [])

        # Initial summary
        if any(w in msg for w in ["summary", "overview", "scan result"]):
            return (
                f"Scan Summary:\n"
                f"Risk Score: {risk.get('score', 'N/A')}/10 ({risk.get('level', 'N/A')})\n"
                f"SQL Injection: {len(sqli)}\n"
                f"XSS: {len(xss)}\n"
                f"CSRF: {len(csrf)}"
            )

        # Risk score
        if any(w in msg for w in ["score", "risk"]):
            return (
                f"Risk Score: {risk.get('score', 'N/A')}/10 "
                f"({risk.get('level', 'N/A')})"
            )

        # SQL count
        if "sql" in msg and "found" in msg:
            return f"SQL Injection issues: {len(sqli)}"

        # XSS count
        if "xss" in msg and "found" in msg:
            return f"XSS issues: {len(xss)}"

        # CSRF count
        if "csrf" in msg and "found" in msg:
            return f"CSRF issues: {len(csrf)}"

    else:
        if any(w in msg for w in ["scan", "risk", "summary"]):
            return "No scan results available yet. Please run a scan first."

    # -----------------------------
    # GENERAL KNOWLEDGE RULES
    # -----------------------------
    for topic, info in GENERAL_KNOWLEDGE.items():
        if any(keyword in msg for keyword in info["keywords"]):
            return info["answer"]

    # Nothing matched
    return None


def chatbot_reply(message, results=None, user_api_key=None):
    """
    Flow:
    1. Rule-based engine first
    2. If no match → Gemini fallback
    """

    # Step 1: Rule-based attempt
    rule_response = rule_based_reply(message, results)

    if rule_response:
        return rule_response

    # Step 2: Gemini fallback
    gemini_response = ask_gemini(message, user_api_key)

    if isinstance(gemini_response, dict):
        return gemini_response["message"]

    return gemini_response