"""
header_scanner.py - Check HTTP security response headers
Also checks for insecure cookies.
"""

import requests

REQUIRED_HEADERS = {
    "Content-Security-Policy": {
        "severity": "High",
        "description": "Prevents XSS and data injection attacks by defining allowed content sources."
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "description": "Prevents clickjacking by controlling whether the page can be embedded in iframes."
    },
    "X-Content-Type-Options": {
        "severity": "Medium",
        "description": "Stops browsers from MIME-sniffing the content type, preventing certain attacks."
    },
    "Strict-Transport-Security": {
        "severity": "High",
        "description": "Forces HTTPS connections. Protects against protocol downgrade attacks."
    },
    "Referrer-Policy": {
        "severity": "Low",
        "description": "Controls how much referrer information is sent with requests."
    },
    "Permissions-Policy": {
        "severity": "Low",
        "description": "Limits access to browser features like camera, geolocation, microphone."
    },
}


def scan_headers(url):
    """
    Returns list of dicts describing missing or misconfigured headers.
    Also checks for insecure cookies.
    """
    findings = []

    try:
        res = requests.get(url, timeout=8)
        headers = res.headers

        # Check missing security headers
        for header, info in REQUIRED_HEADERS.items():
            if header not in headers:
                findings.append({
                    "type": "Missing Header",
                    "header": header,
                    "severity": info["severity"],
                    "description": info["description"]
                })

        # Check cookie security flags
        set_cookie = headers.get("Set-Cookie", "")
        if set_cookie:
            if "HttpOnly" not in set_cookie:
                findings.append({
                    "type": "Insecure Cookie",
                    "header": "Set-Cookie (missing HttpOnly)",
                    "severity": "Medium",
                    "description": "Cookies without HttpOnly can be accessed by JavaScript, enabling session theft."
                })
            if "Secure" not in set_cookie:
                findings.append({
                    "type": "Insecure Cookie",
                    "header": "Set-Cookie (missing Secure flag)",
                    "severity": "Medium",
                    "description": "Cookies without Secure flag can be transmitted over unencrypted HTTP."
                })
            if "SameSite" not in set_cookie:
                findings.append({
                    "type": "Insecure Cookie",
                    "header": "Set-Cookie (missing SameSite)",
                    "severity": "Low",
                    "description": "Cookies without SameSite attribute may be sent in cross-site requests (CSRF risk)."
                })

        # Server header disclosure
        server = headers.get("Server", "")
        if server:
            findings.append({
                "type": "Information Disclosure",
                "header": f"Server: {server}",
                "severity": "Low",
                "description": "Server header reveals software version, which helps attackers target known exploits."
            })

        # X-Powered-By disclosure
        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            findings.append({
                "type": "Information Disclosure",
                "header": f"X-Powered-By: {powered_by}",
                "severity": "Low",
                "description": "X-Powered-By reveals the server-side technology stack."
            })

    except Exception as e:
        findings.append({
            "type": "Scan Error",
            "header": "Connection failed",
            "severity": "Info",
            "description": str(e)
        })

    return findings
