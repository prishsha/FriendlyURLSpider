"""
csrf_scanner.py - Detect CSRF (Cross-Site Request Forgery) vulnerabilities
Checks POST forms for missing CSRF tokens.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Common CSRF token field names
CSRF_TOKEN_NAMES = [
    "csrf_token", "csrftoken", "_token", "csrf", "authenticity_token",
    "nonce", "xsrf_token", "_csrf", "csrfmiddlewaretoken"
]

# Common CSRF token header names
CSRF_HEADERS = ["X-CSRF-Token", "X-CSRFToken", "X-Requested-With"]


def scan_csrf(url_list):
    """
    Returns a list of dicts for forms that lack CSRF protection.
    """
    findings = []

    for url in url_list:
        try:
            res = requests.get(url, timeout=8)
            soup = BeautifulSoup(res.text, "html.parser")

            for form in soup.find_all("form"):
                method = form.get("method", "get").lower()
                action = form.get("action") or url

                # CSRF mainly relevant for state-changing methods
                if method != "post":
                    continue

                if not action.startswith("http"):
                    action = urljoin(url, action)

                # Check for CSRF token in form inputs
                input_names = [
                    inp.get("name", "").lower()
                    for inp in form.find_all("input")
                ]
                hidden_names = [
                    inp.get("name", "").lower()
                    for inp in form.find_all("input", type="hidden")
                ]

                has_csrf = any(
                    tok in name
                    for name in (input_names + hidden_names)
                    for tok in CSRF_TOKEN_NAMES
                )

                if not has_csrf:
                    findings.append({
                        "url": url,
                        "form_action": action,
                        "method": "POST",
                        "reason": "POST form found with no CSRF token field detected in inputs"
                    })

        except Exception:
            continue

    # Deduplicate by URL
    seen = set()
    unique = []
    for f in findings:
        if f["url"] not in seen:
            seen.add(f["url"])
            unique.append(f)
    return unique
