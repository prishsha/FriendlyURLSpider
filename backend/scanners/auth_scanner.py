"""
auth_scanner.py - Detect Authentication and Authorization Weaknesses
Checks for weak login forms, missing rate limiting indicators, default creds, etc.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Common default credentials to test
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("root", "root"),
    ("test", "test"),
]

# Success indicators in response (after login)
AUTH_SUCCESS_INDICATORS = [
    "dashboard", "welcome", "logout", "signed in", "profile",
    "account", "home", "you are logged in"
]

# Failure indicators
AUTH_FAILURE_INDICATORS = [
    "invalid", "incorrect", "wrong", "failed", "error",
    "try again", "not found", "unauthorized"
]


def scan_auth_weaknesses(url_list):
    """
    Returns list of auth-related issues found.
    """
    findings = []

    for url in url_list:
        try:
            res = requests.get(url, timeout=8)
            soup = BeautifulSoup(res.text, "html.parser")

            for form in soup.find_all("form"):
                method = form.get("method", "get").lower()
                action = form.get("action") or url
                if not action.startswith("http"):
                    action = urljoin(url, action)

                inputs = form.find_all("input")
                input_types = [inp.get("type", "text").lower() for inp in inputs]
                input_names = [inp.get("name", "").lower() for inp in inputs]

                # Is this a login form?
                is_login = (
                    "password" in input_types or
                    any(n in input_names for n in ["password", "pass", "pwd"])
                )

                if not is_login:
                    continue

                # Check for autocomplete="off" on password field
                for inp in inputs:
                    if inp.get("type", "").lower() == "password":
                        if inp.get("autocomplete", "").lower() != "off":
                            findings.append({
                                "url": url,
                                "issue": "Password field missing autocomplete='off'",
                                "severity": "Low",
                                "reason": "Browser may auto-fill credentials on shared devices"
                            })

                # Try default credentials
                for username, password in DEFAULT_CREDS:
                    data = {}
                    for inp in inputs:
                        name = inp.get("name")
                        inp_type = inp.get("type", "text").lower()
                        if not name:
                            continue
                        if inp_type == "password":
                            data[name] = password
                        elif inp_type in ("text", "email"):
                            data[name] = username
                        else:
                            data[name] = inp.get("value", "")

                    try:
                        if method == "post":
                            r = requests.post(action, data=data, timeout=5, allow_redirects=True)
                        else:
                            r = requests.get(action, params=data, timeout=5)

                        text = r.text.lower()

                        has_success = any(s in text for s in AUTH_SUCCESS_INDICATORS)
                        has_failure = any(f in text for f in AUTH_FAILURE_INDICATORS)

                        if has_success and not has_failure:
                            findings.append({
                                "url": url,
                                "issue": f"Default credentials accepted: {username}/{password}",
                                "severity": "Critical",
                                "reason": f"Login with '{username}'/'{password}' appears to have succeeded"
                            })
                            break

                    except Exception:
                        continue

                # Check for no rate limiting (basic: send 5 requests quickly)
                fail_count = 0
                rate_check_data = {inp.get("name"): "wrong_val" for inp in inputs if inp.get("name")}
                for _ in range(5):
                    try:
                        if method == "post":
                            r = requests.post(action, data=rate_check_data, timeout=3)
                        else:
                            r = requests.get(action, params=rate_check_data, timeout=3)
                        if r.status_code == 429:
                            break  # Rate limiting found - good!
                    except Exception:
                        break
                else:
                    findings.append({
                        "url": url,
                        "issue": "No rate limiting detected on login form",
                        "severity": "Medium",
                        "reason": "Server did not return 429 after 5 rapid login attempts - brute force may be possible"
                    })

        except Exception:
            continue

    # Deduplicate by URL+issue
    seen = set()
    unique = []
    for f in findings:
        key = f["url"] + f["issue"]
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
