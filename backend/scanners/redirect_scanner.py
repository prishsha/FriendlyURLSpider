"""
redirect_scanner.py - Detect Open Redirect vulnerabilities
Injects external domain into redirect parameters.
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Parameters commonly used for redirects
REDIRECT_PARAMS = ["next", "redirect", "url", "return", "returnUrl", "goto", "dest", "target", "redir"]
TEST_PAYLOAD = "https://evil-example.com"


def scan_open_redirect(url_list):
    findings = []

    for url in url_list:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            continue

        for param in params:
            if param.lower() not in [p.lower() for p in REDIRECT_PARAMS]:
                # Still test all params — dev may use custom param names
                pass

            test_params = dict(params)
            test_params[param] = [TEST_PAYLOAD]
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                res = requests.get(test_url, allow_redirects=False, timeout=5)

                if res.status_code in (301, 302, 303, 307, 308):
                    location = res.headers.get("Location", "")
                    if "evil-example.com" in location or TEST_PAYLOAD in location:
                        findings.append({
                            "url": url,
                            "test_url": test_url,
                            "param": param,
                            "redirect_to": location,
                            "reason": f"Parameter '{param}' redirected to attacker-controlled domain"
                        })
                        break  # One finding per URL is enough

            except Exception:
                continue

    return findings
