"""
xss_scanner.py - Detect Cross-Site Scripting (XSS) vulnerabilities
Tests form inputs and URL query params.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    '"><script>alert(1)</script>',
]


def scan_xss(url_list):
    findings = []

    for url in url_list:
        try:
            res = requests.get(url, timeout=8)
            soup = BeautifulSoup(res.text, "html.parser")

            # --- Form-based XSS ---
            for form in soup.find_all("form"):
                method = form.get("method", "get").lower()
                action = form.get("action") or url
                if not action.startswith("http"):
                    action = urljoin(url, action)

                inputs = form.find_all("input")

                for payload in XSS_PAYLOADS:
                    data = {}
                    for inp in inputs:
                        name = inp.get("name")
                        if name:
                            data[name] = payload

                    try:
                        if method == "post":
                            r = requests.post(action, data=data, timeout=5)
                        else:
                            r = requests.get(action, params=data, timeout=5)

                        if payload in r.text:
                            findings.append({
                                "url": url,
                                "type": "Form-based XSS",
                                "payload": payload,
                                "reason": "Payload reflected unescaped in response body"
                            })
                            break
                    except Exception:
                        continue

            # --- URL param XSS ---
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if params:
                for payload in XSS_PAYLOADS:
                    test_params = {k: payload for k in params}
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                    try:
                        r = requests.get(test_url, timeout=5)
                        if payload in r.text:
                            findings.append({
                                "url": url,
                                "type": "URL Parameter XSS",
                                "payload": payload,
                                "reason": "Payload reflected in response via URL query parameter"
                            })
                            break
                    except Exception:
                        continue

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
