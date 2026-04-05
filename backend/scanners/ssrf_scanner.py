"""
ssrf_scanner.py - Detect Server-Side Request Forgery (SSRF) vulnerabilities
Checks URL parameters that might be used server-side to make requests.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin

# Parameter names that commonly accept URLs (SSRF candidates)
SSRF_PARAMS = [
    "url", "uri", "path", "src", "source", "dest", "destination",
    "target", "link", "href", "fetch", "load", "proxy", "redirect",
    "image", "img", "file", "page", "view", "host", "server"
]

# SSRF test payloads - try to make the server request internal resources
SSRF_PAYLOADS = [
    "http://localhost",
    "http://127.0.0.1",
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://0.0.0.0",
]

# Indicators that SSRF might have worked
SSRF_INDICATORS = [
    "ami-id", "instance-id", "meta-data",  # AWS metadata
    "localhost", "127.0.0.1",
    "connection refused", "network error",  # Suggests server tried to connect
]


def scan_ssrf(url_list):
    """
    Returns list of dicts for potential SSRF vulnerabilities.
    """
    findings = []

    for url in url_list:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # Check URL query params
        ssrf_candidates = [p for p in params if p.lower() in SSRF_PARAMS]

        for param in ssrf_candidates:
            for payload in SSRF_PAYLOADS:
                test_params = dict(params)
                test_params[param] = [payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))

                try:
                    res = requests.get(test_url, timeout=5)
                    response_text = res.text.lower()

                    for indicator in SSRF_INDICATORS:
                        if indicator in response_text:
                            findings.append({
                                "url": url,
                                "param": param,
                                "payload": payload,
                                "reason": f"Response contained SSRF indicator: '{indicator}'"
                            })
                            break
                    else:
                        # Heuristic: if parameter looks like a URL field and reflects content
                        # flag as potential SSRF even without confirmation
                        if res.status_code == 200 and param.lower() in SSRF_PARAMS[:5]:
                            findings.append({
                                "url": url,
                                "param": param,
                                "payload": payload,
                                "reason": f"Parameter '{param}' accepts URL values - potential SSRF (unconfirmed)"
                            })
                            break

                except requests.exceptions.ConnectionError:
                    # If internal address was attempted, connection refused is expected
                    if "127.0.0.1" in payload or "localhost" in payload:
                        findings.append({
                            "url": url,
                            "param": param,
                            "payload": payload,
                            "reason": "Server attempted connection to internal address (connection refused from scanner side)"
                        })
                except Exception:
                    continue

            if any(f["url"] == url for f in findings):
                break

        # Also scan forms
        try:
            res = requests.get(url, timeout=8)
            soup = BeautifulSoup(res.text, "html.parser")
            for form in soup.find_all("form"):
                for inp in form.find_all("input"):
                    name = inp.get("name", "").lower()
                    if name in SSRF_PARAMS:
                        action = form.get("action") or url
                        if not action.startswith("http"):
                            action = urljoin(url, action)
                        method = form.get("method", "get").lower()

                        findings.append({
                            "url": url,
                            "param": name,
                            "payload": "N/A (form input)",
                            "reason": f"Form input named '{name}' could be SSRF vector"
                        })
                        break
        except Exception:
            pass

    # Deduplicate
    seen = set()
    unique = []
    for f in findings:
        if f["url"] not in seen:
            seen.add(f["url"])
            unique.append(f)
    return unique
