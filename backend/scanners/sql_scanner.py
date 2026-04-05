"""
sql_scanner.py - Detect SQL injection vulnerabilities
Checks forms with error-based and response-diff methods.
"""

import requests
from bs4 import BeautifulSoup

SQL_PAYLOADS = ["' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--", "1'"]
SQL_ERROR_KEYWORDS = ["sql", "syntax", "mysql", "ora-", "pg::", "sqlite", "unclosed quotation"]


def scan_sql_injection(url_list):
    """
    Returns list of dicts: {url, form_method, payload, reason}
    """
    findings = []

    for url in url_list:
        try:
            res = requests.get(url, timeout=8)
            soup = BeautifulSoup(res.text, "html.parser")
            forms = soup.find_all("form")

            for form in forms:
                method = form.get("method", "get").lower()
                action = form.get("action") or url
                if not action.startswith("http"):
                    from urllib.parse import urljoin
                    action = urljoin(url, action)

                inputs = form.find_all("input")
                normal_data = {}
                for inp in inputs:
                    name = inp.get("name")
                    if name:
                        normal_data[name] = "testvalue123"

                for payload in SQL_PAYLOADS:
                    injected = {k: payload for k in normal_data}

                    try:
                        if method == "post":
                            normal_res = requests.post(action, data=normal_data, timeout=5)
                            injected_res = requests.post(action, data=injected, timeout=5)
                        else:
                            normal_res = requests.get(action, params=normal_data, timeout=5)
                            injected_res = requests.get(action, params=injected, timeout=5)

                        inj_text = injected_res.text.lower()

                        # Method 1: SQL error keywords in response
                        for keyword in SQL_ERROR_KEYWORDS:
                            if keyword in inj_text:
                                findings.append({
                                    "url": url,
                                    "form_action": action,
                                    "method": method.upper(),
                                    "payload": payload,
                                    "reason": f"SQL error keyword '{keyword}' found in response"
                                })
                                break
                        else:
                            # Method 2: Response length difference
                            diff = abs(len(injected_res.text) - len(normal_res.text))
                            if diff > 100:
                                findings.append({
                                    "url": url,
                                    "form_action": action,
                                    "method": method.upper(),
                                    "payload": payload,
                                    "reason": f"Response length changed by {diff} bytes after injection"
                                })
                    except Exception:
                        continue

                    # Avoid duplicate findings for same URL
                    if any(f["url"] == url for f in findings):
                        break

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
