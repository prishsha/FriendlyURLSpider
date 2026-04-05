"""
directory_scanner.py - Detect exposed directories and sensitive paths
Probes common admin/backup/config paths.
"""

import requests
from urllib.parse import urljoin

# Common sensitive paths to probe
SENSITIVE_PATHS = [
    ("admin", "High", "Admin panel accessible without authentication"),
    ("admin/login", "High", "Admin login page found"),
    ("login", "Medium", "Login page found - check brute force protection"),
    ("backup", "High", "Backup directory exposed - may contain source code or DB dumps"),
    ("uploads", "Medium", "Uploads directory accessible - check for arbitrary file upload"),
    ("config", "High", "Config directory found - may expose credentials"),
    ("dashboard", "Medium", "Dashboard endpoint accessible"),
    (".git", "Critical", ".git directory exposed - full source code may be downloadable"),
    (".env", "Critical", ".env file exposed - contains secrets and credentials"),
    ("test", "Low", "Test directory found - should not be on production"),
    ("debug", "Medium", "Debug endpoint accessible"),
    ("api/v1", "Low", "API v1 endpoint found"),
    ("api/v2", "Low", "API v2 endpoint found"),
    ("phpinfo.php", "High", "phpinfo() page found - reveals PHP config"),
    ("server-status", "Medium", "Apache server-status page accessible"),
    ("robots.txt", "Low", "robots.txt found - may reveal hidden paths"),
    ("sitemap.xml", "Low", "Sitemap found - reveals site structure"),
]


def scan_directories(base_url):
    """
    Returns list of dicts with found sensitive paths.
    """
    findings = []
    base = base_url.rstrip("/")

    for path, severity, description in SENSITIVE_PATHS:
        url = f"{base}/{path}"
        try:
            res = requests.get(url, timeout=5, allow_redirects=False)

            if res.status_code == 200:
                findings.append({
                    "url": url,
                    "path": path,
                    "status_code": res.status_code,
                    "severity": severity,
                    "description": description
                })
            elif res.status_code in (301, 302):
                # Some sensitive redirects are still worth noting
                if path in (".git", ".env", "config", "backup"):
                    findings.append({
                        "url": url,
                        "path": path,
                        "status_code": res.status_code,
                        "severity": severity,
                        "description": description + " (redirects)"
                    })
        except Exception:
            continue

    return findings
