"""
crawler.py - Web crawler for WebSpidey v2
Stays within the same domain, respects a URL cap.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

MAX_URLS = 15  # keep it reasonable for a demo scanner


def crawl(start_url):
    """Discover URLs on the same domain as start_url."""
    found = []
    to_visit = [start_url]
    visited = set()

    base_domain = urlparse(start_url).netloc

    while to_visit and len(found) < MAX_URLS:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            res = requests.get(url, timeout=8, allow_redirects=True)
            if "text/html" not in res.headers.get("Content-Type", ""):
                continue

            soup = BeautifulSoup(res.text, "html.parser")

            for tag in soup.find_all("a", href=True):
                href = tag["href"]
                if href.startswith(("mailto:", "javascript:", "#", "tel:")):
                    continue

                full_url = urljoin(url, href)
                parsed = urlparse(full_url)

                if parsed.scheme not in ("http", "https"):
                    continue
                if parsed.netloc != base_domain:
                    continue
                if full_url not in found and full_url not in to_visit:
                    found.append(full_url)
                    to_visit.append(full_url)

        except Exception:
            continue

    # Always include start_url
    if start_url not in found:
        found.insert(0, start_url)

    return found[:MAX_URLS]
