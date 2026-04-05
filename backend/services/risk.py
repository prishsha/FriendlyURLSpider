"""
risk.py - OWASP-style risk scoring for WebSpidey v2
Weights each vulnerability category by severity.
"""


SEVERITY_WEIGHTS = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Info": 0,
}


def classify_risk(results):
    """
    Calculate an overall risk score (1-10) and level from scan results.
    Returns dict with score, level, and per-category breakdown.
    """
    score = 1
    breakdown = {}

    # SQL Injection - High impact
    sqli_count = len(results.get("sqli", []))
    score += min(sqli_count * 3, 8)
    breakdown["sql_injection"] = sqli_count

    # XSS - High impact
    xss_count = len(results.get("xss", []))
    score += min(xss_count * 3, 8)
    breakdown["xss"] = xss_count

    # CSRF - Medium impact
    csrf_count = len(results.get("csrf", []))
    score += min(csrf_count * 2, 4)
    breakdown["csrf"] = csrf_count

    # Headers - lower impact but adds up
    header_issues = results.get("headers", [])
    high_headers = sum(1 for h in header_issues if h.get("severity") == "High")
    med_headers = sum(1 for h in header_issues if h.get("severity") == "Medium")
    score += min(high_headers * 2 + med_headers * 1, 4)
    breakdown["header_issues"] = len(header_issues)

    # Open Redirect - Medium
    redirect_count = len(results.get("open_redirect", []))
    score += min(redirect_count * 2, 4)
    breakdown["open_redirect"] = redirect_count

    # Directories - varies
    dirs = results.get("directories", [])
    critical_dirs = sum(1 for d in dirs if d.get("severity") == "Critical")
    high_dirs = sum(1 for d in dirs if d.get("severity") == "High")
    score += min(critical_dirs * 3 + high_dirs * 2, 5)
    breakdown["exposed_paths"] = len(dirs)

    # SSRF - High
    ssrf_count = len(results.get("ssrf", []))
    score += min(ssrf_count * 2, 4)
    breakdown["ssrf"] = ssrf_count

    # Auth weaknesses
    auth_issues = results.get("auth", [])
    critical_auth = sum(1 for a in auth_issues if a.get("severity") == "Critical")
    score += min(critical_auth * 4, 6)
    breakdown["auth_issues"] = len(auth_issues)

    # Normalize
    score = min(10, max(1, score))

    if score <= 3:
        level = "Low"
        color = "green"
    elif score <= 5:
        level = "Medium"
        color = "yellow"
    elif score <= 7:
        level = "High"
        color = "orange"
    else:
        level = "Critical"
        color = "red"

    return {
        "score": score,
        "level": level,
        "color": color,
        "breakdown": breakdown
    }
