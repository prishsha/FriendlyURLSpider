"""
pdf_generator.py - Generate vulnerability scan reports as PDF
Uses ReportLab. Returns raw PDF bytes.
"""

from io import BytesIO
from datetime import datetime
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch

SEVERITY_COLORS = {
    "Critical": colors.HexColor("#dc2626"),
    "High": colors.HexColor("#ea580c"),
    "Medium": colors.HexColor("#d97706"),
    "Low": colors.HexColor("#16a34a"),
    "Info": colors.HexColor("#6b7280"),
}

RISK_COLORS = {
    "Critical": colors.HexColor("#dc2626"),
    "High": colors.HexColor("#ea580c"),
    "Medium": colors.HexColor("#d97706"),
    "Low": colors.HexColor("#16a34a"),
}


def generate_pdf_bytes(results, urls, target_url):
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch
    )
    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Title"],
        fontSize=22,
        spaceAfter=6,
        textColor=colors.HexColor("#111827")
    )
    h2_style = ParagraphStyle(
        "H2", parent=styles["Heading2"],
        fontSize=14, spaceAfter=4,
        textColor=colors.HexColor("#1f2937")
    )
    h3_style = ParagraphStyle(
        "H3", parent=styles["Heading3"],
        fontSize=11, spaceAfter=3,
        textColor=colors.HexColor("#374151")
    )
    normal = styles["Normal"]
    small = ParagraphStyle("Small", parent=normal, fontSize=9, textColor=colors.HexColor("#6b7280"))

    # --- Title ---
    story.append(Paragraph("WebSpidey v2 - Vulnerability Scan Report", title_style))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", small))
    story.append(Paragraph(f"Target: {target_url}", small))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e5e7eb")))
    story.append(Spacer(1, 10))

    # --- Risk Summary ---
    risk = results.get("risk", {})
    score = risk.get("score", "N/A")
    level = risk.get("level", "N/A")
    risk_color = RISK_COLORS.get(level, colors.gray)

    story.append(Paragraph("Scan Summary", h2_style))

    summary_data = [
        ["Risk Score", "Risk Level", "URLs Crawled", "Total Findings"],
        [
            str(score) + " / 10",
            level,
            str(len(urls)),
            str(sum([
                len(results.get("sqli", [])),
                len(results.get("xss", [])),
                len(results.get("csrf", [])),
                len(results.get("open_redirect", [])),
                len(results.get("directories", [])),
                len(results.get("ssrf", [])),
                len(results.get("auth", [])),
                len(results.get("headers", [])),
            ]))
        ]
    ]

    summary_table = Table(summary_data, colWidths=[1.5 * inch] * 4)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e5e7eb")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TEXTCOLOR", (1, 1), (1, 1), risk_color),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 16))

    # --- Findings breakdown table ---
    story.append(Paragraph("Vulnerability Breakdown", h2_style))

    breakdown_data = [["Vulnerability Type", "Findings", "Severity"]]
    categories = [
        ("SQL Injection", "sqli", "Critical"),
        ("XSS", "xss", "High"),
        ("CSRF", "csrf", "Medium"),
        ("Open Redirect", "open_redirect", "Medium"),
        ("Exposed Directories", "directories", "High"),
        ("SSRF", "ssrf", "High"),
        ("Auth Weaknesses", "auth", "Critical"),
        ("Header Issues", "headers", "Medium"),
    ]
    for label, key, sev in categories:
        count = len(results.get(key, []))
        breakdown_data.append([label, str(count), sev])

    bt = Table(breakdown_data, colWidths=[3 * inch, 1 * inch, 1.5 * inch])
    bt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (1, 0), (2, -1), "CENTER"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e5e7eb")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(bt)
    story.append(Spacer(1, 16))

    # --- Per-vulnerability detail sections ---
    explanations = results.get("explanations", {})

    def add_vuln_section(title, key, items, item_formatter):
        if not items:
            return
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e5e7eb")))
        story.append(Spacer(1, 8))
        story.append(Paragraph(title, h2_style))

        exp = explanations.get(key, {})
        if exp:
            story.append(Paragraph(f"<b>Why it matters:</b> {exp.get('why', '')}", normal))
            story.append(Spacer(1, 4))
            story.append(Paragraph(f"<b>How detected:</b> {exp.get('how_detected', '')}", normal))
            story.append(Spacer(1, 4))
            story.append(Paragraph(f"<b>Remediation:</b> {exp.get('fix', '')}", normal))
            story.append(Spacer(1, 6))

        story.append(Paragraph("<b>Affected URLs:</b>", normal))
        for item in items[:10]:
            story.append(Paragraph(f"• {item_formatter(item)}", small))
        story.append(Spacer(1, 10))

    add_vuln_section(
        "SQL Injection Findings", "sqli", results.get("sqli", []),
        lambda x: f"{x.get('url', x)} — {x.get('reason', '')}" if isinstance(x, dict) else str(x)
    )
    add_vuln_section(
        "XSS Findings", "xss", results.get("xss", []),
        lambda x: f"{x.get('url', x)} ({x.get('type', '')})" if isinstance(x, dict) else str(x)
    )
    add_vuln_section(
        "CSRF Issues", "csrf", results.get("csrf", []),
        lambda x: f"{x.get('url', x)} — {x.get('reason', '')}" if isinstance(x, dict) else str(x)
    )
    add_vuln_section(
        "Open Redirect Findings", "open_redirect", results.get("open_redirect", []),
        lambda x: f"{x.get('url', x)} (param: {x.get('param', '')})" if isinstance(x, dict) else str(x)
    )
    add_vuln_section(
        "Exposed Directories", "directories", results.get("directories", []),
        lambda x: f"{x.get('url', x)} [{x.get('severity', '')}]" if isinstance(x, dict) else str(x)
    )
    add_vuln_section(
        "SSRF Vulnerabilities", "ssrf", results.get("ssrf", []),
        lambda x: f"{x.get('url', x)} (param: {x.get('param', '')})" if isinstance(x, dict) else str(x)
    )
    add_vuln_section(
        "Authentication Issues", "auth", results.get("auth", []),
        lambda x: f"{x.get('url', x)} — {x.get('issue', '')}" if isinstance(x, dict) else str(x)
    )

    # Headers section
    headers = results.get("headers", [])
    if headers:
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e5e7eb")))
        story.append(Spacer(1, 8))
        story.append(Paragraph("Security Header Issues", h2_style))
        exp = explanations.get("headers", {})
        if exp:
            story.append(Paragraph(f"<b>Fix:</b> {exp.get('fix', '')}", normal))
            story.append(Spacer(1, 4))
        for h in headers[:10]:
            sev = h.get("severity", "Low")
            story.append(Paragraph(
                f"• [{sev}] {h.get('header', '')} — {h.get('description', '')}",
                small
            ))
        story.append(Spacer(1, 10))

    # --- Crawled URLs ---
    if urls:
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e5e7eb")))
        story.append(Spacer(1, 8))
        story.append(Paragraph("Crawled URLs", h2_style))
        for u in urls[:20]:
            story.append(Paragraph(f"• {u}", small))
        story.append(Spacer(1, 10))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
