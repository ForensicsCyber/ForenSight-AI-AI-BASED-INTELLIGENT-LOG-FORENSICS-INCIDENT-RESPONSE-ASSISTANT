"""
ForenSight AI - PDF Report Generator
====================================

Generates enterprise-style forensic investigation
reports for detected security incidents.

Responsibilities
----------------
1. Build structured PDF reports
2. Render attack visualizations
3. Generate IOC intelligence sections
4. Render threat intelligence summaries
5. Display AI-generated recommendations
6. Produce printable forensic documentation

Features
--------
• Corporate branding
• Watermark support
• Timeline visualizations
• Attack distribution charts
• Threat intelligence tables
• IOC reporting
• Severity highlighting

Architecture Notes
------------------
• Built using ReportLab
• Compatible with packaged (.exe) deployment
• Supports AI + rule-based reporting workflows
"""

from collections import Counter, defaultdict
from datetime import datetime
import os

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    Image
)

from src.utils.logger_config import setup_logger


# ---------------------------------------------------------
# LOGGER INITIALIZATION
# ---------------------------------------------------------

logger = setup_logger()


# ---------------------------------------------------------
# OUTPUT DIRECTORY
# ---------------------------------------------------------

OUTPUT_DIR = os.path.join(
    os.path.expanduser("~"),
    "Downloads",
    "ForenSightAI",
    "Reports"
)

os.makedirs(OUTPUT_DIR, exist_ok=True)


# ---------------------------------------------------------
# APPLICATION CONFIGURATION
# ---------------------------------------------------------

LOGO_PATH = "logo.png"

COMPANY_NAME = "ForenSight AI"


# ---------------------------------------------------------
# PDF PAGE LAYOUT
# ---------------------------------------------------------

def draw_page_elements(canvas, doc):
    """
    Render page decorations including:
    • border
    • logo
    • watermark
    • footer
    """

    width, height = doc.pagesize

    # ---------------------------------------------------------
    # Border
    # ---------------------------------------------------------

    margin = 20

    canvas.setStrokeColor(colors.grey)
    canvas.setLineWidth(1)

    canvas.rect(
        margin,
        margin,
        width - 2 * margin,
        height - 2 * margin
    )

    # ---------------------------------------------------------
    # Company Logo
    # ---------------------------------------------------------

    if os.path.exists(LOGO_PATH):

        canvas.drawImage(
            LOGO_PATH,
            x=width - 150,
            y=height - 90,
            width=120,
            height=60,
            preserveAspectRatio=True,
            mask='auto'
        )

    # ---------------------------------------------------------
    # Confidential Watermark
    # ---------------------------------------------------------

    canvas.saveState()

    canvas.setFont("Helvetica-Bold", 40)

    canvas.setFillColorRGB(
        0.9,
        0.9,
        0.9
    )

    canvas.translate(
        width / 2,
        height / 2 - 50
    )

    canvas.rotate(45)

    canvas.drawCentredString(
        0,
        0,
        "CONFIDENTIAL"
    )

    canvas.restoreState()

    # ---------------------------------------------------------
    # Footer Section
    # ---------------------------------------------------------

    page_number = canvas.getPageNumber()

    canvas.setFont("Helvetica", 10)

    footer_y = 30

    # Company Name
    canvas.drawString(
        30,
        footer_y,
        COMPANY_NAME
    )

    # Page Number
    canvas.drawCentredString(
        width / 2,
        footer_y,
        f"Page {page_number}"
    )


# ---------------------------------------------------------
# SEVERITY COLOR MAPPING
# ---------------------------------------------------------

def get_severity_color(severity):
    """
    Return report color associated with severity.
    """

    if severity == "CRITICAL":
        return colors.red

    elif severity == "HIGH":
        return colors.orange

    elif severity == "MEDIUM":
        return colors.darkgoldenrod

    return colors.green


# ---------------------------------------------------------
# TEXT CLEANING
# ---------------------------------------------------------

def clean_lines(text):
    """
    Normalize and clean report text blocks.
    """

    if isinstance(text, str):
        text = text.split("\n")

    cleaned = []

    for line in text:

        line = line.strip()

        if not line:
            continue

        line = line.replace("*", "")
        line = line.replace("•", "")

        cleaned.append(line)

    return cleaned


# ---------------------------------------------------------
# ATTACK DISTRIBUTION CHART
# ---------------------------------------------------------

def generate_attack_chart(alerts, path=None):
    """
    Generate attack distribution visualization.
    """

    if path is None:

        path = os.path.join(
            OUTPUT_DIR,
            "attack_chart.png"
        )

    counts = {}

    for alert in alerts:

        attack_type = alert.get("type")

        counts[attack_type] = (
            counts.get(attack_type, 0) + 1
        )

    if not counts:
        return None

    plt.figure()

    plt.bar(
        list(counts.keys()),
        list(counts.values())
    )

    plt.xticks(rotation=30)

    plt.title("Attack Distribution")

    plt.tight_layout()

    plt.savefig(path)

    plt.close()

    return path


# ---------------------------------------------------------
# TIMELINE CHART
# ---------------------------------------------------------

def generate_timeline_chart(alerts, path=None):
    """
    Generate attack timeline visualization.
    """

    if path is None:

        path = os.path.join(
            OUTPUT_DIR,
            "timeline_chart.png"
        )

    timestamps = [

        a.get("timestamp")

        for a in alerts

        if a.get("timestamp")

    ]

    if not timestamps:
        return None

    timestamps.sort()

    plt.figure()

    plt.plot(
        range(len(timestamps)),
        [1] * len(timestamps)
    )

    plt.title("Attack Timeline")

    plt.tight_layout()

    plt.savefig(path)

    plt.close()

    return path


# ---------------------------------------------------------
# MAIN PDF REPORT GENERATION
# ---------------------------------------------------------

def generate_pdf_report(report_data, output=None):
    """
    Generate forensic investigation PDF report.

    Parameters
    ----------
    report_data : dict
        Structured report data

    output : str, optional
        Output PDF path

    Returns
    -------
    str
        Generated PDF file path
    """

    if output is None:

        output = os.path.join(
            OUTPUT_DIR,
            "ForenSightAI_Report.pdf"
        )

    logger.info("PDF report generation started")

    doc = SimpleDocTemplate(output)

    styles = getSampleStyleSheet()

    content = []

    # ---------------------------------------------------------
    # Report Title
    # ---------------------------------------------------------

    content.append(

        Paragraph(
            "ForenSight AI - Enterprise Security Report",
            styles["Title"]
        )

    )

    content.append(Spacer(1, 10))

    content.append(

        Paragraph(
            f"Generated on: {datetime.now()}",
            styles["Normal"]
        )

    )

    content.append(Spacer(1, 20))

    # ---------------------------------------------------------
    # Executive Summary
    # ---------------------------------------------------------

    content.append(

        Paragraph(
            "Executive Summary",
            styles["Heading2"]
        )

    )

    content.append(Spacer(1, 10))

    summary_lines = clean_lines(
        report_data["summary"]
    )

    section_titles = [

        "Incident Summary",

        "Attack Analysis",

        "Severity Levels",

        "Attacker Behavior",

        "Recommendations",

        "Next Steps"

    ]

    for line in summary_lines:

        if line in section_titles:

            content.append(

                Paragraph(
                    f"<b>{line}</b>",
                    styles["Normal"]
                )

            )

            content.append(Spacer(1, 6))

            continue

        content.append(
            Paragraph(line, styles["Normal"])
        )

        content.append(Spacer(1, 6))

    content.append(Spacer(1, 20))

    # ---------------------------------------------------------
    # Aggregated Detection Alerts
    # ---------------------------------------------------------

    content.append(
        Paragraph(
            "Detected Alerts",
            styles["Heading2"]
        )
    )

    content.append(Spacer(1, 10))

    alerts = report_data.get("alerts", [])

    if not isinstance(alerts, list):
        alerts = []

    attack_counter = Counter()

    severity_map = {}

    severity_order = [
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ]

    for alert in alerts:

        attack_type = alert.get(
            "type",
            "Unknown"
        )

        severity = str(
            alert.get("severity", "LOW")
        ).upper()

        if severity not in severity_order:
            severity = "LOW"

        attack_counter[attack_type] += 1

        if attack_type not in severity_map:

            severity_map[attack_type] = severity

        else:

            existing = severity_map[attack_type]

            if existing not in severity_order:
                existing = "LOW"

            if (
                severity_order.index(severity)
                >
                severity_order.index(existing)
            ):
                severity_map[attack_type] = severity

    sorted_attacks = sorted(
        attack_counter.items(),
        key=lambda x: x[1],
        reverse=True
    )

    table_data = [[
        "Attack Type",
        "Total Occurrences",
        "Severity"
    ]]

    for attack, count in sorted_attacks:

        formatted_attack = (
            str(attack)
            .replace("_", " ")
            .title()
        )

        table_data.append([
            formatted_attack,
            str(count),
            severity_map.get(attack, "LOW")
        ])

    table = Table(table_data)

    style = TableStyle([

        ("GRID", (0, 0), (-1, -1), 1, colors.black),

        ("BACKGROUND", (0, 0), (-1, 0), colors.darkgrey),

        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),

        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),

    ])

    for i, row in enumerate(table_data[1:], start=1):

        severity = row[2]

        color = get_severity_color(severity)

        style.add(
            "TEXTCOLOR",
            (2, i),
            (2, i),
            color
        )

    table.setStyle(style)

    content.append(table)

    content.append(Spacer(1, 20))

    # ---------------------------------------------------------
    # Correlated Security Incidents
    # ---------------------------------------------------------

    content.append(
        Paragraph(
            "Incidents",
            styles["Heading2"]
        )
    )

    content.append(Spacer(1, 10))

    incident_groups = defaultdict(list)

    for alert in report_data.get("alerts", []):

        attack_type = alert.get(
            "type",
            "Unknown"
        )

        incident_groups[attack_type].append(alert)

    for attack_type, items in incident_groups.items():

        count = len(items)

        severities = [

            str(i.get("severity", "LOW")).upper()

            for i in items

        ]

        highest_severity = max(
            severities,
            key=lambda x: severity_order.index(x)
        )

        ip_counter = Counter([

            i.get("source_ip")

            for i in items

            if i.get("source_ip")

        ])

        top_ip = (

            ip_counter.most_common(1)[0][0]

            if ip_counter

            else "N/A"

        )

        content.append(
            Paragraph(
                f"<b>{attack_type}</b>",
                styles["Normal"]
            )
        )

        content.append(Spacer(1, 6))

        content.append(
            Paragraph(
                f"Severity: {highest_severity}",
                styles["Normal"]
            )
        )

        content.append(
            Paragraph(
                f"Occurrences: {count}",
                styles["Normal"]
            )
        )

        content.append(
            Paragraph(
                f"Top Source IP: {top_ip}",
                styles["Normal"]
            )
        )

        content.append(Spacer(1, 6))

        description_map = {

            "Web Injection":
                "Possible injection attempts targeting application endpoints.",

            "Brute Force Attack":
                "Repeated login attempts detected indicating password attack.",

            "Port Scan":
                "Scanning activity detected across multiple ports.",

            "HDFS System Error":
                "Repeated system errors indicating instability or stress.",

            "Linux Authentication Attack":
                "Suspicious authentication activity detected.",

            "HTTP Traffic Spike":
                "Unusual traffic spike detected, possible DoS behavior."

        }

        description = description_map.get(
            attack_type,
            "Suspicious activity detected."
        )

        content.append(
            Paragraph(
                f"Description: {description}",
                styles["Normal"]
            )
        )

        content.append(Spacer(1, 6))

        content.append(
            Paragraph(
                "Impact: Potential security risk requiring investigation.",
                styles["Normal"]
            )
        )

        content.append(Spacer(1, 12))

    # ---------------------------------------------------------
    # Attack Distribution Chart
    # ---------------------------------------------------------

    content.append(
        Paragraph(
            "Attack Distribution",
            styles["Heading2"]
        )
    )

    content.append(Spacer(1, 10))

    chart = generate_attack_chart(alerts)

    if chart:

        content.append(
            Image(
                chart,
                width=400,
                height=200
            )
        )

    content.append(Spacer(1, 20))

    # ---------------------------------------------------------
    # Attack Timeline Chart
    # ---------------------------------------------------------

    content.append(
        Paragraph(
            "Attack Timeline",
            styles["Heading2"]
        )
    )

    content.append(Spacer(1, 10))

    timeline = generate_timeline_chart(alerts)

    if timeline:

        content.append(
            Image(
                timeline,
                width=400,
                height=200
            )
        )

    content.append(Spacer(1, 20))

    # ---------------------------------------------------------
    # Indicators of Compromise
    # ---------------------------------------------------------

    content.append(
        Paragraph(
            "Indicators of Compromise",
            styles["Heading2"]
        )
    )

    content.append(Spacer(1, 10))

    iocs = report_data.get("iocs", {})

    attacker_ips = sorted(
        set(iocs.get("attacker_ips", []))
    )

    ports = sorted(
        set(iocs.get("suspicious_ports", []))
    )

    attack_types = sorted(
        set(iocs.get("attack_types", []))
    )

    # ---------------------------------------------------------
    # Attacker IPs
    # ---------------------------------------------------------

    content.append(
        Paragraph(
            "<b>Attacker IPs:</b>",
            styles["Normal"]
        )
    )

    content.append(Spacer(1, 8))

    cols = 4

    rows = []

    for i in range(0, len(attacker_ips), cols):

        row = attacker_ips[i:i + cols]

        while len(row) < cols:
            row.append("")

        rows.append(row)

    if not rows:

        content.append(
            Paragraph(
                "No attacker IPs detected.",
                styles["Normal"]
            )
        )

    else:

        ip_table = Table(
            rows,
            colWidths=[120] * cols
        )

        ip_table.setStyle(TableStyle([

            ("LEFTPADDING", (0, 0), (-1, -1), 4),

            ("RIGHTPADDING", (0, 0), (-1, -1), 4),

            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),

            ("TOPPADDING", (0, 0), (-1, -1), 2),

        ]))

        content.append(ip_table)

    content.append(Spacer(1, 12))

    # ---------------------------------------------------------
    # Suspicious Ports
    # ---------------------------------------------------------

    content.append(
        Paragraph(
            "<b>Suspicious Ports:</b>",
            styles["Normal"]
        )
    )

    content.append(Spacer(1, 8))

    cols = 8

    rows = []

    ports_str = [str(p) for p in ports]

    for i in range(0, len(ports_str), cols):

        row = ports_str[i:i + cols]

        while len(row) < cols:
            row.append("")

        rows.append(row)

    if not rows:

        content.append(
            Paragraph(
                "No suspicious ports detected.",
                styles["Normal"]
            )
        )

    else:

        port_table = Table(
            rows,
            colWidths=[60] * cols
        )

        port_table.setStyle(TableStyle([

            ("LEFTPADDING", (0, 0), (-1, -1), 3),

            ("RIGHTPADDING", (0, 0), (-1, -1), 3),

            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),

            ("TOPPADDING", (0, 0), (-1, -1), 2),

        ]))

        content.append(port_table)

    content.append(Spacer(1, 12))

    # ---------------------------------------------------------
    # Attack Types
    # ---------------------------------------------------------

    content.append(
        Paragraph(
            "<b>Attack Types:</b>",
            styles["Normal"]
        )
    )

    content.append(Spacer(1, 6))

    if attack_types:

        for attack in attack_types:

            formatted = (
                attack
                .replace("_", " ")
                .title()
            )

            content.append(
                Paragraph(
                    f"- {formatted}",
                    styles["Normal"]
                )
            )

    else:

        content.append(
            Paragraph(
                "No attack types detected.",
                styles["Normal"]
            )
        )

    content.append(Spacer(1, 20))

    # ---------------------------------------------------------
    # Threat Intelligence
    # ---------------------------------------------------------

    content.append(
        Paragraph(
            "Threat Intelligence",
            styles["Heading2"]
        )
    )

    content.append(Spacer(1, 10))

    threat_data = report_data.get(
        "threat_intel",
        []
    )

    unique_threats = {}

    for item in threat_data:

        ip = item.get("ip")

        if not ip:
            continue

        if ip not in unique_threats:

            unique_threats[ip] = item

        else:

            existing = unique_threats[ip]

            if (
                severity_order.index(
                    item.get("threat_score", "LOW")
                )
                >
                severity_order.index(
                    existing.get("threat_score", "LOW")
                )
            ):
                unique_threats[ip] = item

    table_data = [[
        "IP",
        "Country",
        "Threat Score"
    ]]

    for item in unique_threats.values():

        table_data.append([

            item.get("ip"),

            item.get("country"),

            item.get("threat_score")

        ])

    if len(table_data) <= 1:

        content.append(
            Paragraph(
                "No threat intelligence data available.",
                styles["Normal"]
            )
        )

    else:

        table = Table(table_data)

        style = TableStyle([

            ("GRID", (0, 0), (-1, -1), 1, colors.black),

            ("BACKGROUND", (0, 0), (-1, 0), colors.darkgrey),

            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)

        ])

        for i, row in enumerate(table_data[1:], start=1):

            severity = row[2]

            color = get_severity_color(severity)

            style.add(
                "TEXTCOLOR",
                (2, i),
                (2, i),
                color
            )

        table.setStyle(style)

        content.append(table)

    content.append(Spacer(1, 20))

    # ---------------------------------------------------------
    # Recommendations
    # ---------------------------------------------------------

    content.append(
        Paragraph(
            "Recommendations",
            styles["Heading2"]
        )
    )

    content.append(Spacer(1, 10))

    recommendations = report_data["recommendations"]

    if isinstance(recommendations, str):

        recommendations = recommendations.split("\n")

    for line in recommendations:

        line = line.strip()

        if not line:
            continue

        line = (
            line
            .replace("*", "")
            .replace("**", "")
        )

        if line.lower() in [

            "mitigation steps:",

            "prevention strategies:",

            "security controls:"

        ]:

            content.append(
                Paragraph(
                    f"<b>{line}</b>",
                    styles["Normal"]
                )
            )

            content.append(Spacer(1, 6))

            continue

        content.append(
            Paragraph(
                f"- {line}",
                styles["Normal"]
            )
        )

        content.append(Spacer(1, 4))

    # ---------------------------------------------------------
    # Build PDF
    # ---------------------------------------------------------

    doc.build(

        content,

        onFirstPage=draw_page_elements,

        onLaterPages=draw_page_elements

    )

    logger.info(
        "PDF report generated successfully"
    )

    logger.info(
        "Thank you for using ForenSight AI!"
    )

    # ---------------------------------------------------------
    # Cleanup Temporary Chart Files
    # ---------------------------------------------------------

    for f in [

        "attack_chart.png",

        "timeline_chart.png"

    ]:

        file_path = os.path.join(
            OUTPUT_DIR,
            f
        )

        if os.path.exists(file_path):

            try:

                os.remove(file_path)

            except Exception as e:

                logger.warning(
                    f"Cleanup failed for {file_path}: {e}"
                )

    return output