"""
Dashboard Service (FINAL FIXED VERSION)
======================================

Processes alerts into GUI-ready metrics.

✔ Case-insensitive severity handling
✔ Correct structure for dashboard widget
✔ Accurate severity counts
✔ Top IOC calculation
"""

from collections import Counter


def compute_metrics(alerts):
    """
    FINAL VERSION – Compatible with dashboard widget
    """

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    ip_counter = Counter()

    for alert in alerts:

        severity = str(alert.get("severity", "LOW")).upper()

        if severity in severity_counts:
            severity_counts[severity] += 1

        ip = alert.get("source_ip")
        if ip:
            ip_counter[ip] += 1

    top_ip = ip_counter.most_common(1)[0][0] if ip_counter else "N/A"

    return {
        "total_alerts": len(alerts),
        "top_ip": top_ip,
        "overall_severity": (
            "CRITICAL" if severity_counts["CRITICAL"] > 0 else
            "HIGH" if severity_counts["HIGH"] > 0 else
            "MEDIUM" if severity_counts["MEDIUM"] > 0 else
            "LOW"
        ),
        "severity_counts": severity_counts
    }