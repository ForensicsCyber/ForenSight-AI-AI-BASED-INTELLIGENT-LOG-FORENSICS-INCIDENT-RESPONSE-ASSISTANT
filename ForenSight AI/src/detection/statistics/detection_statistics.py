"""
ForenSight AI - Detection Statistics Engine
===========================================

Generates aggregated statistical summaries from
detection alerts.

Purpose
-------
Provides high-level security analytics used by:

• SOC dashboards
• Detection summaries
• Incident reporting
• Threat intelligence views
• Executive security reports

Generated Metrics
-----------------
1. Total alert count
2. Alerts grouped by attack category
3. Top attacking source IP addresses

Architecture Notes
------------------
• Lightweight aggregation engine
• Operates directly on generated alerts
• Supports dashboard and reporting workflows
"""

# ---------------------------------------------------------
# DETECTION STATISTICS GENERATION
# ---------------------------------------------------------

def generate_detection_statistics(alerts):
    """
    Generate statistical summaries from alerts.

    Parameters
    ----------
    alerts : list
        Detection alert objects

    Returns
    -------
    dict
        Aggregated detection statistics
    """

    stats = {

        "total_alerts": len(alerts),

        "alerts_by_type": {},

        "top_attackers": {}

    }

    # ---------------------------------------------------------
    # Process Detection Alerts
    # ---------------------------------------------------------

    for alert in alerts:

        # ---------------------------------------------------------
        # Attack Type Aggregation
        # ---------------------------------------------------------

        alert_type = alert.get("type", "unknown")

        stats["alerts_by_type"][alert_type] = (

            stats["alerts_by_type"].get(alert_type, 0) + 1

        )

        # ---------------------------------------------------------
        # Source IP Aggregation
        # ---------------------------------------------------------

        ip = alert.get("source_ip")

        if ip:

            stats["top_attackers"][ip] = (

                stats["top_attackers"].get(ip, 0) + 1

            )

    # ---------------------------------------------------------
    # Sort Top Attackers by Frequency
    # ---------------------------------------------------------

    top_attackers_sorted = sorted(

        stats["top_attackers"].items(),

        key=lambda x: x[1],

        reverse=True

    )[:5]

    # ---------------------------------------------------------
    # Return Aggregated Statistics
    # ---------------------------------------------------------

    return {

        "total_alerts": stats["total_alerts"],

        "alerts_by_type": stats["alerts_by_type"],

        "top_attackers": top_attackers_sorted

    }