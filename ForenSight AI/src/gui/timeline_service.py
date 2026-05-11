"""
ForenSight AI - Timeline Service
================================

Builds chronological forensic timelines
from generated detection alerts.

Responsibilities
----------------
1. Normalize alert timestamps
2. Normalize severity classifications
3. Generate GUI-ready timeline entries
4. Sort events by severity and time

Timeline Ordering
-----------------
1. Higher severity events first
2. Chronological ordering within severity

Supported Severities
--------------------
• CRITICAL
• HIGH
• MEDIUM
• LOW
"""

# ---------------------------------------------------------
# TIMELINE GENERATION
# ---------------------------------------------------------

def build_timeline(alerts):
    """
    Build structured forensic timeline.

    Parameters
    ----------
    alerts : list
        Detection alert objects

    Returns
    -------
    list
        Timeline event entries
    """

    timeline = []

    # ---------------------------------------------------------
    # Process Alerts
    # ---------------------------------------------------------

    for alert in alerts:

        # ---------------------------------------------------------
        # Normalize Severity
        # ---------------------------------------------------------

        raw_severity = alert.get("severity", "LOW")

        severity = str(raw_severity).strip().upper()

        if severity not in [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW"
        ]:
            severity = "LOW"

        # ---------------------------------------------------------
        # Normalize Event Name
        # ---------------------------------------------------------

        event_name = (

            alert.get("type")

            or alert.get("alert_type")

            or alert.get("attack_type")

            or alert.get("details")

            or alert.get("description")

            or "Unknown"

        )

        # ---------------------------------------------------------
        # Build Timeline Entry
        # ---------------------------------------------------------

        timeline.append({

            "time": (

                alert.get("timestamp")

                or alert.get("event_time")

                or alert.get("time")

                or "N/A"

            ),

            "event": str(event_name)
            .replace("_", " ")
            .title(),

            "severity": severity

        })

    # ---------------------------------------------------------
    # Severity Priority Sorting
    # ---------------------------------------------------------

    severity_order = {

        "CRITICAL": 4,

        "HIGH": 3,

        "MEDIUM": 2,

        "LOW": 1

    }

    try:

        timeline.sort(

            key=lambda x: (

                -severity_order.get(
                    x["severity"],
                    0
                ),

                x["time"]

            )

        )

    except Exception:
        pass

    return timeline