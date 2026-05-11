"""
ForenSight AI - Event Correlation Engine
========================================

Correlates low-level detection alerts into
higher-level security incidents.

Purpose
-------
Security operations platforms typically generate
large numbers of isolated alerts.

This module groups related alerts into broader
incident categories to improve:

• analyst visibility
• incident prioritization
• attack understanding
• forensic investigation workflows

Current Correlation Categories
------------------------------
• Reconnaissance Activity
• Credential Attack

Architecture Notes
------------------
• Lightweight rule-based correlation engine
• Operates on generated detection alerts
• Designed for SOC dashboard integration
• Easily extensible for future attack chains
"""

# ---------------------------------------------------------
# EVENT CORRELATION ENGINE
# ---------------------------------------------------------

def correlate_events(alerts):
    """
    Correlate detection alerts into incidents.

    Parameters
    ----------
    alerts : list
        Detection alert objects

    Returns
    -------
    list
        Correlated security incidents
    """

    incidents = []

    # ---------------------------------------------------------
    # Process Detection Alerts
    # ---------------------------------------------------------

    for alert in alerts:

        alert_type = alert.get("type")

        # ---------------------------------------------------------
        # Reconnaissance Correlation
        # ---------------------------------------------------------

        if alert_type == "Port Scan":

            incidents.append({

                "incident": "Reconnaissance Activity",

                "details": alert

            })

        # ---------------------------------------------------------
        # Credential Attack Correlation
        # ---------------------------------------------------------

        elif alert_type == "Brute Force Attack":

            incidents.append({

                "incident": "Credential Attack",

                "details": alert

            })

    return incidents