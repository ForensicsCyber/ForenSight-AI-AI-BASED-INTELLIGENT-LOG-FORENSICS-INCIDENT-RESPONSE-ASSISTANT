"""
Severity Utility Module
=======================

Provides centralized severity classification
for detection alerts.

Severity Levels
---------------
LOW
    Minor anomalies or low-risk events

MEDIUM
    Suspicious or potentially malicious activity

HIGH
    Confirmed attack behavior requiring investigation

CRITICAL
    Severe compromise or exploit attempt

Purpose
-------
Ensures consistent severity scoring across
all detection modules and dashboard components.
"""


# ---------------------------------------------------------
# SEVERITY MAPPING
# ---------------------------------------------------------

def assign_severity(alert_type):
    """
    Assign severity level based on alert type.

    Parameters
    ----------
    alert_type : str
        Detection alert category

    Returns
    -------
    str
        Severity classification
    """

    severity_map = {

        "Brute Force Attack": "HIGH",

        "Linux Authentication Attack": "HIGH",

        "Port Scan": "MEDIUM",

        "Web Injection": "CRITICAL",

        "HTTP Traffic Spike": "LOW",

        "HDFS System Error": "MEDIUM"

    }

    return severity_map.get(alert_type, "MEDIUM")