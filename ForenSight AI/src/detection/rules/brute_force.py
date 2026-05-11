"""
ForenSight AI - Brute Force Detection
=====================================

Detects potential SSH brute force attacks by identifying
repeated failed authentication attempts originating
from the same source IP address and username.

Detection Logic
---------------
• Failed SSH authentication attempts
• Grouped by source IP and username
• Triggered when threshold is exceeded

Dataset Source
--------------
OpenSSH logs stored in structured_logs.db

Attack Category
---------------
Credential Access
"""

from src.utils.db_utils import execute_query


# ---------------------------------------------------------
# BRUTE FORCE DETECTION ENGINE
# ---------------------------------------------------------

def detect_brute_force(threshold=5):
    """
    Detect repeated SSH authentication failures.

    Parameters
    ----------
    threshold : int
        Minimum failed attempts required to trigger alert

    Returns
    -------
    list
        Generated brute force alerts
    """

    # ---------------------------------------------------------
    # SQL Detection Query
    # ---------------------------------------------------------

    query = f"""
    SELECT source_ip,
           username,
           MIN(timestamp),
           COUNT(*)

    FROM logs

    WHERE message LIKE '%Failed password%'

    GROUP BY source_ip, username

    HAVING COUNT(*) >= {threshold}
    """

    rows = execute_query(query)

    alerts = []

    # ---------------------------------------------------------
    # Build Detection Alerts
    # ---------------------------------------------------------

    for ip, username, timestamp, count in rows:

        alerts.append({

            "type": "Brute Force Attack",

            "timestamp": timestamp,

            "source_ip": ip,

            "username": username,

            "attempts": count

        })

    return alerts