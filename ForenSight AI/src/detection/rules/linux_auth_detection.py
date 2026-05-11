"""
ForenSight AI - Linux Authentication Detection
==============================================

Detects suspicious authentication activity within
Linux system logs.

Detection Logic
---------------
Identifies repeated:

• authentication failures
• invalid user attempts
• failed login activity

Dataset Source
--------------
Linux system logs stored in structured_logs.db

Attack Category
---------------
Credential Access
"""

from src.utils.db_utils import execute_query


# ---------------------------------------------------------
# LINUX AUTHENTICATION DETECTION
# ---------------------------------------------------------

def detect_linux_auth_failures(threshold=5):
    """
    Detect repeated Linux authentication failures.

    Parameters
    ----------
    threshold : int
        Minimum failed attempts required to trigger alert

    Returns
    -------
    list
        Linux authentication alerts
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

    WHERE log_type='linux'

      AND (
            message LIKE '%authentication failure%'
         OR message LIKE '%invalid user%'
         OR message LIKE '%failed%'
      )

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

            "type": "Linux Authentication Attack",

            "timestamp": timestamp,

            "source_ip": ip,

            "username": username,

            "attempts": count

        })

    return alerts