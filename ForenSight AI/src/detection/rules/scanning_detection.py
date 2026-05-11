"""
ForenSight AI - Port Scanning Detection
=======================================

Detects reconnaissance activity by identifying
hosts attempting connections to multiple ports.

Detection Logic
---------------
• Counts distinct destination ports
• Groups activity by source IP
• Triggers alert when threshold exceeded

Dataset Source
--------------
Firewall logs stored in structured_logs.db

Attack Category
---------------
Reconnaissance
"""

from src.utils.db_utils import execute_query


# ---------------------------------------------------------
# PORT SCANNING DETECTION
# ---------------------------------------------------------

def detect_port_scans(port_threshold=20):
    """
    Detect port scanning activity.

    Parameters
    ----------
    port_threshold : int
        Minimum distinct ports scanned before alert

    Returns
    -------
    list
        Port scan alerts
    """

    # ---------------------------------------------------------
    # SQL Detection Query
    # ---------------------------------------------------------

    query = f"""
    SELECT source_ip,
           MIN(timestamp),
           COUNT(DISTINCT endpoint)

    FROM logs

    WHERE log_type='firewall'

    GROUP BY source_ip

    HAVING COUNT(DISTINCT endpoint) >= {port_threshold}
    """

    rows = execute_query(query)

    alerts = []

    # ---------------------------------------------------------
    # Build Detection Alerts
    # ---------------------------------------------------------

    for ip, timestamp, port_count in rows:

        alerts.append({

            "type": "Port Scan",

            "timestamp": timestamp,

            "source_ip": ip,

            "ports_scanned": port_count

        })

    return alerts