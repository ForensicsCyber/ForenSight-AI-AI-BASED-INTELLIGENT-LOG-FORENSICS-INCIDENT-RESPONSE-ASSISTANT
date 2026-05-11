"""
ForenSight AI - HTTP Traffic Anomaly Detection
==============================================

Detects abnormal spikes in HTTP traffic volume.

Detection Logic
---------------
• Groups requests by endpoint
• Counts total requests
• Triggers alert when threshold exceeded

Dataset Source
--------------
Apache logs stored in structured_logs.db

Attack Category
---------------
Traffic Anomaly
"""

from src.utils.db_utils import execute_query


# ---------------------------------------------------------
# HTTP TRAFFIC ANOMALY DETECTION
# ---------------------------------------------------------

def detect_http_spikes(threshold=200):
    """
    Detect abnormal HTTP request spikes.

    Parameters
    ----------
    threshold : int
        Minimum request count required to trigger alert

    Returns
    -------
    list
        HTTP traffic anomaly alerts
    """

    # ---------------------------------------------------------
    # SQL Detection Query
    # ---------------------------------------------------------

    query = f"""
    SELECT endpoint,
           MIN(timestamp),
           COUNT(*)

    FROM logs

    WHERE log_type='apache'

    GROUP BY endpoint

    HAVING COUNT(*) >= {threshold}
    """

    rows = execute_query(query)

    alerts = []

    # ---------------------------------------------------------
    # Build Detection Alerts
    # ---------------------------------------------------------

    for endpoint, timestamp, count in rows:

        alerts.append({

            "type": "HTTP Traffic Spike",

            "timestamp": timestamp,

            "endpoint": endpoint,

            "request_count": count

        })

    return alerts