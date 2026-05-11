"""
ForenSight AI - HDFS Error Detection
====================================

Detects abnormal Hadoop Distributed File System
(HDFS) events and operational failures.

Detection Logic
---------------
Identifies suspicious HDFS events including:

• ERROR messages
• Exceptions
• System failures

Dataset Source
--------------
HDFS logs stored in structured_logs.db

Attack Category
---------------
System Anomaly
"""

from src.utils.db_utils import execute_query


# ---------------------------------------------------------
# HDFS ERROR DETECTION
# ---------------------------------------------------------

def detect_hdfs_errors():
    """
    Detect suspicious HDFS system events.

    Returns
    -------
    list
        Generated HDFS alerts
    """

    # ---------------------------------------------------------
    # SQL Detection Query
    # ---------------------------------------------------------

    query = """
    SELECT timestamp,
           message

    FROM logs

    WHERE log_type='hdfs'

      AND (
            message LIKE '%ERROR%'
         OR message LIKE '%Exception%'
         OR message LIKE '%failure%'
      )
    """

    rows = execute_query(query)

    alerts = []

    # ---------------------------------------------------------
    # Build Detection Alerts
    # ---------------------------------------------------------

    for timestamp, message in rows:

        alerts.append({

            "type": "HDFS System Error",

            "timestamp": timestamp,

            "details": message

        })

    return alerts