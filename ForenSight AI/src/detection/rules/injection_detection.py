"""
ForenSight AI - Web Injection Detection
=======================================

Detects common web application attack patterns.

Detection Logic
---------------
Identifies indicators associated with:

• SQL Injection
• Cross-Site Scripting (XSS)

Dataset Source
--------------
Firewall logs stored in structured_logs.db

Attack Category
---------------
Web Application Attack
"""

from src.utils.db_utils import execute_query


# ---------------------------------------------------------
# WEB INJECTION DETECTION
# ---------------------------------------------------------

def detect_web_injections():
    """
    Detect web injection attacks.

    Returns
    -------
    list
        Web injection alerts
    """

    # ---------------------------------------------------------
    # SQL Detection Query
    # ---------------------------------------------------------

    query = """
    SELECT timestamp,
           message

    FROM logs

    WHERE message LIKE '%SQL Injection%'
       OR message LIKE '%XSS%'
    """

    rows = execute_query(query)

    alerts = []

    # ---------------------------------------------------------
    # Build Detection Alerts
    # ---------------------------------------------------------

    for timestamp, message in rows:

        alerts.append({

            "type": "Web Injection",

            "timestamp": timestamp,

            "details": message

        })

    return alerts