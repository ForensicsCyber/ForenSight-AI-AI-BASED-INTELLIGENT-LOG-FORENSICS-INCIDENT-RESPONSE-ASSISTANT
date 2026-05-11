"""
ForenSight AI - GUI Alert Loader
================================

Provides database loading utilities used by
the graphical dashboard interface.

Responsibilities
----------------
1. Load alerts from alerts.db
2. Normalize alert records for GUI consumption
3. Support both .py and packaged .exe execution

Architecture Notes
------------------
• Uses centralized runtime dataset directory
• Compatible with PyInstaller builds
• Supplies dashboard, IOC and reporting views
"""

import os
import sqlite3

from src.utils.db_utils import get_alert_db_path


# ---------------------------------------------------------
# ALERT DATABASE PATH
# ---------------------------------------------------------

ALERT_DB_PATH = get_alert_db_path()


# ---------------------------------------------------------
# ALERT LOADER
# ---------------------------------------------------------

def load_alerts():
    """
    Load alerts from alerts database.

    Returns
    -------
    list
        GUI-ready alert dictionaries
    """

    # ---------------------------------------------------------
    # Validate Database Existence
    # ---------------------------------------------------------

    if not os.path.exists(ALERT_DB_PATH):

        raise FileNotFoundError(
            f"alerts.db not found at: {ALERT_DB_PATH}"
        )

    conn = sqlite3.connect(ALERT_DB_PATH)

    cursor = conn.cursor()

    # ---------------------------------------------------------
    # Load Alerts
    # ---------------------------------------------------------

    cursor.execute("""
        SELECT
            id,
            timestamp,
            alert_type,
            source_ip,
            username,
            severity,
            description

        FROM alerts

        ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    alerts = []

    # ---------------------------------------------------------
    # Normalize Alert Objects
    # ---------------------------------------------------------

    for row in rows:

        alerts.append({

            "id": row[0],

            "timestamp": row[1],

            "type": row[2],

            "source_ip": row[3],

            "username": row[4],

            "severity": row[5],

            "details": row[6]

        })

    return alerts