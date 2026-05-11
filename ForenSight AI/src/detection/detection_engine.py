"""
ForenSight AI - Detection Engine
================================

Central orchestration layer for all detection
components within the ForenSight AI platform.

Responsibilities
----------------
1. Execute rule-based detection modules
2. Assign severity classifications
3. Persist generated alerts
4. Correlate alerts into incidents
5. Generate chronological timelines
6. Produce detection statistics
7. Extract Indicators of Compromise (IOCs)

Database Inputs
---------------
structured_logs.db

Database Outputs
----------------
alerts.db

Architecture Notes
------------------
• Supports both development and packaged (.exe) execution
• Uses centralized database management utilities
• Designed for modular SOC-style detection workflows
"""

# ---------------------------------------------------------
# DETECTION RULE MODULES
# ---------------------------------------------------------

from src.detection.rules.brute_force import detect_brute_force
from src.detection.rules.scanning_detection import detect_port_scans
from src.detection.rules.injection_detection import detect_web_injections
from src.detection.rules.http_anomalies import detect_http_spikes
from src.detection.rules.linux_auth_detection import (
    detect_linux_auth_failures
)
from src.detection.rules.hdfs_error_detection import detect_hdfs_errors


# ---------------------------------------------------------
# SUPPORTING DETECTION COMPONENTS
# ---------------------------------------------------------

from src.detection.correlation.event_correlator import correlate_events

from src.gui.timeline_service import build_timeline

from src.detection.statistics.detection_statistics import (
    generate_detection_statistics
)

from src.detection.ioc_extraction.ioc_extractor import (
    extract_iocs
)


# ---------------------------------------------------------
# DATABASE UTILITIES
# ---------------------------------------------------------

from src.utils.db_utils import (
    insert_alert,
    get_alert_connection
)


# ---------------------------------------------------------
# LOGGING CONFIGURATION
# ---------------------------------------------------------

from src.utils.logger_config import setup_logger

logger = setup_logger()


# ---------------------------------------------------------
# SEVERITY CLASSIFICATION
# ---------------------------------------------------------

from src.utils.severity_utils import assign_severity


# ---------------------------------------------------------
# ALERT DATABASE RESET
# ---------------------------------------------------------

def reset_alerts_db():
    """
    Reset alerts database before a new detection run.

    This prevents stale alerts from previous analysis
    sessions from contaminating new detection results.
    """

    conn = get_alert_connection()
    cursor = conn.cursor()

    # ---------------------------------------------------------
    # Ensure alerts table exists
    # ---------------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            alert_type TEXT,
            source_ip TEXT,
            username TEXT,
            severity TEXT,
            description TEXT
        )
    """)

    # ---------------------------------------------------------
    # Clear Existing Alert Records
    # ---------------------------------------------------------

    try:

        cursor.execute("DELETE FROM alerts")

        cursor.execute("""
            DELETE FROM sqlite_sequence
            WHERE name='alerts'
        """)

    except Exception as e:

        logger.warning(
            f"Could not reset alerts database: {e}"
        )

    conn.commit()
    conn.close()


# ---------------------------------------------------------
# MAIN DETECTION ENGINE
# ---------------------------------------------------------

def run_detection_engine():
    """
    Execute complete detection workflow.

    Workflow
    --------
    1. Execute detection rules
    2. Aggregate alerts
    3. Assign severity levels
    4. Persist alerts to database
    5. Correlate incidents
    6. Generate attack timeline
    7. Generate detection statistics
    8. Extract Indicators of Compromise

    Returns
    -------
    dict
        Aggregated detection results
    """

    logger.info("Detection engine started")

    # ---------------------------------------------------------
    # Reset Previous Detection Results
    # ---------------------------------------------------------

    reset_alerts_db()

    # ---------------------------------------------------------
    # Alert Container
    # ---------------------------------------------------------

    alerts = []

    # ---------------------------------------------------------
    # Execute Detection Rules
    # ---------------------------------------------------------

    alerts.extend(detect_brute_force())

    alerts.extend(detect_port_scans())

    alerts.extend(detect_web_injections())

    alerts.extend(detect_http_spikes())

    alerts.extend(detect_linux_auth_failures())

    alerts.extend(detect_hdfs_errors())

    logger.info(f"Total alerts generated: {len(alerts)}")

    # ---------------------------------------------------------
    # Severity Classification & Persistence
    # ---------------------------------------------------------

    for alert in alerts:

        # ---------------------------------------------------------
        # Assign Severity Classification
        # ---------------------------------------------------------

        alert_type = alert.get("type", "unknown")

        alert["severity"] = assign_severity(alert_type)

        # ---------------------------------------------------------
        # Ensure Required Fields Exist
        # ---------------------------------------------------------

        alert.setdefault("timestamp", None)

        alert.setdefault("source_ip", None)

        alert.setdefault(
            "description",
            alert.get("details", "Detection event")
        )

        # ---------------------------------------------------------
        # Persist Alert
        # ---------------------------------------------------------

        insert_alert(alert)

    # ---------------------------------------------------------
    # Event Correlation
    # ---------------------------------------------------------

    incidents = correlate_events(alerts)

    # ---------------------------------------------------------
    # Timeline Generation
    # ---------------------------------------------------------

    timeline = build_timeline(alerts)

    # ---------------------------------------------------------
    # Detection Statistics
    # ---------------------------------------------------------

    statistics = generate_detection_statistics(alerts)

    # ---------------------------------------------------------
    # IOC Extraction
    # ---------------------------------------------------------

    iocs = extract_iocs(alerts)

    logger.info("Detection engine completed")

    # ---------------------------------------------------------
    # Return Aggregated Results
    # ---------------------------------------------------------

    return {

        "alerts": alerts,

        "incidents": incidents,

        "timeline": timeline,

        "statistics": statistics,

        "iocs": iocs

    }