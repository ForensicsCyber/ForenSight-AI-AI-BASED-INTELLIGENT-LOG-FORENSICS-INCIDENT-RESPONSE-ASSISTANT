"""
ForenSight AI - Log Ingestion Pipeline
=====================================

Centralized ingestion engine responsible for processing
raw security logs into normalized forensic records.

Responsibilities
----------------
1. Detect and process supported log formats
2. Normalize heterogeneous log datasets
3. Validate parsed log integrity
4. Insert structured records into SQLite
5. Maintain ingestion statistics and logging

Supported Datasets
------------------
• Apache Logs
• Linux System Logs
• OpenSSH Logs
• HDFS Logs
• Firewall / Network Flow Logs

Database
--------
structured_logs.db

Architecture Notes
------------------
• Supports both development and packaged (.exe) execution
• Uses centralized runtime dataset storage
• Designed for forensic consistency and SOC workflows
"""

import logging
import os
import sqlite3

from src.ingestion.apache_parser import parse_apache_file
from src.ingestion.firewall_parser import parse_firewall_csv
from src.ingestion.hdfs_parser import parse_hdfs_file
from src.ingestion.linux_parser import parse_linux_file
from src.ingestion.openssh_parser import parse_openssh_file

from src.utils.logger_config import setup_logger
from src.utils.db_utils import LOG_DB_PATH


# ---------------------------------------------------------
# LOGGER INITIALIZATION
# ---------------------------------------------------------

logger = setup_logger()


# ---------------------------------------------------------
# DATABASE INITIALIZATION
# ---------------------------------------------------------

def initialize_database():
    """
    Ensure structured logs table exists.
    """

    conn = sqlite3.connect(LOG_DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            username TEXT,
            request_method TEXT,
            endpoint TEXT,
            status_code TEXT,
            message TEXT,
            log_type TEXT
        )
    """)

    conn.commit()
    conn.close()


# ---------------------------------------------------------
# DATABASE RESET
# ---------------------------------------------------------

def reset_database():
    """
    Clear existing structured logs before new ingestion.
    """

    conn = sqlite3.connect(LOG_DB_PATH)
    cursor = conn.cursor()

    try:

        cursor.execute("""
            SELECT name
            FROM sqlite_master
            WHERE type='table'
            AND name='logs'
        """)

        if cursor.fetchone():

            cursor.execute("DELETE FROM logs")

            cursor.execute("""
                DELETE FROM sqlite_sequence
                WHERE name='logs'
            """)

    except Exception as e:
        logger.warning(f"Could not clear logs table: {e}")

    conn.commit()
    conn.close()

    logger.info("Database reset completed")


# ---------------------------------------------------------
# LOG VALIDATION
# ---------------------------------------------------------

def validate_log(log):
    """
    Validate parsed log before database insertion.

    Parameters
    ----------
    log : dict
        Parsed normalized log event

    Returns
    -------
    bool
        Validation result
    """

    if log["timestamp"] is None:
        return False

    if log["message"] is None or log["message"] == "":
        return False

    if log["log_type"] is None:
        return False

    return True


# ---------------------------------------------------------
# DATABASE INSERTION
# ---------------------------------------------------------

def insert_logs(logs):
    """
    Insert normalized logs into SQLite database.

    Parameters
    ----------
    logs : list
        Parsed normalized log records
    """

    conn = sqlite3.connect(LOG_DB_PATH)
    cursor = conn.cursor()

    inserted_count = 0

    for log in logs:

        if not validate_log(log):
            continue

        cursor.execute(
            """
            INSERT INTO logs (
                timestamp,
                source_ip,
                destination_ip,
                username,
                request_method,
                endpoint,
                status_code,
                message,
                log_type
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(log["timestamp"]),
                log["source_ip"],
                log["destination_ip"],
                log["username"],
                log["request_method"],
                log["endpoint"],
                log["status_code"],
                log["message"],
                log["log_type"],
            ),
        )

        inserted_count += 1

    conn.commit()
    conn.close()

    logger.info(f"{inserted_count} logs inserted into database")


# ---------------------------------------------------------
# DATASET STATISTICS
# ---------------------------------------------------------

def print_statistics():
    """
    Display structured log statistics grouped by log type.
    """

    conn = sqlite3.connect(LOG_DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT log_type, COUNT(*)
        FROM logs
        GROUP BY log_type
    """)

    results = cursor.fetchall()

    print("\nDataset Statistics")
    print("------------------")

    for row in results:
        print(f"{row[0]} : {row[1]} logs")

    conn.close()


# ---------------------------------------------------------
# MAIN INGESTION PIPELINE
# ---------------------------------------------------------

def ingest_logs(file_routes):
    """
    Process uploaded log files and insert normalized
    records into the forensic database.

    Parameters
    ----------
    file_routes : dict
        Mapping of file paths to detected log types
    """

    logger.info("Starting log ingestion...")

    all_logs = []

    # ---------------------------------------------------------
    # Process Uploaded Files
    # ---------------------------------------------------------

    for file_path, log_type in file_routes.items():

        try:

            logger.info(f"{file_path} → {log_type}")

            # ---------------------------------------------------------
            # Apache Logs
            # ---------------------------------------------------------

            if log_type == "apache":
                logs = parse_apache_file(file_path)

            # ---------------------------------------------------------
            # Firewall Logs
            # ---------------------------------------------------------

            elif log_type == "firewall":
                logs = parse_firewall_csv(file_path)

            # ---------------------------------------------------------
            # HDFS Logs
            # ---------------------------------------------------------

            elif log_type == "hdfs":
                logs = parse_hdfs_file(file_path)

            # ---------------------------------------------------------
            # Linux Logs
            # ---------------------------------------------------------

            elif log_type == "linux":
                logs = parse_linux_file(file_path)

            # ---------------------------------------------------------
            # OpenSSH Logs
            # ---------------------------------------------------------

            elif log_type == "openssh":
                logs = parse_openssh_file(file_path)

            else:
                logger.warning(
                    f"Unsupported log file skipped: {file_path}"
                )
                continue

            all_logs.extend(logs)

        except Exception as e:
            logger.error(
                f"Error processing file {file_path}: {e}"
            )

    # ---------------------------------------------------------
    # Validation Check
    # ---------------------------------------------------------

    if not all_logs:
        logger.warning(
            "No logs were parsed from the provided files."
        )
        return

    logger.info(f"Total logs parsed: {len(all_logs)}")

    # ---------------------------------------------------------
    # Ensure Database Exists
    # ---------------------------------------------------------

    initialize_database()

    # ---------------------------------------------------------
    # Reset Existing Dataset
    # ---------------------------------------------------------

    try:
        reset_database()

    except Exception as e:
        logger.warning(
            f"Database reset failed: {e}"
        )

    # ---------------------------------------------------------
    # Insert Parsed Logs
    # ---------------------------------------------------------

    try:

        insert_logs(all_logs)

        logger.info(
            "Logs successfully inserted into database."
        )

    except Exception as e:

        logger.error(
            f"Failed to insert logs: {e}"
        )

    logger.info("Log ingestion completed.")