"""
Detection System Integration Test
=================================

This script tests the entire detection module of the
ForenSight AI project.

Components Tested
-----------------
1. Rule-based detection modules
2. Anomaly detection
3. Event correlation
4. Attack timeline reconstruction
5. Detection statistics
6. IOC extraction
7. Full detection engine

This provides a full verification of the Member-2
Detection Engine implementation.
"""
import sys
import os

# Add project root directory to Python path
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)

# -----------------------------------------------------
# Import Rule Detection Modules
# -----------------------------------------------------

from src.detection.rules.brute_force import detect_brute_force
from src.detection.rules.scanning_detection import detect_port_scans
from src.detection.rules.injection_detection import detect_web_injections
from src.detection.rules.http_anomalies import detect_http_spikes
from src.detection.rules.linux_auth_detection import detect_linux_auth_failures
from src.detection.rules.hdfs_error_detection import detect_hdfs_errors

# -----------------------------------------------------
# Import Anomaly Detection
# -----------------------------------------------------

from src.detection.anomaly_detection.isolation_forest import run_isolation_forest

# -----------------------------------------------------
# Import Correlation Engine
# -----------------------------------------------------

from src.detection.correlation.event_correlator import correlate_events

# -----------------------------------------------------
# Import Timeline Builder
# -----------------------------------------------------

from src.gui.timeline_service import build_timeline

# -----------------------------------------------------
# Import Detection Statistics
# -----------------------------------------------------

from src.detection.statistics.detection_statistics import generate_detection_statistics

# -----------------------------------------------------
# Import IOC Extraction
# -----------------------------------------------------

from src.detection.ioc_extraction.ioc_extractor import extract_iocs

# -----------------------------------------------------
# Import Full Detection Engine
# -----------------------------------------------------

from src.detection.detection_engine import run_detection_engine


def run_detection_tests():

    print("\n===============================")
    print("RULE DETECTION TESTS")
    print("===============================")

    print("\nBrute Force Detection")
    print(detect_brute_force())

    print("\nPort Scan Detection")
    print(detect_port_scans())

    print("\nWeb Injection Detection")
    print(detect_web_injections())

    print("\nHTTP Anomaly Detection")
    print(detect_http_spikes())

    print("\nLinux Authentication Detection")
    print(detect_linux_auth_failures())

    print("\nHDFS Error Detection")
    print(detect_hdfs_errors())

    print("\n===============================")
    print("ANOMALY DETECTION TEST")
    print("===============================")

    anomalies = run_isolation_forest()
    print(anomalies)

    print("\n===============================")
    print("CORRELATION ENGINE TEST")
    print("===============================")

    sample_alerts = [
        {"type": "Port Scan", "source_ip": "192.168.1.20"},
        {"type": "Brute Force Attack", "source_ip": "10.0.0.5"}
    ]

    incidents = correlate_events(sample_alerts)

    for incident in incidents:
        print(incident)

    print("\n===============================")
    print("TIMELINE GENERATION TEST")
    print("===============================")

    # Get alerts from detection engine
    results = run_detection_engine()
    alerts = results["alerts"]

    timeline = build_timeline(alerts)

    for event in timeline[:10]:
        print(event)

    print("\n===============================")
    print("STATISTICS TEST")
    print("===============================")

    stats = generate_detection_statistics(alerts)
    
    print(stats)

    print("\n===============================")
    print("IOC EXTRACTION TEST")
    print("===============================")

    sample_alerts = [
        {"type": "Port Scan", "source_ip": "192.168.1.20", "details": "Port 22"},
        {"type": "Brute Force Attack", "source_ip": "10.0.0.5", "details": "Port 80"}
    ]

    iocs = extract_iocs(sample_alerts)

    print(iocs)

    print("\n===============================")
    print("FULL DETECTION ENGINE TEST")
    print("===============================")

    results = run_detection_engine()

    print("\nAlerts")
    for alert in results["alerts"]:
        print(alert)

    print("\nIncidents")
    for incident in results["incidents"]:
        print(incident)

    print("\nStatistics")
    print(results["statistics"])

    print("\nIOCs")
    print(results["iocs"])


if __name__ == "__main__":
    run_detection_tests()