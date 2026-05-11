"""
ForenSight AI - IOC Extraction Engine
====================================

Extracts Indicators of Compromise (IOCs)
from generated detection alerts and applies
basic threat scoring logic.

Responsibilities
----------------
1. Extract attacker IP addresses
2. Identify suspicious ports
3. Aggregate attack categories
4. Calculate IOC threat scores
5. Rank highest-risk indicators

Extracted IOC Categories
------------------------
• Attacker IP Addresses
• Suspicious Ports
• Attack Types
• Top Threat Indicators

Threat Scoring Factors
----------------------
• Alert frequency
• Attack diversity
• Suspicious port activity

Architecture Notes
------------------
• Designed for SOC dashboard enrichment
• Supports forensic correlation workflows
• Lightweight rule-based threat prioritization
"""

import re

from collections import Counter


# ---------------------------------------------------------
# THREAT SEVERITY CLASSIFICATION
# ---------------------------------------------------------

def classify_score(score):
    """
    Convert numeric threat score into severity level.

    Parameters
    ----------
    score : int
        Calculated threat score

    Returns
    -------
    str
        Severity classification
    """

    if score >= 80:
        return "CRITICAL"

    elif score >= 60:
        return "HIGH"

    elif score >= 40:
        return "MEDIUM"

    return "LOW"


# ---------------------------------------------------------
# IOC EXTRACTION ENGINE
# ---------------------------------------------------------

def extract_iocs(alerts):
    """
    Extract Indicators of Compromise (IOCs)
    from generated alerts.

    Parameters
    ----------
    alerts : list
        Detection alert objects

    Returns
    -------
    dict
        Aggregated IOC intelligence
    """

    attacker_ips = []

    suspicious_ports = set()

    attack_types = set()

    # ---------------------------------------------------------
    # Extract IOC Data
    # ---------------------------------------------------------

    for alert in alerts:

        # ---------------------------------------------------------
        # Source IP Extraction
        # ---------------------------------------------------------

        ip = alert.get("source_ip")

        if ip:
            attacker_ips.append(ip)

        # ---------------------------------------------------------
        # Attack Type Extraction
        # ---------------------------------------------------------

        attack_type = alert.get("type")

        if attack_type:
            attack_types.add(attack_type)

        # ---------------------------------------------------------
        # Port Extraction
        # ---------------------------------------------------------

        details = alert.get("details")

        if details:

            ports = re.findall(r"\d+", str(details))

            for port in ports:

                try:

                    port_int = int(port)

                    # Validate valid TCP/UDP range
                    if 0 <= port_int <= 65535:
                        suspicious_ports.add(port_int)

                except ValueError:
                    continue

    # ---------------------------------------------------------
    # Threat Scoring
    # ---------------------------------------------------------

    ip_counts = Counter(attacker_ips)

    threat_scores = []

    for ip, count in ip_counts.items():

        score = 0

        # ---------------------------------------------------------
        # Frequency-Based Weighting
        # ---------------------------------------------------------

        if count > 10:
            score += 40

        elif count > 5:
            score += 30

        else:
            score += 10

        # ---------------------------------------------------------
        # Attack Diversity Weighting
        # ---------------------------------------------------------

        if any(
            t in ["injection", "brute_force"]
            for t in attack_types
        ):
            score += 30

        # ---------------------------------------------------------
        # Suspicious Port Activity Weighting
        # ---------------------------------------------------------

        if suspicious_ports:
            score += 20

        # ---------------------------------------------------------
        # Cap Maximum Score
        # ---------------------------------------------------------

        score = min(score, 100)

        threat_scores.append({

            "ip": ip,

            "score": score,

            "severity": classify_score(score)

        })

    # ---------------------------------------------------------
    # Sort Highest Risk Indicators
    # ---------------------------------------------------------

    threat_scores.sort(
        key=lambda x: x["score"],
        reverse=True
    )

    # ---------------------------------------------------------
    # Return Aggregated IOC Intelligence
    # ---------------------------------------------------------

    return {

        "attacker_ips": sorted(set(attacker_ips)),

        "suspicious_ports": sorted(
            list(suspicious_ports)
        ),

        "attack_types": sorted(
            list(attack_types)
        ),

        "top_threats": threat_scores[:5]

    }