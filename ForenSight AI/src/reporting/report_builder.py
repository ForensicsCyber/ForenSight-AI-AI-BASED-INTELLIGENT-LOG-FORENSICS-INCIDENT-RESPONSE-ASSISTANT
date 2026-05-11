"""
ForenSight AI - Report Builder
==============================

Builds structured forensic report content from
detection and AI analysis results.

Responsibilities
----------------
1. Normalize AI-generated summaries
2. Normalize recommendation output
3. Extract Indicators of Compromise (IOCs)
4. Combine GUI and backend datasets
5. Build report-ready data structures

Architecture Notes
------------------
• Shared by GUI and PDF generator
• Supports hybrid AI + rule-based workflows
• Prevents malformed report content
"""

# ---------------------------------------------------------
# IOC EXTRACTION
# ---------------------------------------------------------

from src.detection.ioc_extraction.ioc_extractor import (
    extract_iocs
)


# ---------------------------------------------------------
# REPORT CONTENT BUILDER
# ---------------------------------------------------------

def build_report_content(detection_results, ai_results):
    """
    Build structured report content.

    Parameters
    ----------
    detection_results : dict
        Detection engine results

    ai_results : dict
        AI-generated analysis results

    Returns
    -------
    dict
        Structured report data
    """

    # ---------------------------------------------------------
    # Normalize AI Summary
    # ---------------------------------------------------------

    summary = ai_results.get("summary", "")

    if not isinstance(summary, str) or not summary.strip():

        summary = "AI summary unavailable"

    # ---------------------------------------------------------
    # Normalize Recommendations
    # ---------------------------------------------------------

    recommendations = ai_results.get(
        "recommendations",
        []
    )

    # Convert string → list
    if isinstance(recommendations, str):

        recommendations = recommendations.split("\n")

    # Validate recommendation structure
    if (
        not isinstance(recommendations, list)
        or not recommendations
    ):

        recommendations = [
            "AI recommendations unavailable"
        ]

    # ---------------------------------------------------------
    # Clean Recommendation Formatting
    # ---------------------------------------------------------

    cleaned_recommendations = []

    for rec in recommendations:

        rec = str(rec).strip()

        if rec:
            cleaned_recommendations.append(rec)

    # ---------------------------------------------------------
    # Detection Alerts
    # ---------------------------------------------------------

    alerts = detection_results.get("alerts", [])

    # ---------------------------------------------------------
    # IOC Extraction
    # ---------------------------------------------------------

    iocs = extract_iocs(alerts)

    # ---------------------------------------------------------
    # Optional GUI Hybrid Data
    # ---------------------------------------------------------

    timeline = detection_results.get(
        "timeline",
        []
    )

    incidents = detection_results.get(
        "incidents",
        []
    )

    threat_intel = detection_results.get(
        "threat_intel",
        []
    )

    # ---------------------------------------------------------
    # Final Report Structure
    # ---------------------------------------------------------

    return {

        "summary": summary,

        "recommendations": cleaned_recommendations,

        "alerts": alerts,

        "statistics": detection_results.get(
            "statistics",
            {}
        ),

        "iocs": iocs,

        # Hybrid GUI + Backend Data
        "timeline": timeline,

        "incidents": incidents,

        "threat_intel": threat_intel

    }