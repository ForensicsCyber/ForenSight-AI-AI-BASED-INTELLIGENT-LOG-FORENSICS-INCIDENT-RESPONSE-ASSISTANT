"""
AISummarizer – Unified AI + Structured Summarizer
=================================================

Combines:
• Rule-based structured detection summaries
• AI-generated incident summaries
• Timeline generation
• Severity assessment

Used By
-------
• GUI Dashboard
• AI Engine
• PDF Reporting

Architecture Notes
------------------
• Supports both legacy and modern alert schemas
• Compatible with current detection engine
• Designed for SOC-style reporting workflows
"""

from src.ai_engine.llm_interface import LocalLLM
from src.ai_engine.prompt_builder import build_summary_prompt


class AISummarizer:
    """
    Unified summarizer combining structured logic
    with AI-generated cybersecurity analysis.
    """

    def __init__(self):
        """
        Initialize local LLM interface.
        """

        self.llm = LocalLLM()

    # ---------------------------------------------------------
    # MAIN SUMMARY FUNCTION
    # ---------------------------------------------------------

    def summarize(self, detection_results: list) -> dict:
        """
        Generate structured and AI-enhanced summaries.

        Parameters
        ----------
        detection_results : list
            Detection alert objects

        Returns
        -------
        dict
            Structured summary output
        """

        summary_lines = []

        incident_types = set()

        structured_incidents = []

        timeline = []

        # ---------------------------------------------------------
        # Process Detection Results
        # ---------------------------------------------------------

        for incident in detection_results:

            incident_type = incident.get("type", "Unknown")

            incident_types.add(incident_type)

            severity = self._calculate_incident_severity(
                incident
            )

            description = self._build_description(
                incident
            )

            summary_lines.append(description)

            structured_incidents.append({

                "type": incident_type,

                "severity": severity,

                "description": description,

                "source_ip": incident.get("source_ip"),

                "timestamp_range": (
                    f"{incident.get('start_time')} - "
                    f"{incident.get('end_time')}"
                )

            })

            # ---------------------------------------------------------
            # Timeline Construction
            # ---------------------------------------------------------

            if incident.get("start_time"):

                timeline.append({

                    "timestamp": incident["start_time"],

                    "event": description

                })

            elif incident.get("timestamp"):

                timeline.append({

                    "timestamp": incident["timestamp"],

                    "event": description

                })

        # ---------------------------------------------------------
        # Chronological Timeline Sorting
        # ---------------------------------------------------------

        timeline = sorted(

            timeline,

            key=lambda x: x["timestamp"]

        )

        # ---------------------------------------------------------
        # AI Summary Generation
        # ---------------------------------------------------------

        ai_summary = self._generate_ai_summary(
            detection_results
        )

        # ---------------------------------------------------------
        # Return Summary Package
        # ---------------------------------------------------------

        return {

            "summary_text": "\n\n".join(summary_lines),

            "ai_summary": ai_summary,

            "incident_count": len(detection_results),

            "incident_types": list(incident_types),

            "overall_severity": (
                self._calculate_overall_severity(
                    detection_results
                )
            ),

            "incidents": structured_incidents,

            "timeline": timeline

        }

    # ---------------------------------------------------------
    # INCIDENT DESCRIPTION BUILDER
    # ---------------------------------------------------------

    def _build_description(self, incident):
        """
        Build human-readable incident description.

        Parameters
        ----------
        incident : dict

        Returns
        -------
        str
        """

        incident_type = incident.get("type", "")

        # ---------------------------------------------------------
        # Brute Force / Linux Authentication
        # ---------------------------------------------------------

        if incident_type in [

            "brute_force",

            "Brute Force Attack",

            "Linux Authentication Attack"

        ]:

            return (

                f"Repeated authentication failures "

                f"originating from "

                f"{incident.get('source_ip', 'unknown')} "

                f"targeting user "

                f"{incident.get('username', 'unknown')} "

                f"with "

                f"{incident.get('attempts', 0)} "

                f"failed attempts."

            )

        # ---------------------------------------------------------
        # HTTP / HDFS Anomalies
        # ---------------------------------------------------------

        elif incident_type in [

            "anomaly",

            "HTTP Traffic Spike",

            "HDFS System Error"

        ]:

            return (

                f"Suspicious anomalous activity detected: "

                f"{incident.get('details', 'Unknown anomaly')}."

            )

        # ---------------------------------------------------------
        # Web Injection
        # ---------------------------------------------------------

        elif incident_type in [

            "injection",

            "Web Injection"

        ]:

            return (

                f"Potential web injection activity "

                f"detected from "

                f"{incident.get('source_ip', 'unknown')} "

                f"targeting endpoint "

                f"{incident.get('endpoint', 'unknown')}."

            )

        # ---------------------------------------------------------
        # Port Scanning
        # ---------------------------------------------------------

        elif incident_type in [

            "scan",

            "Port Scan"

        ]:

            return (

                f"Reconnaissance or port scanning "

                f"activity detected from "

                f"{incident.get('source_ip', 'unknown')}."

            )

        # ---------------------------------------------------------
        # Generic Fallback
        # ---------------------------------------------------------

        return (

            f"Suspicious activity detected from "

            f"{incident.get('source_ip', 'unknown')}."

        )

    # ---------------------------------------------------------
    # AI SUMMARY GENERATION
    # ---------------------------------------------------------

    def _generate_ai_summary(self, detection_results):
        """
        Generate AI-powered cybersecurity summary.

        Parameters
        ----------
        detection_results : list or dict

        Returns
        -------
        str
        """

        try:

            # ---------------------------------------------------------
            # Normalize Detection Input
            # ---------------------------------------------------------

            if isinstance(detection_results, list):

                structured_input = {

                    "alerts": detection_results

                }

            else:

                structured_input = detection_results

            # ---------------------------------------------------------
            # Build Prompt
            # ---------------------------------------------------------

            prompt = build_summary_prompt(
                structured_input
            )

            # ---------------------------------------------------------
            # Generate AI Response
            # ---------------------------------------------------------

            raw_output = self.llm.generate(prompt)

            return self._clean_ai_text(raw_output)

        except Exception as e:

            return f"AI summary unavailable: {str(e)}"

    # ---------------------------------------------------------
    # AI OUTPUT CLEANER
    # ---------------------------------------------------------

    def _clean_ai_text(self, text):
        """
        Clean formatting artifacts from AI output.

        Parameters
        ----------
        text : str

        Returns
        -------
        str
        """

        if not text:
            return ""

        text = text.replace("**", "")

        text = text.replace("*", "")

        text = text.replace("•", "")

        return text.strip()

    # ---------------------------------------------------------
    # INCIDENT SEVERITY CALCULATION
    # ---------------------------------------------------------

    def _calculate_incident_severity(
        self,
        incident: dict
    ) -> str:
        """
        Calculate incident severity classification.

        Parameters
        ----------
        incident : dict

        Returns
        -------
        str
        """

        incident_type = incident.get("type", "")

        # ---------------------------------------------------------
        # Critical / High Severity
        # ---------------------------------------------------------

        if incident_type in [

            "injection",

            "Web Injection"

        ]:

            return "high"

        # ---------------------------------------------------------
        # Medium Severity
        # ---------------------------------------------------------

        if incident_type in [

            "brute_force",

            "Brute Force Attack",

            "Linux Authentication Attack"

        ]:

            return "medium"

        if incident_type == "Port Scan":

            return "medium"

        if incident_type == "HDFS System Error":

            return "medium"

        # ---------------------------------------------------------
        # Low Severity
        # ---------------------------------------------------------

        if incident_type == "HTTP Traffic Spike":

            return "low"

        return "low"

    # ---------------------------------------------------------
    # OVERALL SEVERITY CALCULATION
    # ---------------------------------------------------------

    def _calculate_overall_severity(
        self,
        detection_results: list
    ) -> str:
        """
        Calculate overall incident severity.

        Parameters
        ----------
        detection_results : list

        Returns
        -------
        str
        """

        severities = [

            self._calculate_incident_severity(i)

            for i in detection_results

        ]

        if "high" in severities:
            return "high"

        if "medium" in severities:
            return "medium"

        return "low"