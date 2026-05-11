"""
ForenSight AI - Recommendation Engine
=====================================

Hybrid recommendation engine combining:

1. Rule-based remediation guidance
2. AI-generated security recommendations

Purpose
-------
Provides actionable defensive recommendations
based on detected attack activity.

Responsibilities
----------------
• Generate deterministic remediation guidance
• Generate AI-assisted recommendations
• Merge and normalize recommendation output
• Remove duplicate recommendations
• Support reporting and GUI workflows

Architecture Notes
------------------
• Compatible with local Ollama execution
• Supports legacy and modern alert schemas
• Designed for SOC-style remediation workflows
"""

from src.ai_engine.llm_interface import LocalLLM

from src.ai_engine.prompt_builder import (
    build_recommendation_prompt
)


# ---------------------------------------------------------
# RECOMMENDATION ENGINE
# ---------------------------------------------------------

class RecommendationEngine:
    """
    Hybrid recommendation generation engine.
    """

    def __init__(self):
        """
        Initialize local LLM interface.
        """

        self.llm = LocalLLM()

    # ---------------------------------------------------------
    # MAIN ENTRY FUNCTION
    # ---------------------------------------------------------

    def generate(self, detection_results: list) -> list:
        """
        Generate combined remediation recommendations.

        Parameters
        ----------
        detection_results : list
            Detection alerts or incidents

        Returns
        -------
        list
            Combined recommendation list
        """

        # ---------------------------------------------------------
        # Rule-Based Recommendations
        # ---------------------------------------------------------

        rule_recommendations = self._generate_rule_based(
            detection_results
        )

        # ---------------------------------------------------------
        # AI-Based Recommendations
        # ---------------------------------------------------------

        ai_recommendations = self._generate_ai_recommendations(
            detection_results
        )

        # ---------------------------------------------------------
        # Merge & Deduplicate
        # ---------------------------------------------------------

        final_recommendations = self._merge_recommendations(

            rule_recommendations,

            ai_recommendations

        )

        return final_recommendations

    # ---------------------------------------------------------
    # RULE-BASED RECOMMENDATIONS
    # ---------------------------------------------------------

    def _generate_rule_based(self, detection_results):
        """
        Generate deterministic remediation guidance.

        Parameters
        ----------
        detection_results : list

        Returns
        -------
        list
        """

        recommendations = []

        for incident in detection_results:

            incident_type = incident.get("type", "")

            # ---------------------------------------------------------
            # Brute Force Attacks
            # ---------------------------------------------------------

            if incident_type in [
                "brute_force",
                "Brute Force Attack",
                "Linux Authentication Attack"
            ]:

                recommendations.append(
                    "Implement account lockout policies "
                    "and enable multi-factor authentication."
                )

                recommendations.append(
                    "Monitor authentication logs for repeated "
                    "failed login attempts."
                )

            # ---------------------------------------------------------
            # Web Injection Attacks
            # ---------------------------------------------------------

            elif incident_type in [
                "injection",
                "Web Injection"
            ]:

                recommendations.append(
                    "Validate and sanitize all user inputs "
                    "to prevent injection attacks."
                )

                recommendations.append(
                    "Deploy a Web Application Firewall (WAF) "
                    "to detect and block malicious requests."
                )

            # ---------------------------------------------------------
            # Traffic Anomalies
            # ---------------------------------------------------------

            elif incident_type in [
                "anomaly",
                "HTTP Traffic Spike"
            ]:

                recommendations.append(
                    "Review traffic logs and implement "
                    "rate-limiting controls where necessary."
                )

                recommendations.append(
                    "Investigate unusual request spikes "
                    "for potential denial-of-service activity."
                )

            # ---------------------------------------------------------
            # Port Scanning Activity
            # ---------------------------------------------------------

            elif incident_type in [
                "scan",
                "Port Scan"
            ]:

                recommendations.append(
                    "Deploy firewall rules or intrusion "
                    "detection systems to block scanning activity."
                )

                recommendations.append(
                    "Restrict unnecessary exposed ports "
                    "and services."
                )

            # ---------------------------------------------------------
            # HDFS System Errors
            # ---------------------------------------------------------

            elif incident_type in [
                "HDFS System Error"
            ]:

                recommendations.append(
                    "Review HDFS system logs and investigate "
                    "abnormal operational failures."
                )

                recommendations.append(
                    "Ensure proper Hadoop cluster monitoring "
                    "and fault tolerance mechanisms."
                )

        # ---------------------------------------------------------
        # Remove Duplicates
        # ---------------------------------------------------------

        return list(set(recommendations))

    # ---------------------------------------------------------
    # AI-BASED RECOMMENDATIONS
    # ---------------------------------------------------------

    def _generate_ai_recommendations(self, detection_results):
        """
        Generate AI-assisted remediation guidance.

        Parameters
        ----------
        detection_results : list

        Returns
        -------
        list
        """

        try:

            # ---------------------------------------------------------
            # Normalize Input Structure
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

            prompt = build_recommendation_prompt(
                structured_input
            )

            # ---------------------------------------------------------
            # Generate AI Response
            # ---------------------------------------------------------

            raw_output = self.llm.generate(prompt)

            # ---------------------------------------------------------
            # Normalize AI Output
            # ---------------------------------------------------------

            return self._clean_ai_output(raw_output)

        except Exception as e:

            return [
                f"AI recommendations unavailable: {str(e)}"
            ]

    # ---------------------------------------------------------
    # CLEAN AI OUTPUT
    # ---------------------------------------------------------

    def _clean_ai_output(self, text):
        """
        Normalize AI-generated recommendations.

        Parameters
        ----------
        text : str

        Returns
        -------
        list
        """

        if not text:
            return []

        lines = text.split("\n")

        cleaned = []

        for line in lines:

            line = line.strip()

            if not line:
                continue

            # ---------------------------------------------------------
            # Remove Markdown Artifacts
            # ---------------------------------------------------------

            line = line.replace("*", "")
            line = line.replace("•", "")

            # ---------------------------------------------------------
            # Remove Numeric Bullet Prefixes
            # ---------------------------------------------------------

            if line[0].isdigit():

                line = line.split(".", 1)[-1].strip()

            cleaned.append(line)

        return cleaned

    # ---------------------------------------------------------
    # MERGE RECOMMENDATIONS
    # ---------------------------------------------------------

    def _merge_recommendations(
        self,
        rule_recs,
        ai_recs
    ):
        """
        Merge rule-based and AI-generated recommendations.

        Parameters
        ----------
        rule_recs : list
        ai_recs : list

        Returns
        -------
        list
        """

        combined = []

        # ---------------------------------------------------------
        # Add Rule-Based Recommendations First
        # ---------------------------------------------------------

        for rec in rule_recs:

            if rec not in combined:

                combined.append(rec)

        # ---------------------------------------------------------
        # Add AI Recommendations
        # ---------------------------------------------------------

        for rec in ai_recs:

            if rec not in combined:

                combined.append(rec)

        return combined