"""
ForenSight AI - IOC Enrichment Engine
=====================================

Extracts and enriches Indicators of Compromise (IOCs)
for AI analysis, GUI presentation and reporting.

Responsibilities
----------------
1. Extract attacker IP addresses
2. Extract usernames and endpoints
3. Normalize attack categories
4. Identify suspicious ports
5. Build GUI-ready IOC intelligence

Extracted IOC Categories
------------------------
• IP Addresses
• Usernames
• Endpoints
• Attack Types
• Ports
• Timestamps

Architecture Notes
------------------
• Extends detection-layer IOC extraction
• Used by GUI and AI modules
• Supports forensic investigation workflows
"""

import re


# ---------------------------------------------------------
# IOC ENRICHMENT ENGINE
# ---------------------------------------------------------

class IOCExtractor:
    """
    Extract and enrich Indicators of Compromise.
    """

    def extract(self, detection_results: list) -> dict:
        """
        Extract Indicators of Compromise (IOCs).

        Parameters
        ----------
        detection_results : list
            Detection alerts or incidents

        Returns
        -------
        dict
            Structured IOC intelligence
        """

        # ---------------------------------------------------------
        # IOC Containers
        # ---------------------------------------------------------

        iocs = {

            "ips": set(),

            "usernames": set(),

            "endpoints": set(),

            "timestamps": set(),

            "attack_types": set(),

            "ports": set()

        }

        # ---------------------------------------------------------
        # Process Detection Results
        # ---------------------------------------------------------

        for incident in detection_results:

            # ---------------------------------------------------------
            # IP Address Extraction
            # ---------------------------------------------------------

            ip = incident.get("source_ip")

            if ip:
                iocs["ips"].add(ip)

            # ---------------------------------------------------------
            # Username Extraction
            # ---------------------------------------------------------

            user = (

                incident.get("username")

                or incident.get("target_user")

            )

            if user:
                iocs["usernames"].add(user)

            # ---------------------------------------------------------
            # Endpoint Extraction
            # ---------------------------------------------------------

            endpoint = incident.get("endpoint")

            if endpoint:
                iocs["endpoints"].add(endpoint)

            # ---------------------------------------------------------
            # Timestamp Extraction
            # ---------------------------------------------------------

            if incident.get("start_time"):

                iocs["timestamps"].add(
                    incident["start_time"]
                )

            if incident.get("end_time"):

                iocs["timestamps"].add(
                    incident["end_time"]
                )

            if incident.get("timestamp"):

                iocs["timestamps"].add(
                    incident["timestamp"]
                )

            # ---------------------------------------------------------
            # Attack Type Extraction
            # ---------------------------------------------------------

            attack_type = incident.get("type")

            if attack_type:

                iocs["attack_types"].add(

                    attack_type
                    .replace("_", " ")
                    .title()

                )

            # ---------------------------------------------------------
            # Suspicious Port Extraction
            # ---------------------------------------------------------

            details = (

                incident.get("description")

                or incident.get("details")

            )

            if details:

                numbers = re.findall(
                    r"\d+",
                    str(details)
                )

                for num in numbers:

                    try:

                        port = int(num)

                        # Valid TCP/UDP Port Range
                        if 0 <= port <= 65535:

                            iocs["ports"].add(port)

                    except ValueError:
                        continue

        # ---------------------------------------------------------
        # Normalize IOC Output
        # ---------------------------------------------------------

        return {

            key: sorted(list(values))

            for key, values in iocs.items()

        }