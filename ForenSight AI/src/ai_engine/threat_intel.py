"""
ForenSight AI - Threat Intelligence Engine
==========================================

Provides enrichment capabilities for attacker
IP addresses and suspicious indicators.

Responsibilities
----------------
1. Identify private vs public IP addresses
2. Simulate threat intelligence lookups
3. Assign risk scores and severity levels
4. Enrich dashboard and reporting workflows

Current Features
----------------
• IP enrichment
• Risk scoring
• Threat classification
• Simulated intelligence feeds

Architecture Notes
------------------
• Lightweight enrichment engine
• SOC dashboard compatible
• Easily extensible for real API integration
"""

import ipaddress
import random


# ---------------------------------------------------------
# THREAT INTELLIGENCE ENGINE
# ---------------------------------------------------------

class ThreatIntel:
    """
    Threat intelligence enrichment engine.
    """

    def __init__(self):
        """
        Initialize local simulated threat database.
        """

        self.threat_database = {

            "10.0.0.5": {

                "country": "Russia",

                "score": 85

            },

            "192.168.1.100": {

                "country": "Internal Network",

                "score": 10

            },

            "172.16.0.3": {

                "country": "Private Network",

                "score": 5

            }

        }

    # ---------------------------------------------------------
    # MAIN ENRICHMENT FUNCTION
    # ---------------------------------------------------------

    def enrich_ip(self, ip):
        """
        Enrich IP address with threat intelligence data.

        Parameters
        ----------
        ip : str
            IP address to enrich

        Returns
        -------
        dict
            Enriched threat intelligence record
        """

        # ---------------------------------------------------------
        # Validate IP Address
        # ---------------------------------------------------------

        try:

            ip_obj = ipaddress.ip_address(ip)

        except ValueError:

            return {

                "ip": ip,

                "country": "Invalid IP",

                "threat_score": "UNKNOWN",

                "risk_score": 0

            }

        # ---------------------------------------------------------
        # Internal / Private Network Detection
        # ---------------------------------------------------------

        if ip_obj.is_private:

            return {

                "ip": ip,

                "country": "Internal Network",

                "threat_score": "LOW",

                "risk_score": 5

            }

        # ---------------------------------------------------------
        # Local Threat Intelligence Database
        # ---------------------------------------------------------

        if ip in self.threat_database:

            data = self.threat_database[ip]

            return {

                "ip": ip,

                "country": data["country"],

                "threat_score": self._classify_score(
                    data["score"]
                ),

                "risk_score": data["score"]

            }

        # ---------------------------------------------------------
        # Simulated Threat Intelligence Lookup
        # ---------------------------------------------------------

        return self._simulate_external_lookup(ip)

    # ---------------------------------------------------------
    # SIMULATED EXTERNAL LOOKUP
    # ---------------------------------------------------------

    def _simulate_external_lookup(self, ip):
        """
        Simulate external threat intelligence enrichment.

        Returns synthetic enrichment data to emulate
        real-world threat intelligence provider behavior.

        Parameters
        ----------
        ip : str
            Target IP address

        Returns
        -------
        dict
            Simulated threat intelligence record
        """

        countries = [

            "USA",

            "Germany",

            "China",

            "Brazil",

            "India",

            "Netherlands"

        ]

        score = random.randint(20, 90)

        return {

            "ip": ip,

            "country": random.choice(countries),

            "threat_score": self._classify_score(score),

            "risk_score": score

        }

    # ---------------------------------------------------------
    # RISK SCORE CLASSIFICATION
    # ---------------------------------------------------------

    def _classify_score(self, score):
        """
        Convert numeric risk score into severity level.

        Parameters
        ----------
        score : int
            Numeric threat score

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

        else:
            return "LOW"