"""
Smart Log Classifier (Production Grade)
======================================

✔ Content-based detection
✔ Multi-pattern matching
✔ Confidence scoring
✔ Robust against noisy logs
"""

import re

class LogClassifier:

    def __init__(self):
        pass

    # ---------------------------------------------------------
    # MAIN ENTRY
    # ---------------------------------------------------------
    def classify(self, file_path):
        try:
            with open(file_path, "r", errors="ignore") as f:
                sample = f.read(4000).lower()

            
            scores = {
                "apache": self._score_apache(sample),
                "linux": self._score_linux(sample),
                "openssh": self._score_openssh(sample),
                "hdfs": self._score_hdfs(sample),
                "firewall": self._score_firewall(sample)
            }

            if scores["firewall"] < 4:
                scores["firewall"] = 0

            # Pick best match
            log_type = max(scores, key=scores.get)

            if all(score == 0 for score in scores.values()):
                return "unknown"

            # -----------------------------------
            # STRICT VALIDATION (STRONG SIGNAL REQUIRED)
            # -----------------------------------

            strong_signals = {
                "apache": scores["apache"] >= 3,
                "linux": scores["linux"] >= 4,
                "openssh": scores["openssh"] >= 3,
                "hdfs": scores["hdfs"] >= 3,
                "firewall": scores["firewall"] >= 3,
            }

            # If detected type does NOT meet strong signal → reject
            if not strong_signals.get(log_type, False):
                return "unknown"

            # -----------------------------------
            # PRIORITY RULES (ORDER MATTERS)
            # -----------------------------------

            # OpenSSH (very distinct)
            if scores["openssh"] >= 3:
                return "openssh"

            # HDFS (unique keywords)
            if scores["hdfs"] >= 3:
                return "hdfs"

            # Firewall (CSV + IP structure)
            if scores["firewall"] >= 3:
                return "firewall"

            # Apache (error logs / modules)
            if scores["apache"] >= 3:
                return "apache"

            # Linux (generic → keep last)
            if scores["linux"] >= 3:
                return "linux"

            # -----------------------------------
            # FALLBACK
            # -----------------------------------
            return log_type

        except Exception:
            return "unknown"

    # ---------------------------------------------------------
    # APACHE LOG DETECTION
    # ---------------------------------------------------------
    def _score_apache(self, text):
        score = 0

        # 🔥 Apache ERROR LOG TIMESTAMP FORMAT
        if re.search(r'\[[a-z]{3}\s+[a-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}\]', text):
            score += 3

        # Log levels typical in Apache
        if re.search(r'\[(notice|error|warn|info|debug)\]', text):
            score += 3

        # Apache module indicators
        if "mod_jk" in text or "workerenv" in text or "jk2_init" in text:
            score += 3

        # Apache config paths
        if "/etc/httpd" in text or "apache" in text:
            score += 1

        return score
    
    # ---------------------------------------------------------
    # LINUX LOG DETECTION
    # ---------------------------------------------------------
    def _score_linux(self, text):
        score = 0

        if "sudo" in text:
            score += 2

        if "cron" in text:
            score += 2

        if "session opened" in text:
            score += 1

        if re.search(r'jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec', text):
            score += 1

        if re.search(r'\b(sshd|systemd|kernel)\b', text):
            score += 2

        return score

    # ---------------------------------------------------------
    # OPENSSH LOG DETECTION
    # ---------------------------------------------------------
    def _score_openssh(self, text):
        score = 0

        # 🔥 Only count AUTH-related events (real OpenSSH signals)
        if "failed password" in text:
            score += 3

        if "accepted password" in text:
            score += 3

        if "invalid user" in text:
            score += 2

        # sshd alone is NOT enough (reduce weight)
        if "sshd" in text:
            score += 1

        # login attempts with port
        if re.search(r'port \d+', text):
            score += 1

        return score

    # ---------------------------------------------------------
    # HDFS LOG DETECTION
    # ---------------------------------------------------------
    def _score_hdfs(self, text):
        score = 0

        if "dfsclient" in text:
            score += 3

        if "namenode" in text:
            score += 2

        if "block" in text:
            score += 1

        if "datanode" in text:
            score += 2

        return score

    # ---------------------------------------------------------
    # FIREWALL LOG DETECTION (CSV)
    # ---------------------------------------------------------
    def _score_firewall(self, text):
        score = 0

        # 🔥 MUST be CSV-like (many commas)
        if text.count(",") > 20:
            score += 2

        # 🔥 Must contain multiple IP addresses (not just one)
        ip_matches = re.findall(r'\d{1,3}(\.\d{1,3}){3}', text)
        if len(ip_matches) > 5:
            score += 2

        # 🔥 Strong firewall dataset indicators (VERY IMPORTANT)
        if (
            "flow duration" in text
            or "total fwd packets" in text
            or "total backward packets" in text
            or "flow bytes/s" in text
        ):
            score += 4

        # 🔥 Port patterns (secondary signal)
        if re.search(r',\d{2,5},', text):
            score += 1

        return score