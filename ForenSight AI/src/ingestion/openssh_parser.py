"""
OpenSSH Log Parser
------------------

Parses SSH authentication logs which are useful for brute-force detection.

Example:
Dec 10 06:55:46 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2

Reference:
LogHub Dataset – https://github.com/logpai/loghub/blob/master/OpenSSH/OpenSSH_2k.log
"""

import re                      # Used for pattern matching with regular expressions
from datetime import datetime  # Used to convert string timestamps into datetime objects


def parse_openssh_line(line):

    # Regex to extract timestamp and message portion
    pattern = r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd.*?:\s+(.*)"

    match = re.match(pattern, line)

    if not match:
        return None

    timestamp_str, message = match.groups()

    try:
        # Convert timestamp string into datetime object
        timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
    except ValueError:
        timestamp = None

    # Extract source IP address from message
    ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", message)
    source_ip = ip_match.group(1) if ip_match else None

    # Extract username if present
    user_match = re.search(r"user\s+(\w+)", message)
    username = user_match.group(1) if user_match else None

    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": None,
        "username": username,
        "request_method": "SSH",
        "endpoint": None,
        "status_code": None,
        "message": message,
        "log_type": "openssh"
    }


def parse_openssh_file(file_path):

    parsed_logs = []

    # Open the log file safely with UTF-8 encoding
    with open(file_path, "r", encoding="utf-8") as f:

        # Process each line individually
        for line in f:

            # Remove whitespace and newline characters
            line = line.strip()

            if not line:
                continue

            # Parse the log line
            parsed = parse_openssh_line(line)

            # Append valid parsed logs to list
            if parsed:
                parsed_logs.append(parsed)

    return parsed_logs