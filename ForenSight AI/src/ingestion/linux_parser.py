"""
Linux System Log Parser
-----------------------

Parses Linux system logs used for authentication monitoring.

Example:
Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure

Reference:
LogHub Dataset – https://github.com/logpai/loghub/blob/master/Linux/Linux_2k.log
"""

import re                      # Used for pattern matching with regular expressions
from datetime import datetime  # Used to convert string timestamps into datetime objects


def parse_linux_line(line):

    # Regex to extract timestamp and message
    pattern = r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+(.*)"

    match = re.match(pattern, line)

    if not match:
        return None

    timestamp_str, message = match.groups()

    try:
        timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
    except ValueError:
        timestamp = None

    # Extract IP address if present
    ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", message)
    source_ip = ip_match.group(1) if ip_match else None

    # Extract username
    user_match = re.search(r"user=(\w+)", message)
    username = user_match.group(1) if user_match else None

    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": None,
        "username": username,
        "request_method": None,
        "endpoint": None,
        "status_code": None,
        "message": message,
        "log_type": "linux"
    }


def parse_linux_file(file_path):

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
            parsed = parse_linux_line(line)

            # Append valid parsed logs to list
            if parsed:
                parsed_logs.append(parsed)

    return parsed_logs