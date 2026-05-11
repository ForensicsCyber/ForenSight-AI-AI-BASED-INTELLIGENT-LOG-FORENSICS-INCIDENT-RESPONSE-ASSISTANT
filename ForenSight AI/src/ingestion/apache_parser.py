"""
Apache Log Parser
-----------------

This parser processes Apache server log entries from the LogHub dataset.
Each line is parsed and normalized into the unified event schema used
in the ForenSight AI project.

Dataset reference:
LogHub: https://github.com/logpai/loghub/blob/master/Apache/Apache_2k.log

Log format example:
[Sun Dec 04 04:47:44 2005] [notice] workerEnv.init() ok /etc/httpd/conf/workers2.properties
"""

import re                      # Used for pattern matching with regular expressions
from datetime import datetime  # Used to convert string timestamps into datetime objects


def parse_apache_line(line):
   
    # Regular expression pattern used to extract:
    # 1. timestamp
    # 2. log level
    # 3. message
    pattern = r"\[(.*?)\]\s+\[(.*?)\]\s+(.*)"

    # Attempt to match the pattern to the log line
    match = re.match(pattern, line)

    # If the log line does not match the expected pattern, skip it
    if not match:
        return None

    # Extract matched groups
    raw_timestamp, level, message = match.groups()

    try:
        # Convert Apache timestamp string into Python datetime object
        timestamp = datetime.strptime(raw_timestamp, "%a %b %d %H:%M:%S %Y")
    except ValueError:
        # If timestamp conversion fails, store None
        timestamp = None

    # Return normalized log record matching the SQLite schema
    return {
        "timestamp": timestamp,
        "source_ip": None,
        "destination_ip": None,
        "username": None,
        "request_method": None,
        "endpoint": None,
        "status_code": None,
        "message": f"{level}: {message}",
        "log_type": "apache"
    }


def parse_apache_file(file_path):
    
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
            parsed = parse_apache_line(line)

            # Append valid parsed logs to list
            if parsed:
                parsed_logs.append(parsed)

    return parsed_logs