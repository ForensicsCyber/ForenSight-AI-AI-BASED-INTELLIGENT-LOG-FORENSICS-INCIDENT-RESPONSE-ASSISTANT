"""
HDFS Log Parser
---------------

Processes Hadoop Distributed File System logs from the LogHub dataset.

Example log format:
081109 203615 148 INFO dfs.DataNode$PacketResponder: PacketResponder 1 for block blk_38865049064139660 terminating

Reference:
LogHub Dataset – https://github.com/logpai/loghub/blob/master/HDFS/HDFS_2k.log
"""

import re                      # Used for pattern matching with regular expressions
from datetime import datetime  # Used to convert string timestamps into datetime objects


def parse_hdfs_line(line):

    # Regex pattern to extract
    # date, time, log level, and message
    pattern = r"(\d{6})\s+(\d{6})\s+\d+\s+(\w+)\s+(.*)"

    match = re.match(pattern, line)

    if not match:
        return None

    # Extract values from regex groups
    date_part, time_part, level, message = match.groups()

    try:
        # Convert combined date/time into datetime object
        timestamp = datetime.strptime(date_part + time_part, "%y%m%d%H%M%S")
    except ValueError:
        timestamp = None

    return {
        "timestamp": timestamp,
        "source_ip": None,
        "destination_ip": None,
        "username": None,
        "request_method": None,
        "endpoint": None,
        "status_code": None,
        "message": f"{level}: {message}",
        "log_type": "hdfs"
    }


def parse_hdfs_file(file_path):

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
            parsed = parse_hdfs_line(line)

            # Append valid parsed logs to list
            if parsed:
                parsed_logs.append(parsed)

    return parsed_logs