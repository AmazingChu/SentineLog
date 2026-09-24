import re
import ipaddress

from datetime import datetime


#Pattern used to extract
#IP Address, HTTP method, request path and HTTP status code, maybe more in the future
LOG_PATTERN = re.compile(
    r'^(\b(?:\d{1,3}\.){3}\d{1,3}\b).*?'
    r'\[([^\]]+)\]\s+"'
    r'(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+'
    r'(\S+)\s+HTTP/\d(?:\.\d)?"\s+(\d{3})'
)

def parse_log(log_file):
    """
    Parse an Apache-style access log.

    Args:
        log_file: path to the log file

    Returns:
        A list of dict contain parsed log entries
    """

    parse_logs = []

    with open(log_file, "r", encoding="utf-8") as file:
         for line in file:
            
            match = LOG_PATTERN.search(line)

            #This use for ignore lines that do not match the excepted log format.
            if not match:
                continue

            ip = match.group(1)
            timestamp_string = match.group(2)
            method = match.group(3)
            path = match.group(4)
            status_code = int(match.group(5))

            #Reject invalid IPv4 address such as 999.999.999.999
            try:
                ipaddress.IPv4Address(ip)

            except ValueError:
                continue
            
            #Convert timestamp into a datetime object
            try:
                timestamp = datetime.strptime(
                    timestamp_string,
                    "%d/%b/%Y:%H:%M:%S %z"
                )
            
            except ValueError:
                continue

            parse_logs.append({
                "ip": ip,
                "timestamp": timestamp,
                "method": method,
                "path": path,
                "status_code": status_code
            })
    return parse_logs