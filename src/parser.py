import re
import ipaddress

#Pattern used to extract
#IP Address, HTTP method, request path and HTTP status code, maybe more in the future
LOG_PATTERN = re.compile(
    r'^(\b(?:\d{1,3}\.){3}\d{1,3}\b).*?"'
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
            method = match.group(2)
            path = match.group(3)
            status_code = int(match.group(4))

            #Reject invalid IPv4 address such as 999.999.999.999
            try:
                ipaddress.IPv4Address(ip)

            except ValueError:
                continue

            parse_logs.append({
                "ip": ip,
                "method": method,
                "path": path,
                "status_code": status_code
            })
    return parse_logs