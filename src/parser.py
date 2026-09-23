import re
import ipaddress

LOG_PATTERN = re.compile(
    r'^(\b(?:\d{1,3}\.){3}\d{1,3}\b).*?"'
    r'(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+'
    r'(\S+)\s+HTTP/\d(?:\.\d)?"\s+(\d{3})'
)

def parse_log(log_file):

    parse_logs = []

    with open(log_file, "r", encoding="utf-8") as file:
         for line in file:
            
            match = LOG_PATTERN.search(line)

            if not match:
                continue

            ip = match.group(1)
            method = match.group(2)
            path = match.group(3)
            status_code = int(match.group(4))

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