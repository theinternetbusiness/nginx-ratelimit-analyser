import re
import argparse
from collections import defaultdict
from datetime import datetime, timedelta

# Regular expression pattern to parse the access log
log_pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<time>[^\]]+)\] "(?P<request>[^"]+)" '
    r'(?P<status>\d+) (?P<size>\d+) "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)"'
)

# Function to parse a log line
def parse_log_line(line):
    match = log_pattern.match(line)
    if match:
        return match.groupdict()
    return None

def analyze_log(access_log_path):
    # Parse the access log and collect request times per IP
    ip_requests = defaultdict(list)
    with open(access_log_path, 'r') as file:
        for line in file:
            log_entry = parse_log_line(line)
            if log_entry:
                ip = log_entry['ip']
                time_str = log_entry['time']
                request_time = datetime.strptime(time_str, "%d/%b/%Y:%H:%M:%S %z")
                ip_requests[ip].append(request_time)

    # Calculate request rates for each IP
    ip_request_rates = defaultdict(int)
    for ip, times in ip_requests.items():
        times.sort()
        for i in range(1, len(times)):
            delta = times[i] - times[i - 1]
            if delta.total_seconds() < 1:
                ip_request_rates[ip] += 1

    # Analyze the distribution of request rates
    request_rate_counts = defaultdict(int)
    for rate in ip_request_rates.values():
        request_rate_counts[rate] += 1

    # Output the analysis results
    print("Request rate distribution:")
    for rate, count in sorted(request_rate_counts.items()):
        print(f"{rate} requests/second: {count} IPs")

    # Suggest rate limit settings based on analysis
    average_rate = sum(ip_request_rates.values()) / len(ip_request_rates)
    burst_capacity = max(ip_request_rates.values())
    suggested_rate_limit = max(1, int(average_rate * 1.5))
    suggested_burst_limit = max(10, int(burst_capacity * 1.2))

    print(f"\nSuggested rate limit settings:")
    print(f"Rate limit: {suggested_rate_limit} requests/second")
    print(f"Burst capacity: {suggested_burst_limit} requests")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze Nginx access log for rate limiting")
    parser.add_argument("logfile", help="Path to the Nginx access log file")

    args = parser.parse_args()

    analyze_log(args.logfile)
