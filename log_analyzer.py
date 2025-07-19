import re
from collections import Counter, defaultdict
from datetime import datetime
import matplotlib.pyplot as plt

LOG_FILE = "sample-log.log"

# Regex pattern to parse log entries
log_pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s-\s'
    r'(?P<country>[A-Z]+)\s-\s'
    r'\[(?P<timestamp>[^\]]+)\]\s'
    r'"(?P<method>\w+)\s(?P<endpoint>\S+)\sHTTP/\d\.\d"\s'
    r'(?P<status>\d+)\s\d+\s"-"\s"[^"]*"\s(?P<response_time>\d+)' 
)

def parse_time(timestamp_str):
    """Converts timestamp string to datetime object."""
    return datetime.strptime(timestamp_str, "%d/%m/%Y:%H:%M:%S")

def analyze_log(file_path):
    ip_counter = Counter()
    endpoint_counter = Counter()
    suspicious_ips = set()
    ip_rate = defaultdict(lambda: defaultdict(int))  # ip → timestamp → count

    with open(file_path, "r") as file:
        for line in file:
            match = log_pattern.search(line)
            if match:
                ip = match.group("ip")
                endpoint = match.group("endpoint")
                status = int(match.group("status"))
                method = match.group("method")
                timestamp = parse_time(match.group("timestamp"))
                time_key = timestamp.strftime("%Y-%m-%d %H:%M:%S")

                # Count frequency
                ip_counter[ip] += 1
                endpoint_counter[endpoint] += 1
                ip_rate[ip][time_key] += 1

                # Flag suspicious behavior
                if status == 404 or method == "POST":
                    suspicious_ips.add(ip)

    # Report top IPs
    print("\n Top 5 IP addresses by request count:")
    for ip, count in ip_counter.most_common(5):
        print(f"{ip}: {count} requests")

    # Report top endpoints
    print("\n Top 5 requested endpoints:")
    for endpoint, count in endpoint_counter.most_common(5):
        print(f"{endpoint}: {count} hits")

    # Report suspicious IPs
    print("\n Suspicious IPs (POSTs or 404s):")
    for ip in sorted(suspicious_ips):  # Sorted for consistent order
        print(ip)

    # Save suspicious IPs to blocklist file
    with open("blocklist.txt", "w") as f:
        for ip in sorted(suspicious_ips):
            f.write(ip + "\n")
    print("\n Blocklist saved as 'blocklist.txt'")

    # Detect high request rate per second
    print("\n IPs with high request rates (>5 reqs/sec):")
    for ip, time_counts in ip_rate.items():
        for second, count in time_counts.items():
            if count > 5:
                print(f"{ip} made {count} requests at {second}")
                break  # Report once per IP
    
    plot_top_ips(ip_counter)
    plot_top_endpoints(endpoint_counter)

def plot_top_ips(ip_counter):
    top_ips = ip_counter.most_common(5)
    ips = [ip for ip, _ in top_ips]
    counts = [count for _, count in top_ips]

    plt.figure(figsize=(8, 5))
    plt.bar(ips, counts, color="skyblue")
    plt.xlabel("IP Address")
    plt.ylabel("Request Count")
    plt.title("Top 5 IP Addresses by Request Volume")
    plt.tight_layout()
    plt.savefig("top_ips.png")
    print("\n Chart saved as 'top_ips.png'")

def plot_top_endpoints(endpoint_counter):
    top_endpoints = endpoint_counter.most_common(5)
    endpoints = [ep for ep, _ in top_endpoints]
    counts = [count for _, count in top_endpoints]

    plt.figure(figsize=(8, 5))
    plt.barh(endpoints, counts, color="lightgreen")
    plt.xlabel("Hit Count")
    plt.title("Top 5 Endpoints")
    plt.tight_layout()
    plt.savefig("top_endpoints.png")
    print(" Chart saved as 'top_endpoints.png'")

if __name__ == "__main__":
    analyze_log(LOG_FILE)
