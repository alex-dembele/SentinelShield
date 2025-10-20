from prometheus_client import start_http_server, Counter

packet_counter = Counter('network_packets', 'Number of network packets captured')
suspicious_counter = Counter('suspicious_events', 'Number of suspicious events detected')

def start_metrics_server(port=8000):
    start_http_server(port)
    print("Prometheus metrics server started on port 8000")