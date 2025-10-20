from prometheus_client import start_http_server, Counter
from prometheus_client import Gauge

packet_counter = Counter('network_packets', 'Number of network packets captured')
suspicious_counter = Counter('suspicious_events', 'Number of suspicious events detected')
anomaly_score = Gauge('anomaly_score', 'Z-score for anomalies')

def start_metrics_server(port=8000):
    start_http_server(port)
    print("Prometheus metrics server started on port 8000")