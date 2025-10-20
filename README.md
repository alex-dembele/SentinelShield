# SentinelShield

Network monitoring and anomaly detection tool.

## Purpose
Monitor internal network traffic and detect suspicious behavior (scanning, exfiltration, DDoS, abnormal connections).

## Stack
- Python (Scapy, psutil, socket)
- Grafana + Prometheus for dashboards
- Alerts via Slack/Telegram/Email
- Containerization with Docker

## Key Features
- Real-time traffic analysis
- Detection of scanned ports / suspicious traffic
- Real-time dashboards
- Automatic alerting

## Installation
1. Clone the repository: `git clone <repo_url>`
2. Install dependencies: `pip install -r requirements.txt`
3. Configure the files in `config/` (e.g., config.yaml for alerts and Prometheus)
4. Launch the application: `python src/main.py` (run with sudo for Scapy if necessary)

## Prometheus and Grafana Setup
1. Install Prometheus and Grafana locally (via their official websites or packages). 2. Configure Prometheus with the `config/prometheus.yml` file to scrape application metrics from `http://localhost:8000`.
3. Launch Prometheus: navigate to `http://localhost:9090` to verify.
4. Launch Grafana: navigate to `http://localhost:3000`, add Prometheus as a data source (URL: `http://localhost:9090`).
5. Import the dashboard from `docs/grafana_dashboard.json` into Grafana to visualize metrics (captured packets, suspicious events).

## Usage
- The script captures traffic, detects anomalies, and sends alerts.
- Monitor console logs for detections.
- Access Prometheus metrics and Grafana dashboards for visual monitoring.

## Tests
- Test the capture: run the script and generate traffic (e.g., ping, nmap for scans).
- Verify alerts by configuring low thresholds to trigger detections.

## Notes
- Run with root privileges for a full network capture.
- Customize detection thresholds in the code to suit your environment.
- For production deployment, use Docker (coming soon).