from flask import Flask, render_template, request, jsonify, redirect, url_for
import requests
import json
from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler
import os
from dotenv import load_dotenv
from prometheus_client import generate_latest
import threading
import time

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET', 'sentinelshield_secret')

# Logging setup
logging.basicConfig(level=logging.INFO)
handler = RotatingFileHandler('web_app.log', maxBytes=1000000, backupCount=5)
handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
app.logger.addHandler(handler)

# Global state
monitoring_active = False
monitoring_thread = None

# Prometheus API endpoint
PROMETHEUS_URL = os.getenv('PROMETHEUS_URL', 'http://localhost:9090')

# Grafana iframe URL
GRAFANA_URL = os.getenv('GRAFANA_URL', 'http://localhost:3000/d/sentinel-dashboard')

def query_prometheus(query):
    """Query Prometheus API"""
    try:
        url = f"{PROMETHEUS_URL}/api/v1/query?query={query}"
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        return response.json()['data']['result']
    except Exception as e:
        app.logger.error(f"Prometheus query error: {e}")
        return []

def get_recent_alerts():
    """Get recent alerts from Prometheus Alertmanager (simplified)"""
    try:
        url = f"{PROMETHEUS_URL}/api/v1/query?query=ALERTS{{alertstate='firing'}}"
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        alerts = response.json()['data']['result']
        return alerts[:5]  # Last 5 alerts
    except:
        return []

def start_monitoring():
    """Start the monitoring process"""
    global monitoring_active, monitoring_thread
    if not monitoring_active:
        # In production, this would subprocess.call(['python', 'src/main.py'])
        # For demo, simulate with a thread
        monitoring_active = True
        monitoring_thread = threading.Thread(target=monitoring_worker, daemon=True)
        monitoring_thread.start()
        app.logger.info("Monitoring started")

def stop_monitoring():
    """Stop the monitoring process"""
    global monitoring_active
    monitoring_active = False
    if monitoring_thread:
        monitoring_thread.join(timeout=2)
    app.logger.info("Monitoring stopped")

def monitoring_worker():
    """Simulate monitoring activity"""
    while monitoring_active:
        time.sleep(5)  # Simulate work
        # In real impl: subprocess.Popen(['python', 'src/main.py'])

@app.route('/')
def dashboard():
    """Main dashboard"""
    metrics = {
        'packets': query_prometheus('rate(network_packets[5m])'),
        'anomalies': query_prometheus('suspicious_events'),
        'anomaly_score': query_prometheus('suspicious_events_zscore'),
        'connections': query_prometheus('process_open_fds'),
        'cpu_usage': query_prometheus('100 - (avg by(instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)'),
        'memory_usage': query_prometheus('100 - ((node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100)')
    }
    
    alerts = get_recent_alerts()
    
    return render_template('dashboard.html', 
                         metrics=metrics, 
                         alerts=alerts,
                         monitoring_active=monitoring_active,
                         timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

@app.route('/metrics')
def metrics():
    """Expose Prometheus metrics for the web app"""
    return generate_latest()

@app.route('/api/start_monitoring', methods=['POST'])
def api_start_monitoring():
    start_monitoring()
    return jsonify({'status': 'started', 'timestamp': datetime.now().isoformat()})

@app.route('/api/stop_monitoring', methods=['POST'])
def api_stop_monitoring():
    stop_monitoring()
    return jsonify({'status': 'stopped', 'timestamp': datetime.now().isoformat()})

@app.route('/api/alerts')
def api_alerts():
    alerts = get_recent_alerts()
    return jsonify(alerts)

@app.route('/grafana')
def grafana():
    """Redirect to Grafana dashboard"""
    return redirect(GRAFANA_URL)

@app.route('/logs')
def logs():
    """View recent logs"""
    try:
        with open('sentinelshield.log', 'r') as f:
            log_lines = f.readlines()[-50:]  # Last 50 lines
        logs = ''.join(log_lines)
    except FileNotFoundError:
        logs = "No logs found"
    return render_template('logs.html', logs=logs)

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)