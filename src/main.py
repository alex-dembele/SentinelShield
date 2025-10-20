from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time
import psutil
import smtplib
from email.mime.text import MIMEText
import yaml
import requests
from metrics import start_metrics_server, packet_counter, suspicious_counter
from scapy.layers.http import HTTPRequest, HTTPResponse
import datetime
import multiprocessing as mp

# Load configuration
with open('../config/config.yaml', 'r') as f:
    config = yaml.safe_load(f)

suspicious_ips = defaultdict(list)  # Track ports scanned per IP
io_tracker = defaultdict(lambda: {'sent': 0, 'recv': 0})  # Track bytes sent/received per IP

def packet_callback(packet):
    packet_counter.inc()  # Increment packet counter for Prometheus
    
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        
        # Update IO tracker
        io_tracker[src]['sent'] += len(packet)
        io_tracker[dst]['recv'] += len(packet)
        
        print(f"Packet: {src} -> {dst} (Proto: {proto})")
        
        if TCP in packet:
            dport = packet[TCP].dport
            flags = packet[TCP].flags
            print(f"TCP Port: {packet[TCP].sport} -> {dport} (Flags: {flags})")
            
            # Detect port scan: multiple SYN to different ports
            if flags & 2:  # SYN flag
                suspicious_ips[src].append((dport, time.time()))
                recent_scans = [p for p in suspicious_ips[src] if time.time() - p[1] < 60]  # Last 60s
                if len(recent_scans) > 10:  # Threshold for suspicion
                    print(f"Suspicious port scan from {src}!")
                    suspicious_counter.inc()
                    send_alert(f"Suspicious port scan from {src}!")
                    send_slack_alert(f"Suspicious port scan from {src}!")
                    send_telegram_alert(f"Suspicious port scan from {src}!")

        elif UDP in packet:
            print(f"UDP Port: {packet[UDP].sport} -> {packet[UDP].dport}")
        
        # Detect exfiltration (high sent bytes)
        if io_tracker[src]['sent'] > 1000000:  # 1MB threshold
            print(f"Possible exfiltration from {src}")
            suspicious_counter.inc()
            send_alert(f"Possible exfiltration from {src}")
            send_slack_alert(f"Possible exfiltration from {src}")
            send_telegram_alert(f"Possible exfiltration from {src}")
        
        # Detect DDoS (high global received bytes)
        total_recv = sum(io['recv'] for io in io_tracker.values())
        if total_recv > 10000000:  # 10MB threshold
            print("Possible DDoS detected!")
            suspicious_counter.inc()
            send_alert("Possible DDoS detected!")
            send_slack_alert("Possible DDoS detected!")
            send_telegram_alert("Possible DDoS detected!")

    # Protocol anomaly: HTTP on non-standard port (not 80/443)
    if TCP in packet and HTTPRequest in packet:
        dport = packet[TCP].dport
        if dport not in [80, 443]:
            print(f"Anomalous HTTP on non-standard port {dport} from {src}")
            suspicious_counter.inc()
            send_alert(f"Anomalous HTTP on port {dport} from {src}")

    # Temporal anomaly: High traffic outside of hours (e.g. after 6 p.m. or before 9 a.m.)
    current_hour = datetime.datetime.now().hour
    if current_hour < 9 or current_hour > 18:
        if io_tracker[src]['sent'] > 500000:  # 0.5MB threshold outside hours
            print(f"Out-of-hours high traffic from {src}")
            suspicious_counter.inc()
            send_alert(f"Out-of-hours anomaly from {src}")

# Behavioral anomaly: Suspicious payload (e.g. long UDP payload)
    if UDP in packet and len(packet[UDP].payload) > 1024:
        print(f"Suspicious large UDP payload from {src}")
        suspicious_counter.inc()
        send_alert(f"Large UDP payload anomaly from {src}")

def monitor_system_connections():
    connections = psutil.net_connections()
    suspicious = [conn for conn in connections if conn.status == 'ESTABLISHED' and conn.raddr]  # Remote connections
    if len(suspicious) > 50:  # Arbitrary threshold
        print("Suspicious number of connections detected!")
        suspicious_counter.inc()
        send_alert("Suspicious number of connections detected!")
        send_slack_alert("Suspicious number of connections detected!")
        send_telegram_alert("Suspicious number of connections detected!")
    for conn in suspicious[:5]:  # Log some
        print(f"Connection: {conn.laddr} <-> {conn.raddr}")

def send_alert(message):
    msg = MIMEText(message)
    msg['Subject'] = 'SentinelShield Alert'
    msg['From'] = config['alert']['email']['sender']
    msg['To'] = config['alert']['email']['receiver']
    
    server = smtplib.SMTP(config['alert']['email']['smtp_server'], config['alert']['email']['smtp_port'])
    server.starttls()
    server.login(config['alert']['email']['sender'], config['alert']['email']['password'])
    server.sendmail(config['alert']['email']['sender'], config['alert']['email']['receiver'], msg.as_string())
    server.quit()
    print("Alert sent!")

def send_slack_alert(message):
    webhook = config['slack']['webhook']
    requests.post(webhook, json={"text": message})
    print("Slack alert sent!")

def send_telegram_alert(message):
    token = config['telegram']['token']
    chat_id = config['telegram']['chat_id']
    url = f"https://api.telegram.org/bot{token}/sendMessage?chat_id={chat_id}&text={message}"
    requests.get(url)
    print("Telegram alert sent!")

def process_packet(packet):
    packet_callback(packet)  # Appel à la fonction existante

def main():
    start_metrics_server()  # Start Prometheus metrics server
    print("Starting optimized network traffic monitoring with anomaly detection...")
    monitor_system_connections()
    
    queue = mp.Queue()
    pool = mp.Pool(processes=4)  # 4 workers for parallel processing
    
    def enqueue_packet(pkt):
        queue.put(pkt)
    
    def worker():
        while True:
            pkt = queue.get()
            if pkt is None:
                break
            process_packet(pkt)
    
# Launch the workers
    for _ in range(4):
        mp.Process(target=worker).start()
    
    # Capture and enqueue
    sniff(prn=enqueue_packet, store=0, timeout=60)  # Run for 60 seconds for test
    
    # Stop workers
    for _ in range(4):
        queue.put(None)
    pool.close()
    pool.join()

if __name__ == "__main__":
    main()