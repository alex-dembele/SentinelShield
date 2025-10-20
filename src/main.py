from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time
import psutil
import smtplib
from email.mime.text import MIMEText
import yaml
import requests
from metrics import start_metrics_server, packet_counter, suspicious_counter

suspicious_ips = defaultdict(list)  # Track ports scanned per IP

with open('../config/config.yaml', 'r') as f:
    config = yaml.safe_load(f)

def packet_callback(packet):
    packet_counter.inc()
    if IP in packet and TCP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        dport = packet[TCP].dport
        flags = packet[TCP].flags
        
        print(f"Packet: {src} -> {dst}:{dport} (Flags: {flags})")
        
        # Detect port scan: multiple SYN to different ports
        if flags & 2:  # SYN flag
            suspicious_ips[src].append((dport, time.time()))
            recent_scans = [p for p in suspicious_ips[src] if time.time() - p[1] < 60]  # Last 60s
            if len(recent_scans) > 10:  # Threshold for suspicion
                print(f"Suspicious port scan from {src}!")
                suspicious_counter.inc()
                send_alert(f"Suspicious port scan from {src}!")
                if 'slack' in config:
                    send_slack_alert(f"Suspicious port scan from {src}!")
                if 'telegram' in config:
                    send_telegram_alert(f"Suspicious port scan from {src}!")

    elif IP in packet and UDP in packet:
        print(f"UDP Packet: {packet[IP].src} -> {packet[IP].dst}:{packet[UDP].dport}")

def monitor_system_connections():
    connections = psutil.net_connections()
    suspicious = [conn for conn in connections if conn.status == 'ESTABLISHED' and conn.raddr]  # Remote connections
    if len(suspicious) > 50:  # Arbitrary threshold
        print("Suspicious number of connections detected!")
        suspicious_counter.inc()
        send_alert("Suspicious number of connections detected!")
        if 'slack' in config:
            send_slack_alert("Suspicious number of connections detected!")
        if 'telegram' in config:
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

def main():
    print("Starting network traffic monitoring with anomaly detection...")
    start_metrics_server()
    monitor_system_connections()
    sniff(prn=packet_callback, store=0, timeout=60)  # Run for 60 seconds for test

if __name__ == "__main__":
    main()