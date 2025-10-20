from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time
import psutil

suspicious_ips = defaultdict(list)  # Track ports scanned per IP

def packet_callback(packet):
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

    elif IP in packet and UDP in packet:
        print(f"UDP Packet: {packet[IP].src} -> {packet[IP].dst}:{packet[UDP].dport}")

def monitor_system_connections():
    connections = psutil.net_connections()
    suspicious = [conn for conn in connections if conn.status == 'ESTABLISHED' and conn.raddr]  # Remote connections
    if len(suspicious) > 50:  # Arbitrary threshold
        print("Suspicious number of connections detected!")
    for conn in suspicious[:5]:  # Log some
        print(f"Connection: {conn.laddr} <-> {conn.raddr}")

def main():
    print("Starting network traffic monitoring with anomaly detection...")
    monitor_system_connections()
    sniff(prn=packet_callback, store=0, timeout=60)  # Run for 60 seconds for test

if __name__ == "__main__":
    main()