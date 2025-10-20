from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        print(f"Packet: {src} -> {dst} (Proto: {proto})")
        if TCP in packet:
            print(f"TCP Port: {packet[TCP].sport} -> {packet[TCP].dport}")
        elif UDP in packet:
            print(f"UDP Port: {packet[UDP].sport} -> {packet[UDP].dport}")

def main():
    print("Starting network traffic capture...")
    sniff(prn=packet_callback, store=0, count=10)  # Capture 10 packets for test

if __name__ == "__main__":
    main()