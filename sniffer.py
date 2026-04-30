from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

packets = []  # store captured packets

def process_packet(packet):
    try:
        if IP in packet:
            proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "OTHER"
            pkt_info = {
                "time": datetime.now().strftime("%H:%M:%S"),
                "src": packet[IP].src,
                "dst": packet[IP].dst,
                "proto": proto
            }
            packets.append(pkt_info)
            if len(packets) > 100:  # limit memory
                packets.pop(0)
    except Exception as e:
        print("Error processing packet:", e)

def start_sniffer():
    print("🔍 Sniffer starting...")
    sniff(prn=process_packet, store=False)

def get_recent_packets():
    return packets[-20:]

