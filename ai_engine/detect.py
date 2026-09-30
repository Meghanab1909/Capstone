from scapy.all import sniff, IP, TCP, UDP
import time
import csv
from collections import defaultdict

FLOWS = defaultdict(lambda: {
    "start": None,
    "end": None,
    "packet_count": 0,
    "src_bytes": 0,
    "dst_bytes": 0,
    "conn_state": "UNK"
})

CSV = "logs/traffic.csv"

def process_packet(pkt):
    if IP not in pkt:
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    proto = pkt[IP].proto
    sport = pkt.sport if hasattr(pkt, "sport") else 0
    dport = pkt.dport if hasattr(pkt, "dport") else 0

    key = (src, dst, sport, dport, proto)
    flow = FLOWS[key]

    now = time.time()

    # Initialize flow
    if flow["start"] is None:
        flow["start"] = now

    flow["end"] = now
    flow["packet_count"] += 1

    size = len(pkt)
    flow["src_bytes"] += size

    # Determine connection state
    if TCP in pkt:
        flags = pkt[TCP].flags
        if flags & 0x02:  # SYN
            flow["conn_state"] = "SYN"
        elif flags & 0x04:  # RST
            flow["conn_state"] = "RST"
        elif flags & 0x01:  # FIN
            flow["conn_state"] = "FIN"

def write_flows():
    with open(CSV, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "src_ip","dst_ip","src_port","dst_port",
            "protocol","src_bytes","dst_bytes",
            "flow_duration","packet_count","conn_state"
        ])

        for (src, dst, sport, dport, proto), flow in FLOWS.items():
            duration = (flow["end"] - flow["start"]) if flow["end"] else 0
            writer.writerow([
                src, dst, sport, dport, proto,
                flow["src_bytes"], flow["dst_bytes"],
                duration, flow["packet_count"],
                flow["conn_state"]
            ])

print("[*] Capturing Phase-0 traffic...")
sniff(prn=process_packet, store=0)
write_flows()
