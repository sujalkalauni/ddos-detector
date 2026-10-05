import time
from collections import defaultdict
from scapy.all import IP, TCP, UDP, ICMP, Raw

class TrafficStats:
    def __init__(self):
        self.reset()

    def reset(self):
        self.total_packets = 0
        self.tcp_packets = 0
        self.udp_packets = 0
        self.icmp_packets = 0
        self.http_packets = 0
        
        # Per IP statistics: ip -> count
        self.ip_packet_count = defaultdict(int)
        self.ip_tcp_count = defaultdict(int)
        self.ip_syn_count = defaultdict(int)
        self.ip_syn_ack_count = defaultdict(int)
        self.ip_udp_count = defaultdict(int)
        self.ip_icmp_count = defaultdict(int)
        self.ip_http_count = defaultdict(int)

class PacketCollector:
    def __init__(self):
        self.current_stats = TrafficStats()
        self.last_flush_time = time.time()

    def process_packet(self, packet):
        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        self.current_stats.total_packets += 1
        self.current_stats.ip_packet_count[src_ip] += 1

        # TCP & SYN Analysis
        if packet.haslayer(TCP):
            self.current_stats.tcp_packets += 1
            self.current_stats.ip_tcp_count[src_ip] += 1
            flags = packet[TCP].flags
            
            # Check SYN flag (SYN=0x02, SYN-ACK=0x12)
            if flags == 2 or flags == "S":
                self.current_stats.ip_syn_count[src_ip] += 1
            elif flags == 18 or flags == "SA":
                self.current_stats.ip_syn_ack_count[src_ip] += 1

            # Check HTTP Layer
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                if any(payload.startswith(m) for m in [b"GET ", b"POST ", b"HEAD ", b"PUT "]):
                    self.current_stats.http_packets += 1
                    self.current_stats.ip_http_count[src_ip] += 1

        # UDP Analysis
        elif packet.haslayer(UDP):
            self.current_stats.udp_packets += 1
            self.current_stats.ip_udp_count[src_ip] += 1

        # ICMP Analysis
        elif packet.haslayer(ICMP):
            self.current_stats.icmp_packets += 1
            self.current_stats.ip_icmp_count[src_ip] += 1

    def snapshot_and_reset(self):
        now = time.time()
        duration = max(now - self.last_flush_time, 0.001)
        snapshot = self.current_stats
        self.current_stats = TrafficStats()
        self.last_flush_time = now
        return snapshot, duration
