from config import THRESHOLDS

class TrafficAnalyzer:
    def __init__(self, thresholds=None):
        self.thresholds = thresholds or THRESHOLDS

    def analyze(self, snapshot, duration):
        """
        Analyzes a 1-second (or given duration) snapshot and returns:
        - normalized_pps: dict with rates per layer
        - alerts: list of detected threats with IP, type, severity, and explanation
        """
        alerts = []
        
        # Calculate rates (Packets per second)
        total_pps = snapshot.total_packets / duration
        tcp_pps = snapshot.tcp_packets / duration
        udp_pps = snapshot.udp_packets / duration
        icmp_pps = snapshot.icmp_packets / duration
        http_pps = snapshot.http_packets / duration

        rates = {
            "total_pps": round(total_pps, 2),
            "tcp_pps": round(tcp_pps, 2),
            "udp_pps": round(udp_pps, 2),
            "icmp_pps": round(icmp_pps, 2),
            "http_pps": round(http_pps, 2)
        }

        # Analyze per-IP behavior
        for ip, count in snapshot.ip_packet_count.items():
            ip_pps = count / duration
            syn_count = snapshot.ip_syn_count[ip] / duration
            syn_ack_count = snapshot.ip_syn_ack_count[ip] / duration
            udp_count = snapshot.ip_udp_count[ip] / duration
            icmp_count = snapshot.ip_icmp_count[ip] / duration
            http_count = snapshot.ip_http_count[ip] / duration

            # 1. SYN Flood Detection (High SYN rate with high SYN:SYN-ACK ratio)
            syn_ratio = syn_count / max(syn_ack_count, 1)
            if syn_count >= self.thresholds["SYN_COUNT_THRESHOLD"] and syn_ratio >= self.thresholds["SYN_RATIO_THRESHOLD"]:
                alerts.append({
                    "ip": ip,
                    "type": "SYN_FLOOD",
                    "severity": "CRITICAL" if syn_count > self.thresholds["SYN_COUNT_THRESHOLD"] * 2 else "HIGH",
                    "details": f"SYN Flood detected: {syn_count:.1f} SYN pkts/sec (SYN:SYN-ACK ratio: {syn_ratio:.1f})"
                })
                continue

            # 2. UDP Flood Detection
            if udp_count >= self.thresholds["UDP_PPS_THRESHOLD"]:
                alerts.append({
                    "ip": ip,
                    "type": "UDP_FLOOD",
                    "severity": "HIGH",
                    "details": f"UDP Flood detected: {udp_count:.1f} UDP pkts/sec to random ports"
                })
                continue

            # 3. ICMP Ping Flood Detection
            if icmp_count >= self.thresholds["ICMP_PPS_THRESHOLD"]:
                alerts.append({
                    "ip": ip,
                    "type": "ICMP_FLOOD",
                    "severity": "HIGH",
                    "details": f"ICMP (Ping) Flood detected: {icmp_count:.1f} Echo Requests/sec"
                })
                continue

            # 4. HTTP Application Layer Flood Detection
            if http_count >= self.thresholds["HTTP_RPS_THRESHOLD"]:
                alerts.append({
                    "ip": ip,
                    "type": "HTTP_FLOOD",
                    "severity": "HIGH",
                    "details": f"HTTP Layer 7 Flood detected: {http_count:.1f} requests/sec"
                })
                continue

            # 5. Generic Volumetric PPS Threshold
            if ip_pps >= self.thresholds["IP_PPS_THRESHOLD"]:
                alerts.append({
                    "ip": ip,
                    "type": "VOLUMETRIC_FLOOD",
                    "severity": "MEDIUM",
                    "details": f"Generic Volumetric Flood: {ip_pps:.1f} packets/sec from single host"
                })

        return rates, alerts
