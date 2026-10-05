import os
import platform

# Network Configuration
INTERFACE = os.getenv("DEFENSE_INTERFACE", "eth0" if platform.system() == "Linux" else None)
SERVER_IP = os.getenv("DEFENSE_SERVER_IP", "127.0.0.1")
SERVER_PORT = int(os.getenv("DEFENSE_SERVER_PORT", "8080"))

# Thresholds for Detection (Packets Per Second / Ratios)
THRESHOLDS = {
    # Global / Per-IP Packet Rate (PPS)
    "GLOBAL_PPS_ALERT": 250,        # Total packets/sec threshold to flag global stress
    "IP_PPS_THRESHOLD": 50,         # Per-IP packets/sec to flag flood
    
    # SYN Flood Specific
    "SYN_COUNT_THRESHOLD": 40,      # Number of SYN packets per second
    "SYN_RATIO_THRESHOLD": 3.0,     # Ratio of SYN to SYN-ACK (high means half-open flood)
    
    # UDP Flood Specific
    "UDP_PPS_THRESHOLD": 45,        # UDP packets per second per IP
    
    # ICMP Flood Specific
    "ICMP_PPS_THRESHOLD": 30,       # ICMP packets per second per IP
    
    # HTTP Flood Specific
    "HTTP_RPS_THRESHOLD": 25,       # HTTP requests per second per IP
}

# Mitigation Rules
MITIGATION = {
    "BLOCK_DURATION_SEC": 60,       # Cooldown period before unblocking
    "RATE_LIMIT_PPS": "10/sec",     # iptables rate limit string
    "RATE_LIMIT_BURST": 20,         # iptables burst capacity
    "SIMULATE_MODE": platform.system() != "Linux", # Run in simulation/log mode on Windows/macOS
}

# Database & Logging
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "ddos_monitor.db")
LOG_FILE = os.path.join(BASE_DIR, "ddos_defense.log")
