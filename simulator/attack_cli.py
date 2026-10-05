import argparse
import sys
from simulator.syn_flood import launch_syn_flood
from simulator.udp_flood import launch_udp_flood
from simulator.icmp_flood import launch_icmp_flood
from simulator.http_flood import launch_http_flood

def main():
    parser = argparse.ArgumentParser(description="IT307 DDoS Attack Simulator (Controlled Lab Environment Only)")
    parser.add_argument("--type", choices=["syn", "udp", "icmp", "http"], required=True, help="Attack vector type")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP or hostname")
    parser.add_argument("--port", type=int, default=8080, help="Target port (for TCP/UDP/HTTP)")
    parser.add_argument("--count", type=int, default=300, help="Total packet or request count")
    parser.add_argument("--threads", type=int, default=10, help="Concurrency level for HTTP flood")
    parser.add_argument("--delay", type=float, default=0.005, help="Delay between packets in seconds")

    args = parser.parse_args()

    print("=" * 60)
    print(" IT307 Controlled DDoS Simulation Lab")
    print(f" Target: {args.target} | Type: {args.type.upper()} | Count: {args.count}")
    print(" WARNING: For internal lab demonstration only.")
    print("=" * 60)

    if args.type == "syn":
        launch_syn_flood(args.target, args.port, args.count, args.delay)
    elif args.type == "udp":
        launch_udp_flood(args.target, args.port, args.count, args.delay)
    elif args.type == "icmp":
        launch_icmp_flood(args.target, args.count, args.delay)
    elif args.type == "http":
        url = f"http://{args.target}:{args.port}/" if not args.target.startswith("http") else args.target
        launch_http_flood(url, args.count, args.threads)

if __name__ == "__main__":
    main()
