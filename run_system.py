import sys
import time
import logging
from config import SERVER_IP, SERVER_PORT, INTERFACE
from database import init_db
from mitigation.firewall import Firewall
from mitigation.cooldown_manager import CooldownManager
from detection.detector import DetectionEngine
from dashboard.app import app

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
)
logger = logging.getLogger("SystemRunner")

def main():
    print("=" * 65)
    print(" IT307 DDoS Attack Detection & Automated Response System")
    print("=" * 65)

    # 1. Initialize DB
    logger.info("Initializing SQLite database...")
    init_db()

    # 2. Initialize Mitigation System
    logger.info("Initializing Firewall Mitigator & Cooldown Manager...")
    firewall = Firewall()
    cooldown_mgr = CooldownManager(firewall=firewall, check_interval=5)
    cooldown_mgr.start()

    # 3. Initialize Detection Engine
    logger.info("Starting Sniffer and Real-Time Detection Engine...")
    detector = DetectionEngine(firewall=firewall, interface=INTERFACE)
    detector.start()

    # 4. Start Dashboard Server
    print("\n" + "=" * 65)
    print(f" Web Dashboard running at: http://{SERVER_IP}:{SERVER_PORT}")
    print(" Open this URL in your browser to view the real-time telemetry")
    print("=" * 65 + "\n")

    try:
        app.run(host="0.0.0.0", port=SERVER_PORT, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        print("\n[!] Shutting down DDoS Defense System...")
    finally:
        detector.stop()
        cooldown_mgr.stop()
        print("[+] Defense system stopped cleanly.")

if __name__ == "__main__":
    main()
