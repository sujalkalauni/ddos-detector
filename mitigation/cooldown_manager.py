import time
import threading
import logging
from database import get_active_mitigations, update_mitigation_status

logger = logging.getLogger("CooldownManager")

class CooldownManager:
    def __init__(self, firewall, check_interval=5):
        self.firewall = firewall
        self.check_interval = check_interval
        self.running = False
        self._thread = None

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info("Cooldown Manager background worker started.")

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=2)

    def _run(self):
        while self.running:
            try:
                now = time.time()
                active_records = get_active_mitigations()
                for rec in active_records:
                    if rec["expires_at"] > 0 and now >= rec["expires_at"]:
                        ip = rec["source_ip"]
                        logger.info(f"Cooldown period reached for IP {ip}. Removing mitigation.")
                        self.firewall.unblock_ip(ip)
                        update_mitigation_status(rec["id"], "EXPIRED")
            except Exception as e:
                logger.error(f"Error in CooldownManager loop: {e}")
            
            time.sleep(self.check_interval)
