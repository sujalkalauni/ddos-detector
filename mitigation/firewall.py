import subprocess
import logging
import platform
from config import MITIGATION
from database import log_mitigation

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("FirewallMitigator")

class Firewall:
    def __init__(self, simulate=None):
        self.simulate = simulate if simulate is not None else MITIGATION["SIMULATE_MODE"]
        self.active_blocks = set()
        self.active_rate_limits = set()
        logger.info(f"Firewall initialized (Simulate Mode: {self.simulate})")

    def block_ip(self, ip_address, duration_sec=None):
        """Adds a DROP rule for the specified IP in iptables."""
        if duration_sec is None:
            duration_sec = MITIGATION["BLOCK_DURATION_SEC"]

        if ip_address in self.active_blocks:
            logger.info(f"IP {ip_address} is already blocked.")
            return True

        logger.warning(f"[MITIGATION] Blocking IP {ip_address} for {duration_sec}s")
        success = True

        if not self.simulate:
            try:
                cmd = ["iptables", "-I", "INPUT", "-s", ip_address, "-j", "DROP"]
                subprocess.run(cmd, check=True, capture_output=True)
                logger.info(f"Executed: {' '.join(cmd)}")
            except Exception as e:
                logger.error(f"Failed to apply iptables DROP rule for {ip_address}: {e}")
                success = False
        else:
            logger.info(f"[SIMULATION] iptables -I INPUT -s {ip_address} -j DROP")

        if success:
            self.active_blocks.add(ip_address)
            log_mitigation(ip_address, "BLOCKED", duration_sec)
        return success

    def rate_limit_ip(self, ip_address, duration_sec=None):
        """Applies a rate-limiting rule for the specified IP."""
        if duration_sec is None:
            duration_sec = MITIGATION["BLOCK_DURATION_SEC"]

        if ip_address in self.active_rate_limits or ip_address in self.active_blocks:
            return True

        logger.warning(f"[MITIGATION] Rate limiting IP {ip_address}")
        success = True

        if not self.simulate:
            try:
                rate = MITIGATION["RATE_LIMIT_PPS"]
                burst = str(MITIGATION["RATE_LIMIT_BURST"])
                # Accept up to rate/burst, drop excess
                cmd1 = ["iptables", "-I", "INPUT", "-s", ip_address, "-m", "limit", "--limit", rate, "--limit-burst", burst, "-j", "ACCEPT"]
                cmd2 = ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
                subprocess.run(cmd1, check=True, capture_output=True)
                subprocess.run(cmd2, check=True, capture_output=True)
            except Exception as e:
                logger.error(f"Failed to apply iptables rate limit rule for {ip_address}: {e}")
                success = False
        else:
            logger.info(f"[SIMULATION] Rate limiting applied to {ip_address}")

        if success:
            self.active_rate_limits.add(ip_address)
            log_mitigation(ip_address, "RATE_LIMITED", duration_sec)
        return success

    def unblock_ip(self, ip_address):
        """Removes the DROP / rate limit rule for the specified IP."""
        logger.info(f"[MITIGATION] Unblocking IP {ip_address}")
        success = True

        if not self.simulate:
            try:
                # Remove DROP rule
                cmd = ["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"]
                subprocess.run(cmd, check=False, capture_output=True)
            except Exception as e:
                logger.error(f"Failed to remove iptables rule for {ip_address}: {e}")
                success = False
        else:
            logger.info(f"[SIMULATION] iptables -D INPUT -s {ip_address} -j DROP")

        self.active_blocks.discard(ip_address)
        self.active_rate_limits.discard(ip_address)
        log_mitigation(ip_address, "UNBLOCKED", 0)
        return success
