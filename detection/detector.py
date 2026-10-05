import time
import threading
import logging
from scapy.all import sniff
from config import INTERFACE
from detection.packet_sniffer import PacketCollector
from detection.analyzer import TrafficAnalyzer
from database import log_traffic_stats, log_alert

logger = logging.getLogger("DetectionEngine")

class DetectionEngine:
    def __init__(self, firewall, interface=None, eval_interval=1.0):
        self.firewall = firewall
        self.interface = interface or INTERFACE
        self.eval_interval = eval_interval
        self.collector = PacketCollector()
        self.analyzer = TrafficAnalyzer()
        self.running = False
        self._sniff_thread = None
        self._eval_thread = None

    def start(self):
        self.running = True
        logger.info(f"Starting Detection Engine on interface: {self.interface or 'default'}")
        
        # Sniffer Thread
        self._sniff_thread = threading.Thread(target=self._sniff_worker, daemon=True)
        self._sniff_thread.start()

        # Analyzer / Evaluator Thread
        self._eval_thread = threading.Thread(target=self._eval_worker, daemon=True)
        self._eval_thread.start()

    def stop(self):
        self.running = False

    def _sniff_worker(self):
        logger.info("Sniffer thread active. Listening for packets...")
        try:
            sniff(
                iface=self.interface,
                prn=self.collector.process_packet,
                store=False,
                stop_filter=lambda p: not self.running
            )
        except Exception as e:
            logger.error(f"Sniffer error (Ensure you have administrative/root privileges or Npcap installed): {e}")

    def _eval_worker(self):
        while self.running:
            time.sleep(self.eval_interval)
            try:
                snapshot, duration = self.collector.snapshot_and_reset()
                rates, alerts = self.analyzer.analyze(snapshot, duration)

                # Persist real-time stats
                log_traffic_stats(
                    rates["total_pps"],
                    rates["tcp_pps"],
                    rates["udp_pps"],
                    rates["icmp_pps"],
                    rates["http_pps"]
                )

                # Process alerts
                for alert in alerts:
                    ip = alert["ip"]
                    # Do not block localhost loopback in testing unless explicitly wanted
                    logger.warning(f"[DETECTION ALERT] {alert['type']} ({alert['severity']}) from {ip}: {alert['details']}")
                    log_alert(ip, alert["type"], alert["severity"], alert["details"])

                    # Mitigation action trigger
                    if alert["severity"] in ["CRITICAL", "HIGH"]:
                        self.firewall.block_ip(ip)
                    else:
                        self.firewall.rate_limit_ip(ip)

            except Exception as e:
                logger.error(f"Error in Detection evaluation loop: {e}")
