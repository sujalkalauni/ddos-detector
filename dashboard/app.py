import os
import sys
from flask import Flask, render_template, jsonify, request

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import (
    get_recent_stats,
    get_recent_alerts,
    get_active_mitigations,
    get_db,
    init_db
)
from mitigation.firewall import Firewall

app = Flask(__name__)
firewall = Firewall()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/stats", methods=["GET"])
def api_stats():
    stats = get_recent_stats(limit=30)
    return jsonify(stats)

@app.route("/api/alerts", methods=["GET"])
def api_alerts():
    alerts = get_recent_alerts(limit=20)
    return jsonify(alerts)

@app.route("/api/mitigations", methods=["GET"])
def api_mitigations():
    mitigations = get_active_mitigations()
    return jsonify(mitigations)

@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    data = request.get_json() or {}
    ip = data.get("ip")
    if not ip:
        return jsonify({"success": False, "error": "IP missing"}), 400
    
    success = firewall.unblock_ip(ip)
    # Update DB status
    conn = get_db()
    conn.execute("UPDATE mitigation_actions SET status = 'MANUALLY_REMOVED' WHERE source_ip = ? AND status = 'ACTIVE'", (ip,))
    conn.commit()
    conn.close()

    return jsonify({"success": success, "ip": ip})

def run_dashboard(host="0.0.0.0", port=8080, debug=False):
    init_db()
    app.run(host=host, port=port, debug=debug)

if __name__ == "__main__":
    run_dashboard(port=8080, debug=True)
