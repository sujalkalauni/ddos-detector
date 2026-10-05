import sqlite3
import time
from config import DATABASE_PATH

def get_db():
    conn = sqlite3.connect(DATABASE_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Table for real-time traffic statistics
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS traffic_stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL,
        total_pps REAL,
        tcp_pps REAL,
        udp_pps REAL,
        icmp_pps REAL,
        http_pps REAL
    )
    """)
    
    # Table for detected attack alerts
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS attack_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL,
        source_ip TEXT,
        attack_type TEXT,
        severity TEXT,
        details TEXT
    )
    """)
    
    # Table for mitigation actions (blocks / rate limits)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS mitigation_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL,
        source_ip TEXT,
        action TEXT,
        expires_at REAL,
        status TEXT
    )
    """)
    
    conn.commit()
    conn.close()

def log_traffic_stats(total_pps, tcp_pps, udp_pps, icmp_pps, http_pps):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO traffic_stats (timestamp, total_pps, tcp_pps, udp_pps, icmp_pps, http_pps)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (time.time(), total_pps, tcp_pps, udp_pps, icmp_pps, http_pps))
    conn.commit()
    conn.close()

def log_alert(source_ip, attack_type, severity, details):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO attack_alerts (timestamp, source_ip, attack_type, severity, details)
    VALUES (?, ?, ?, ?, ?)
    """, (time.time(), source_ip, attack_type, severity, details))
    conn.commit()
    conn.close()

def log_mitigation(source_ip, action, duration_sec):
    conn = get_db()
    cursor = conn.cursor()
    expires_at = time.time() + duration_sec if duration_sec > 0 else 0
    
    # Check if there is an existing active record for this IP
    cursor.execute("UPDATE mitigation_actions SET status = 'SUPERSEDED' WHERE source_ip = ? AND status = 'ACTIVE'", (source_ip,))
    
    cursor.execute("""
    INSERT INTO mitigation_actions (timestamp, source_ip, action, expires_at, status)
    VALUES (?, ?, ?, ?, 'ACTIVE')
    """, (time.time(), source_ip, action, expires_at))
    conn.commit()
    conn.close()

def update_mitigation_status(action_id, new_status):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE mitigation_actions SET status = ? WHERE id = ?", (new_status, action_id))
    conn.commit()
    conn.close()

def get_active_mitigations():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM mitigation_actions WHERE status = 'ACTIVE' ORDER BY timestamp DESC")
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows

def get_recent_alerts(limit=25):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM attack_alerts ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows

def get_recent_stats(limit=30):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM traffic_stats ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return list(reversed(rows))
