import threading
import time
from collections import defaultdict, deque
from datetime import datetime

from flask import Flask, jsonify, render_template, send_file
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS

from logger import PacketLogger
from geoip import format_location, is_private
from threat_intel import check_ip, get_threat_level, is_private as ti_is_private
from mitre import map_alert, map_port, format_technique, get_technique
import socket
from functools import lru_cache
from emailer import send_alert
from anomaly import AnomalyDetector
from config import load_config, get as cfg


@lru_cache(maxsize=512)
def resolve_hostname(ip):
    """Reverse DNS lookup — returns hostname or empty string."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""
    
# Load config
config = load_config()

import platform
if platform.system() == "Linux":
    # Running inside Docker
    IFACE = config["network"].get("docker_interface", "eth0")
else:
    # Running on Windows directly
    IFACE = config["network"]["interface"]

IFACE = IFACE or None
RISKY_PORTS  = set(config["detection"]["risky_ports"])
MEDIUM_PORTS = set(config["detection"]["medium_ports"])
SCAN_THRESH  = config["detection"]["port_scan_threshold"]

# ── shared state ─────────────────────────────────────────────
packets      = deque(maxlen=100)
raw_packets  = deque(maxlen=10000)
alerts       = deque(maxlen=50)
stats        = defaultdict(int)
top_ips      = defaultdict(int)
ip_ports     = defaultdict(set)
threat_cache = {}
checked_ips  = set()
ti_queue     = deque()
total        = 0
lock         = threading.Lock()
ti_lock      = threading.Lock()
anomaly_detector = AnomalyDetector(
    baseline_duration=config["ml"]["baseline_duration"],
    contamination=config["ml"]["contamination"],
)



# ── packet parser ─────────────────────────────────────────────
def parse(pkt):
    if IP not in pkt:
        return None
    src      = pkt[IP].src
    dst      = pkt[IP].dst
    proto    = "OTHER"
    info     = ""
    dst_port = 0
    alert    = None

    if TCP in pkt:
        proto    = "TCP"
        dst_port = pkt[TCP].dport
        info     = f"{pkt[TCP].sport}→{dst_port} [{pkt[TCP].flags}]"
        ip_ports[src].add(dst_port)
        if len(ip_ports[src]) >= SCAN_THRESH:
            alert = f"PORT SCAN detected — {len(ip_ports[src])} ports probed"
            ip_ports[src].clear()
    elif UDP in pkt:
        proto    = "UDP"
        dst_port = pkt[UDP].dport
        info     = f"{pkt[UDP].sport}→{dst_port}"
        if DNS in pkt and pkt[DNS].qd:
            info += f" DNS? {pkt[DNS].qd.qname.decode(errors='replace')}"
    elif ICMP in pkt:
        proto = "ICMP"
        info  = {0: "Echo Reply", 8: "Echo Request"}.get(pkt[ICMP].type, f"type={pkt[ICMP].type}")

    level = "NORMAL"
    if alert:                      level = "CRITICAL"
    elif dst_port in RISKY_PORTS:  level = "HIGH"
    elif dst_port in MEDIUM_PORTS: level = "MEDIUM"
    elif proto == "ICMP":          level = "LOW"

    geo_ip   = dst if is_private(src) else src
    geo      = format_location(geo_ip)
    hostname = resolve_hostname(geo_ip)
    tech     = map_alert(alert, dst_port) if alert else map_port(dst_port)

    return {
        "time":      datetime.now().strftime("%H:%M:%S"),
        "proto":     proto,
        "src":       src,
        "dst":       dst,
        "dst_port":  dst_port,
        "info":      info,
        "level":     level,
        "alert":     alert or "",
        "location":  geo,
        "hostname":  hostname,
        "technique": {"id": tech["id"], "name": tech["name"], "tactic": tech["tactic"]} if tech else None,
    }
def handle(pkt):
    global total
    r = parse(pkt)
    if not r:
        return

    raw_packets.append(pkt)        # store raw packet for PCAP export

    # ML anomaly detection
    anomaly = anomaly_detector.add_packet(r)
    if anomaly:
        with lock:
            alerts.appendleft({
                "time":      r["time"],
                "src":       anomaly["src"],
                "msg":       f"ML ANOMALY — {anomaly['reason']} (confidence: {anomaly['confidence']}%)",
                "severity":  "HIGH",
                "technique": {"id": "T1071", "name": "Anomalous Protocol Behavior", "tactic": "Detection"},
            })
        send_alert(
            alert_type="ML ANOMALY",
            src_ip=anomaly["src"],
            message=f"{anomaly['reason']} on port {anomaly['dst_port']} (confidence: {anomaly['confidence']}%)",
            technique={"id": "T1071", "name": "Anomalous Protocol Behavior", "tactic": "Detection"},
        )

    logger.log(r)
    with lock:
        total += 1
        stats[r["proto"]] += 1
        top_ips[r["src"]] += 1
        for ip in [r["src"], r["dst"]]:
            if not ti_is_private(ip):
                with ti_lock:
                    if ip not in checked_ips:
                        checked_ips.add(ip)
                        ti_queue.append(ip)
        packets.appendleft(r)
        if r["alert"]:
            alerts.appendleft({
                "time":      r["time"],
                "src":       r["src"],
                "msg":       r["alert"],
                "severity":  r["level"],
                "technique": r["technique"],
            })
            send_alert(
                alert_type="PORT SCAN",
                src_ip=r["src"],
                message=r["alert"],
                technique=r["technique"],
            )
        if r["level"] == "HIGH":
            tech = map_port(r["dst_port"])
            tech_dict = {"id": tech["id"], "name": tech["name"], "tactic": tech["tactic"]} if tech else None
            alerts.appendleft({
                "time":      r["time"],
                "src":       r["src"],
                "msg":       f"Risky port connection → {r['dst']}:{r['dst_port']}",
                "severity":  "HIGH",
                "technique": tech_dict,
            })
            send_alert(
                alert_type="RISKY PORT",
                src_ip=r["src"],
                message=f"Connection to risky port {r['dst_port']} on {r['dst']}",
                technique=tech_dict,
            )

def threat_intel_worker():
    while True:
        ip = None
        with ti_lock:
            if ti_queue:
                ip = ti_queue.popleft()
        if ip:
            result = check_ip(ip)
            if result and result["score"] > 0:
                with ti_lock:
                    threat_cache[ip] = result
                level, _ = get_threat_level(result["score"])
                if result["score"] >= 20:
                    tech = get_technique("THREAT_INTEL")
                    tech_dict = {"id": tech["id"], "name": tech["name"], "tactic": tech["tactic"]} if tech else None
                    with lock:
                        alerts.appendleft({
                            "time":      datetime.now().strftime("%H:%M:%S"),
                            "src":       ip,
                            "msg":       f"AbuseIPDB {result['score']}% ({result['reports']} reports) — {level}",
                            "severity":  level,
                            "technique": tech_dict,
                        })
                    send_alert(
                        alert_type="MALICIOUS IP",
                        src_ip=ip,
                        message=f"AbuseIPDB score {result['score']}% with {result['reports']} reports. ISP: {result.get('isp','')}",
                        technique=tech_dict,
                    )
        time.sleep(0.1)

def sniffer_thread():
    sniff(iface=IFACE, prn=handle, store=False)

# ── Flask app ─────────────────────────────────────────────────
app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/stats")
def api_stats():
    with lock:
        with ti_lock:
            threats = sorted(threat_cache.items(), key=lambda x: x[1]["score"], reverse=True)[:10]
        return jsonify({
            "total":    total,
            "stats":    dict(stats),
            "top_ips":  sorted(top_ips.items(), key=lambda x: x[1], reverse=True)[:8],
            "packets":  list(packets)[:50],
            "alerts":   list(alerts)[:20],
            "threats":  [{"ip": ip, **data} for ip, data in threats],
        })
@app.route("/api/export/pcap")        
def export_pcap():
    import tempfile
    from flask import send_file
    from scapy.all import wrpcap

    with lock:
        pkts = list(raw_packets)

    if not pkts:
        return jsonify({"error": "No packets captured yet"}), 400

    tmp = tempfile.NamedTemporaryFile(
        suffix=".pcap",
        delete=False,
        prefix="capture_"
    )
    tmp.close()

    wrpcap(tmp.name, pkts)

    filename = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"

    return send_file(
        tmp.name,
        as_attachment=True,
        download_name=filename,
        mimetype="application/vnd.tcpdump.pcap"
    ) 
@app.route("/api/ml/status")          
def ml_status():
    return jsonify(anomaly_detector.get_status())

@app.route("/api/ml/retrain", methods=["POST"])
def ml_retrain():
    anomaly_detector.retrain()
    return jsonify({"message": "Retraining started"})

if __name__ == "__main__":
    logger = PacketLogger()

    print("\n" + "="*55)
    print("  Network Packet Analyzer — Web Dashboard")
    print("  Open your browser at: http://127.0.0.1:5000")
    print("="*55 + "\n")

    # Start sniffers FIRST before Flask loads
    threading.Thread(target=sniffer_thread,      daemon=True).start()
    threading.Thread(target=threat_intel_worker, daemon=True).start()

    # Give sniffer 2 seconds to start capturing before Flask launches
    time.sleep(2)
    print(f"[*] Sniffer running — packets so far: {total}")

    # Run Flask — use_reloader=False is critical on Windows
    app.run(
        host=config["web"]["host"],
        port=config["web"]["port"],
        debug=config["web"]["debug"],
        use_reloader=False,
        threaded=True,
    )