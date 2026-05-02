from scapy.all import IP, TCP, UDP, ICMP, DNS, Raw
from datetime import datetime

SUSPICIOUS_TLDS = (".ru", ".cn", ".tk", ".xyz")

def parse_packet(packet):
    ip_layer = packet.getlayer(IP)

    if not ip_layer:
        return None

    protocol = "UNKNOWN"
    dst_port = None
    info = ""
    alert = None

    # ───────── TCP ─────────
    if packet.haslayer(TCP):
        protocol = "TCP"
        sport = packet[TCP].sport
        dst_port = packet[TCP].dport

        info = f"{sport} -> {dst_port}"

        # 🔥 HTTP ANALYSIS
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode(errors="ignore")

                if payload.startswith("GET") or payload.startswith("POST"):
                    lines = payload.split("\r\n")
                    request_line = lines[0]

                    host = ""
                    for line in lines:
                        if line.lower().startswith("host:"):
                            host = line.split(":", 1)[1].strip()

                    info = f"HTTP {request_line} | Host: {host}"

                    # 🚨 suspicious domain detection
                    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
                        alert = f"Suspicious HTTP domain: {host}"

            except:
                pass

    # ───────── UDP ─────────
    elif packet.haslayer(UDP):
        protocol = "UDP"
        sport = packet[UDP].sport
        dst_port = packet[UDP].dport

        info = f"{sport} -> {dst_port}"

        # 🔥 DNS ANALYSIS
        if packet.haslayer(DNS) and packet[DNS].qd:
            try:
                domain = packet[DNS].qd.qname.decode(errors="ignore")
                info = f"DNS Query: {domain}"

                # 🚨 suspicious domain detection
                if any(domain.endswith(tld + ".") for tld in SUSPICIOUS_TLDS):
                    alert = f"Suspicious DNS query: {domain}"

            except:
                pass

    # ───────── ICMP ─────────
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
        info = "ICMP Echo"

    return {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "protocol": protocol,
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "dst_port": dst_port,
        "info": info,
        "alert": alert,
    }