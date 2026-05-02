# MITRE ATT&CK technique mappings
# Format: detection_type -> (technique_id, technique_name, tactic)

TECHNIQUES = {
    # Network discovery
    "PORT_SCAN": (
        "T1046",
        "Network Service Discovery",
        "Discovery"
    ),

    # Remote access via risky ports
    "RDP": (
        "T1021.001",
        "Remote Services: RDP",
        "Lateral Movement"
    ),
    "SSH": (
        "T1021.004",
        "Remote Services: SSH",
        "Lateral Movement"
    ),
    "SMB": (
        "T1021.002",
        "Remote Services: SMB",
        "Lateral Movement"
    ),
    "TELNET": (
        "T1021",
        "Remote Services: Telnet",
        "Lateral Movement"
    ),

    # Command & Control
    "C2_BEACON": (
        "T1071",
        "Application Layer Protocol",
        "Command & Control"
    ),
    "DNS_TUNNEL": (
        "T1071.004",
        "DNS Application Layer Protocol",
        "Command & Control"
    ),
    "LONG_CONNECTION": (
        "T1571",
        "Non-Standard Port",
        "Command & Control"
    ),

    # Exfiltration
    "DATA_EXFIL": (
        "T1041",
        "Exfiltration Over C2 Channel",
        "Exfiltration"
    ),

    # Credential access
    "MSSQL": (
        "T1078",
        "Valid Accounts: DB Access",
        "Credential Access"
    ),

    # Threat intel hit
    "THREAT_INTEL": (
        "T1071",
        "Application Layer Protocol",
        "Command & Control"
    ),

    # Malware ports
    "MALWARE_PORT": (
        "T1095",
        "Non-Application Layer Protocol",
        "Command & Control"
    ),
}

# Port to technique mapping
PORT_TECHNIQUES = {
    22:   "SSH",
    23:   "TELNET",
    445:  "SMB",
    139:  "SMB",
    3389: "RDP",
    1433: "MSSQL",
    3306: "MSSQL",
    4444: "MALWARE_PORT",
    5555: "MALWARE_PORT",
    6666: "MALWARE_PORT",
    53:   "DNS_TUNNEL",
}

def get_technique(detection_type):
    """
    Get MITRE ATT&CK technique for a detection type.
    Returns (id, name, tactic) or None.
    """
    t = TECHNIQUES.get(detection_type)
    if not t:
        return None
    return {"id": t[0], "name": t[1], "tactic": t[2]}

def map_port(port):
    """Get technique for a specific port number."""
    detection = PORT_TECHNIQUES.get(port)
    if detection:
        return get_technique(detection)
    return None

def map_alert(alert_msg, dst_port=0):
    """
    Automatically map an alert message to a MITRE technique.
    Returns technique dict or None.
    """
    msg = alert_msg.upper()

    if "PORT SCAN" in msg:
        return get_technique("PORT_SCAN")
    if "ABUSEIPDB" in msg:
        return get_technique("THREAT_INTEL")
    if "EXFIL" in msg:
        return get_technique("DATA_EXFIL")
    if "BEACON" in msg:
        return get_technique("C2_BEACON")

    # Try port-based mapping
    if dst_port:
        t = map_port(dst_port)
        if t:
            return t

    return None

def format_technique(technique):
    """Format technique for display in dashboard."""
    if not technique:
        return ""
    return f"[{technique['id']}] {technique['name']} — {technique['tactic']}"