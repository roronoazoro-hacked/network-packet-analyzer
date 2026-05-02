from scapy.all import sniff


def start_sniffing(callback, interface=None, packet_filter="ip", count=0):
    print(f"[*] Starting capture on interface: {interface or 'default'}")
    print(f"[*] Filter: {packet_filter}")
    print(f"[*] Press Ctrl+C to stop\n")

    kwargs = {
        "iface": interface,
        "prn": callback,
        "store": False,
        "count": count,
    }

    # only add filter if it's not None or empty
    if packet_filter:
        kwargs["filter"] = packet_filter

    sniff(**kwargs)