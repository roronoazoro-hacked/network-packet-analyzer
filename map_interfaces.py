from scapy.all import get_if_addr, get_if_list

for iface in get_if_list():
    try:
        ip = get_if_addr(iface)
        print(f"{iface}  --->  {ip}")
    except:
        pass