import requests
from functools import lru_cache

PRIVATE_RANGES = [
    "10.", "192.168.", "127.", "169.254.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
    "172.31.", "224.", "239."
]

def is_private(ip):
    return any(ip.startswith(r) for r in PRIVATE_RANGES)

def iso_to_flag(iso):
    """Convert country ISO code like 'IN' to flag emoji 🇮🇳"""
    if iso and len(iso) == 2:
        return chr(ord(iso[0]) + 127397) + chr(ord(iso[1]) + 127397)
    return "?"

@lru_cache(maxsize=512)
def lookup(ip):
    """
    Look up IP location using ip-api.com (free, no key needed).
    Results are cached so same IP is never looked up twice.
    """
    if is_private(ip):
        return {"country": "Local", "city": "", "flag": "🏠", "isp": "Local network"}

    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,city,isp"},
            timeout=2
        )
        data = r.json()
        if data.get("status") == "success":
            return {
                "country": data.get("country", "Unknown"),
                "city":    data.get("city", ""),
                "flag":    iso_to_flag(data.get("countryCode", "")),
                "isp":     data.get("isp", ""),
            }
    except Exception:
        pass

    return {"country": "Unknown", "city": "", "flag": "?", "isp": ""}

def format_location(ip):
    """Returns short string like  🇮🇳 India · Mumbai"""
    if is_private(ip):
        return "🏠 Local network"
    info = lookup(ip)
    parts = [info["flag"], info["country"]]
    if info["city"]:
        parts.append(f"· {info['city']}")
    return " ".join(p for p in parts if p)