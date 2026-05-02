import requests
import os
from functools import lru_cache
from datetime import datetime
from dotenv import load_dotenv
from config import load_config

load_dotenv()

API_KEY       = os.getenv("ABUSEIPDB_KEY")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
_cfg          = load_config()

PRIVATE_RANGES = [
    "10.", "192.168.", "127.", "169.254.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
    "172.31.", "224.", "239."
]

def is_private(ip):
    return any(ip.startswith(r) for r in PRIVATE_RANGES)

@lru_cache(maxsize=512)
def check_ip(ip):
    if is_private(ip):
        return None
    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers={
                "Key":    API_KEY,
                "Accept": "application/json",
            },
            params={
                "ipAddress":    ip,
                "maxAgeInDays": _cfg["threat_intel"]["max_age_days"],
            },
            timeout=3,
        )
        data = response.json().get("data", {})
        return {
            "score":   data.get("abuseConfidenceScore", 0),
            "reports": data.get("totalReports", 0),
            "country": data.get("countryCode", ""),
            "isp":     data.get("isp", ""),
            "checked": datetime.now().strftime("%H:%M:%S"),
        }
    except Exception:
        return None

def get_threat_level(score):
    if score >= 80: return "CRITICAL", "bold white on red"
    if score >= 50: return "HIGH",     "bold red"
    if score >= 20: return "MEDIUM",   "bold yellow"
    if score > 0:   return "LOW",      "yellow"
    return "CLEAN", "dim green"

def format_threat(ip):
    result = check_ip(ip)
    if not result:
        return ""
    score = result["score"]
    level, _ = get_threat_level(score)
    if level == "CLEAN":
        return ""
    return f"[AbuseIPDB {score}% — {level}]"