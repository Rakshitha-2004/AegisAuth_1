"""
AegisAuth - Geolocation & IP Intelligence Engine
Resolves client IP addresses into Geographic Coordinates, Location Metadata, and Network Classification.
"""
import requests

# Curated reference locations for testing, private networks, and simulation
KNOWN_LOCATIONS = {
    "local": {"lat": 12.9716, "lon": 77.5946, "city": "Bengaluru", "country": "India", "country_code": "IN", "is_vpn": False},
    "frankfurt": {"lat": 50.1109, "lon": 8.6821, "city": "Frankfurt", "country": "Germany", "country_code": "DE", "is_vpn": True},
    "london": {"lat": 51.5074, "lon": -0.1278, "city": "London", "country": "United Kingdom", "country_code": "GB", "is_vpn": False},
    "new_york": {"lat": 40.7128, "lon": -74.0060, "city": "New York", "country": "United States", "country_code": "US", "is_vpn": False},
    "tokyo": {"lat": 35.6762, "lon": 139.6503, "city": "Tokyo", "country": "Japan", "country_code": "JP", "is_vpn": False},
    "toronto": {"lat": 43.6532, "lon": -79.3832, "city": "Toronto", "country": "Canada", "country_code": "CA", "is_vpn": False},
    "sydney": {"lat": -33.8688, "lon": 151.2093, "city": "Sydney", "country": "Australia", "country_code": "AU", "is_vpn": False},
    "datacenter_aws": {"lat": 38.9072, "lon": -77.0369, "city": "Ashburn (AWS)", "country": "United States", "country_code": "US", "is_vpn": True}
}

# Known datacenter and anonymizing network indicators
KNOWN_DATACENTER_ORGS = [
    "amazon", "aws", "digitalocean", "linode", "hetzner", "ovh", "google cloud", "microsoft azure", "m247", "tor exit"
]

def resolve_ip(ip_address: str, simulated_location: str = None) -> dict:
    """
    Resolves client IP into geographic and network metadata.
    If simulated_location is provided (for viva / testing), uses calibrated coordinates.
    """
    ip = (ip_address or "").strip()

    # 1. Check for manual simulation flag (useful for testing & viva demonstrations)
    if simulated_location and simulated_location.lower() in KNOWN_LOCATIONS:
        geo = KNOWN_LOCATIONS[simulated_location.lower()].copy()
        geo["ip"] = ip if ip else "198.51.100.24"
        geo["source"] = f"Simulated Scenario ({simulated_location.title()})"
        return geo

    # 2. Handle Localhost & Private Subnets
    if not ip or ip in ("127.0.0.1", "::1", "localhost") or ip.startswith(("192.168.", "10.", "172.16.")):
        geo = KNOWN_LOCATIONS["local"].copy()
        geo["ip"] = ip if ip else "127.0.0.1"
        geo["source"] = "Localhost / Internal Subnet"
        return geo

    # 3. Live Online Query via free IP-API with fallback
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,isp,org,as,proxy,hosting"
        res = requests.get(url, timeout=2.5)
        if res.status_code == 200:
            data = res.json()
            if data.get("status") == "success":
                org_str = (data.get("org", "") + " " + data.get("isp", "") + " " + data.get("as", "")).lower()
                is_datacenter = any(dc in org_str for dc in KNOWN_DATACENTER_ORGS) or data.get("hosting", False) or data.get("proxy", False)

                return {
                    "ip": ip,
                    "lat": float(data.get("lat", 12.9716)),
                    "lon": float(data.get("lon", 77.5946)),
                    "city": data.get("city", "Unknown City"),
                    "country": data.get("country", "Unknown Country"),
                    "country_code": data.get("countryCode", "XX"),
                    "isp": data.get("isp", "Unknown ISP"),
                    "is_vpn": bool(is_datacenter),
                    "source": "Live IP Intelligence"
                }
    except Exception:
        pass

    # Safe default fallback
    fallback = KNOWN_LOCATIONS["local"].copy()
    fallback["ip"] = ip
    fallback["source"] = "Default Fallback"
    return fallback
