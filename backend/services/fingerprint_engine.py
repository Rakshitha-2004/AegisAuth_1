"""
AegisAuth - Digital Device Entropy Fingerprinting Engine
Generates deterministic hardware/browser fingerprints using SHA-256 hashing.
Completely software-based: Zero physical biometric scanners required.
"""
import hashlib
import json

def generate_device_hash(client_data: dict, request_headers: dict = None) -> str:
    """
    Computes a cryptographic SHA-256 hash of device entropy factors.
    Combines client-side hardware entropy (screen, timezone, cores) with server headers.
    """
    if client_data is None:
        client_data = {}
    if request_headers is None:
        request_headers = {}

    # Extract distinct entropy points
    entropy_payload = {
        "user_agent": str(client_data.get("user_agent") or request_headers.get("User-Agent", "unknown")).strip(),
        "platform": str(client_data.get("platform", "unknown")).strip(),
        "screen": str(client_data.get("screen_res", "unknown")).strip(),
        "timezone": str(client_data.get("timezone", "unknown")).strip(),
        "cores": str(client_data.get("cpu_cores", "unknown")).strip(),
        "accept_lang": str(request_headers.get("Accept-Language", "unknown")).split(",")[0].strip()
    }

    # Deterministic JSON string
    serialized = json.dumps(entropy_payload, sort_keys=True)
    device_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return device_hash

def evaluate_device(device_hash: str, user_profile: dict) -> dict:
    """
    Compares the calculated device hash against the user's historical known_devices list.
    """
    if not user_profile:
        return {
            "device_hash": device_hash,
            "is_new_device": True,
            "risk_weight": 20,
            "severity": "MEDIUM",
            "message": "Unfamiliar client device. Hardware signature has not been verified."
        }

    known_devices = user_profile.get("known_devices", [])

    if not known_devices:
        # First device registered by user
        return {
            "device_hash": device_hash,
            "is_new_device": False,
            "risk_weight": 0,
            "severity": "LOW",
            "message": "Initial client device enrolled into baseline."
        }

    if device_hash in known_devices:
        return {
            "device_hash": device_hash,
            "is_new_device": False,
            "risk_weight": 0,
            "severity": "LOW",
            "message": "Verified client device. Matches known hardware fingerprint."
        }

    return {
        "device_hash": device_hash,
        "is_new_device": True,
        "risk_weight": 35,
        "severity": "MEDIUM",
        "message": "Unfamiliar device fingerprint. Access originated from an unrecognized hardware profile."
    }
