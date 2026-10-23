"""
AegisAuth - Geodesic Velocity & Impossible Travel Engine
Implements the Great-Circle Haversine Formula (Spherical Trigonometry) to detect
physically impossible travel anomalies between consecutive user access events.
"""
import math
from datetime import datetime

EARTH_RADIUS_KM = 6371.0  # Mean radius of Earth in kilometers

def calculate_haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """
    Calculates the great-circle geodesic distance between two points on Earth
    using the Haversine trigonometric formula.
    Returns distance in kilometers.
    """
    # Convert decimal degrees to radians
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    # Haversine formula
    a = (math.sin(delta_phi / 2.0) ** 2 +
         math.cos(phi1) * math.cos(phi2) * (math.sin(delta_lambda / 2.0) ** 2))
    
    # Avoid floating precision overflow
    a = min(1.0, max(0.0, a))
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))

    distance = EARTH_RADIUS_KM * c
    return round(distance, 2)

def evaluate_travel_velocity(prev_event: dict, curr_geo: dict, curr_time: datetime = None) -> dict:
    """
    Evaluates physical travel feasibility between previous verified access and current attempt.
    """
    if curr_time is None:
        curr_time = datetime.utcnow()

    # If no previous login exists (first-time login), no travel velocity can be computed
    if not prev_event or not prev_event.get("timestamp") or prev_event.get("lat") is None:
        return {
            "is_evaluated": False,
            "is_impossible": False,
            "distance_km": 0.0,
            "elapsed_minutes": 0.0,
            "velocity_kmh": 0.0,
            "risk_weight": 0,
            "severity": "LOW",
            "message": "First observed access event. Baseline initialized."
        }

    prev_lat = float(prev_event["lat"])
    prev_lon = float(prev_event["lon"])
    curr_lat = float(curr_geo["lat"])
    curr_lon = float(curr_geo["lon"])

    prev_time = prev_event["timestamp"]
    if isinstance(prev_time, str):
        try:
            prev_time = datetime.fromisoformat(prev_time.replace("Z", "+00:00")).replace(tzinfo=None)
        except Exception:
            prev_time = curr_time

    # Calculate time delta in hours
    time_delta = curr_time - prev_time
    total_seconds = max(1.0, time_delta.total_seconds())
    elapsed_hours = total_seconds / 3600.0
    elapsed_minutes = round(total_seconds / 60.0, 1)

    # Calculate geodesic distance
    distance_km = calculate_haversine_distance(prev_lat, prev_lon, curr_lat, curr_lon)

    # Compute physical velocity
    velocity_kmh = round(distance_km / elapsed_hours, 1)

    # Security Thresholds
    # 1. Supersonic / Physically Impossible Travel (> 900 km/h)
    if velocity_kmh > 900.0 and distance_km > 100.0:
        return {
            "is_evaluated": True,
            "is_impossible": True,
            "distance_km": distance_km,
            "elapsed_minutes": elapsed_minutes,
            "velocity_kmh": velocity_kmh,
            "risk_weight": 60,
            "severity": "CRITICAL",
            "message": (
                f"Impossible Travel Anomaly detected: Distance of {distance_km:,} km traversed in "
                f"{elapsed_minutes} minutes (calculated velocity: {velocity_kmh:,} km/h). "
                f"Exceeds commercial aviation limits (900 km/h)."
            )
        }

    # 2. Feasible Flight Transit (120 to 900 km/h)
    if velocity_kmh >= 120.0 and distance_km > 150.0:
        return {
            "is_evaluated": True,
            "is_impossible": False,
            "distance_km": distance_km,
            "elapsed_minutes": elapsed_minutes,
            "velocity_kmh": velocity_kmh,
            "risk_weight": 25,
            "severity": "MEDIUM",
            "message": (
                f"High-Speed Transit: Distance of {distance_km:,} km in {elapsed_minutes} mins "
                f"({velocity_kmh:,} km/h). Plausible via air travel, but warrants adaptive verification."
            )
        }

    # 3. Normal Ground / Commuter Speed (< 120 km/h or same city)
    return {
        "is_evaluated": True,
        "is_impossible": False,
        "distance_km": distance_km,
        "elapsed_minutes": elapsed_minutes,
        "velocity_kmh": velocity_kmh,
        "risk_weight": 0,
        "severity": "LOW",
        "message": f"Normal geodesic velocity: {distance_km} km over {elapsed_minutes} mins ({velocity_kmh} km/h)."
    }
