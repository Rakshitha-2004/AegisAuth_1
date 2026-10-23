"""
AegisAuth - Zero-Trust Policy Decision Point (PDP)
Implements NIST SP 800-207 Zero-Trust Access Evaluation:
Aggregates multidimensional context vectors into an adaptive composite risk score (0-100)
and enforces automated access decisions: ALLOW, CHALLENGE_MFA, or DENY_QUARANTINE.
"""
from datetime import datetime
from config import Config

def evaluate_access_context(
    velocity_assessment: dict,
    device_assessment: dict,
    rate_assessment: dict,
    geo_data: dict,
    user_profile: dict,
    curr_time: datetime = None
) -> dict:
    """
    Evaluates the complete context of an authentication attempt and produces
    the Zero-Trust Policy Decision, Composite Risk Score, and Explainable Evidence Breakdown.
    """
    if curr_time is None:
        curr_time = datetime.utcnow()

    threat_vectors = []
    accumulated_points = 0
    has_critical_vector = False

    # 1. Geodesic Velocity & Impossible Travel Vector
    if velocity_assessment.get("is_evaluated"):
        v_weight = velocity_assessment.get("risk_weight", 0)
        if v_weight > 0:
            accumulated_points += v_weight
            sev = velocity_assessment.get("severity", "MEDIUM")
            if sev == "CRITICAL":
                has_critical_vector = True
            threat_vectors.append({
                "vector": "Geodesic Velocity Anomaly",
                "severity": sev,
                "weight": v_weight,
                "details": velocity_assessment.get("message"),
                "metrics": {
                    "distance_km": velocity_assessment.get("distance_km"),
                    "elapsed_minutes": velocity_assessment.get("elapsed_minutes"),
                    "velocity_kmh": velocity_assessment.get("velocity_kmh")
                }
            })

    # 2. Client Device Entropy Fingerprint Vector
    d_weight = device_assessment.get("risk_weight", 0)
    if d_weight > 0:
        accumulated_points += d_weight
        threat_vectors.append({
            "vector": "Unfamiliar Device Fingerprint",
            "severity": device_assessment.get("severity", "MEDIUM"),
            "weight": d_weight,
            "details": device_assessment.get("message"),
            "metrics": {
                "device_hash": device_assessment.get("device_hash")[:16] + "..."
            }
        })

    # 3. Rate-Limiting / Brute Force / Credential Stuffing Vector
    r_weight = rate_assessment.get("risk_weight", 0)
    if r_weight > 0:
        accumulated_points += r_weight
        has_critical_vector = True
        vector_name = "Credential Stuffing Pattern" if rate_assessment.get("is_stuffing") else "Brute Force Threshold Exceeded"
        threat_vectors.append({
            "vector": vector_name,
            "severity": "CRITICAL",
            "weight": r_weight,
            "details": rate_assessment.get("message"),
            "metrics": {
                "failed_count": rate_assessment.get("failed_attempts", 0),
                "stuffing_targets": rate_assessment.get("targeted_accounts_count", 0)
            }
        })

    # 4. Network ASN / Datacenter / Commercial VPN Vector
    if geo_data.get("is_vpn"):
        vpn_weight = 25
        accumulated_points += vpn_weight
        threat_vectors.append({
            "vector": "Anonymizing Datacenter / VPN Network",
            "severity": "MEDIUM",
            "weight": vpn_weight,
            "details": f"Connection originated from hosting datacenter or commercial VPN infrastructure ({geo_data.get('isp', 'Datacenter')}).",
            "metrics": {
                "isp": geo_data.get("isp"),
                "country": geo_data.get("country")
            }
        })

    # 5. Temporal Activity Deviation (Off-Hours Anomaly)
    curr_hour = curr_time.hour
    # Typical baseline: active between 07:00 and 23:00 UTC/local
    if 1 <= curr_hour <= 5:
        temporal_weight = 15
        accumulated_points += temporal_weight
        threat_vectors.append({
            "vector": "Temporal Baseline Deviation",
            "severity": "LOW",
            "weight": temporal_weight,
            "details": f"Access initiated during historical dormant hours ({curr_hour:02d}:00 UTC).",
            "metrics": {
                "access_hour": curr_hour
            }
        })

    # Enforce minimum risk floor if any critical vector is triggered
    if has_critical_vector:
        accumulated_points = max(Config.QUARANTINE_SCORE_THRESHOLD, accumulated_points)

    # Calculate final calibrated composite risk score (0 to 100)
    risk_score = max(0, min(100, accumulated_points))

    # Zero Trust Policy Decision
    if risk_score >= Config.QUARANTINE_SCORE_THRESHOLD:
        decision = "DENY_QUARANTINE"
        risk_level = "Critical Threat"
        action_summary = "Access Terminated & Account Quarantined: Severe risk exceeds safe thresholds."
        color = "#ef4444"
    elif risk_score >= Config.MFA_REQUIRED_SCORE_THRESHOLD:
        decision = "CHALLENGE_MFA"
        risk_level = "Suspicious Access"
        action_summary = "Adaptive Step-Up Required: Mandatory 6-digit challenge code must be verified."
        color = "#f59e0b"
    else:
        decision = "ALLOW"
        risk_level = "Low Risk"
        action_summary = "Access Granted: Behavioral and environmental vectors verified within safe parameters."
        color = "#10b981"

    return {
        "decision": decision,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "color": color,
        "action_summary": action_summary,
        "threat_vector_count": len(threat_vectors),
        "threat_vectors": threat_vectors,
        "geo_summary": {
            "ip": geo_data.get("ip"),
            "city": geo_data.get("city"),
            "country": geo_data.get("country"),
            "country_code": geo_data.get("country_code"),
            "lat": geo_data.get("lat"),
            "lon": geo_data.get("lon")
        },
        "evaluated_at": curr_time.isoformat() + "Z"
    }
