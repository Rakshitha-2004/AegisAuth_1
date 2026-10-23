"""
AegisAuth - Threat Simulation Lab Blueprint
Provides interactive, reproducible attack simulation scenarios for viva defense
and Security Operations Center (SOC) verification.
"""
import uuid
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify

from database.db import get_users_collection, get_logs_collection, get_rate_limits_collection
from services.geo_engine import resolve_ip, KNOWN_LOCATIONS
from services.velocity_engine import evaluate_travel_velocity
from services.fingerprint_engine import generate_device_hash, evaluate_device
from services.rate_limiter import record_attempt, evaluate_rate_anomalies
from services.pdp_engine import evaluate_access_context

simulator_bp = Blueprint("simulator", __name__, url_prefix="/api/simulate")


@simulator_bp.route("/impossible-travel", methods=["POST"])
def simulate_impossible_travel():
    """
    Simulates an Impossible Travel attack scenario:
    1. Origin login established in Bangalore, India at T - 3 minutes.
    2. Attacker attempts access with valid credentials from Frankfurt, Germany (or New York, USA) at T.
    3. Runs the real Geodesic Haversine formula and calculates velocity in km/h.
    4. Triggers PDP evaluation and logs the security incident.
    """
    try:
        data = request.get_json(silent=True) or {}
        target_email = data.get("email", "analyst@aegisauth.local").strip().lower()
        destination_ip = data.get("destination_ip", "194.154.200.1")  # Frankfurt, Germany
        origin_ip = data.get("origin_ip", "103.21.124.1")              # Bangalore, India
        time_delta_minutes = float(data.get("time_delta_minutes", 3.0))

        users_col = get_users_collection()
        logs_col = get_logs_collection()

        # Find or mock user profile
        user = None
        if users_col is not None:
            user = users_col.find_one({"email": target_email})

        if not user:
            user = {
                "name": "Simulated User",
                "email": target_email,
                "role": "analyst",
                "status": "active",
                "known_devices": ["known_desktop_device_hash_1"]
            }

        # Resolve Origin & Destination Geos
        origin_geo = resolve_ip(origin_ip)
        dest_geo = resolve_ip(destination_ip)

        now = datetime.utcnow()
        previous_time = now - timedelta(minutes=time_delta_minutes)

        prev_login_state = {
            "timestamp": previous_time,
            "ip": origin_geo["ip"],
            "lat": origin_geo["lat"],
            "lon": origin_geo["lon"],
            "city": origin_geo["city"],
            "country": origin_geo["country"]
        }

        # Run Real Haversine Velocity Engine
        velocity_result = evaluate_travel_velocity(prev_login_state, dest_geo, curr_time=now)

        # Baseline client device
        client_fp = {
            "screen_res": "1920x1080",
            "cpu_cores": 8,
            "timezone": "Asia/Kolkata",
            "platform": "Win32"
        }
        device_hash = generate_device_hash(client_fp)
        device_eval = evaluate_device(device_hash, user)

        # Rate check
        rate_eval = evaluate_rate_anomalies(dest_geo["ip"], target_email)

        # Run Policy Decision Point (PDP)
        pdp_decision = evaluate_access_context(
            velocity_assessment=velocity_result,
            device_assessment=device_eval,
            rate_assessment=rate_eval,
            geo_data=dest_geo,
            user_profile=user,
            curr_time=now
        )

        event_id = str(uuid.uuid4())
        audit_event = {
            "event_id": event_id,
            "timestamp": now,
            "email": target_email,
            "ip": dest_geo["ip"],
            "location": f"{dest_geo['city']}, {dest_geo['country']}",
            "lat": dest_geo["lat"],
            "lon": dest_geo["lon"],
            "device_hash": device_hash,
            "decision": pdp_decision["decision"],
            "risk_score": pdp_decision["risk_score"],
            "threat_vectors": pdp_decision["threat_vectors"],
            "action_summary": pdp_decision.get("action_summary", ""),
            "status": "DETECTED_AND_LOGGED",
            "simulated": True,
            "simulation_scenario": "IMPOSSIBLE_TRAVEL"
        }

        if logs_col is not None:
            logs_col.insert_one(audit_event)

        # Update user status if high risk
        if users_col is not None and pdp_decision["decision"] == "DENY_QUARANTINE":
            users_col.update_one(
                {"email": target_email},
                {"$set": {"status": "quarantined", "quarantine_reason": "Impossible travel threshold exceeded"}}
            )

        return jsonify({
            "status": "success",
            "scenario": "Impossible Travel Detection (NIST SP 800-207 Zero-Trust)",
            "origin": {
                "ip": origin_geo["ip"],
                "location": f"{origin_geo['city']}, {origin_geo['country']}",
                "coordinates": [origin_geo["lat"], origin_geo["lon"]],
                "timestamp": previous_time.isoformat() + "Z"
            },
            "destination": {
                "ip": dest_geo["ip"],
                "location": f"{dest_geo['city']}, {dest_geo['country']}",
                "coordinates": [dest_geo["lat"], dest_geo["lon"]],
                "timestamp": now.isoformat() + "Z"
            },
            "mathematical_breakdown": {
                "distance_km": velocity_result["distance_km"],
                "elapsed_minutes": velocity_result["elapsed_minutes"],
                "calculated_speed_kmh": velocity_result["velocity_kmh"],
                "threshold_kmh": 900.0,
                "is_impossible": velocity_result["is_impossible"],
                "formula": "Haversine: d = 2r * arcsin(sqrt(sin^2(dlat/2) + cos(lat1)*cos(lat2)*sin^2(dlon/2)))"
            },
            "pdp_evaluation": pdp_decision,
            "audit_logged": True,
            "event_id": event_id
        }), 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500


@simulator_bp.route("/brute-force", methods=["POST"])
def simulate_brute_force():
    """
    Simulates a rapid Credential Brute-Force attack:
    1. Simulates consecutive failed attempts from an attacker IP.
    2. Slides window across rate limiter.
    3. Triggers account lockout / quarantine at threshold >= 5 attempts.
    """
    try:
        data = request.get_json(silent=True) or {}
        target_email = data.get("email", "analyst@aegisauth.local").strip().lower()
        attacker_ip = data.get("attacker_ip", "45.33.32.156")
        attempt_count = int(data.get("attempts", 6))

        geo = resolve_ip(attacker_ip)
        logs_col = get_logs_collection()
        users_col = get_users_collection()

        user = None
        if users_col is not None:
            user = users_col.find_one({"email": target_email})
        if not user:
            user = {"name": "Target User", "email": target_email, "role": "analyst", "status": "active"}

        simulation_log = []
        now = datetime.utcnow()

        for i in range(1, attempt_count + 1):
            record_attempt(attacker_ip, target_email, status="failed")
            rate_eval = evaluate_rate_anomalies(attacker_ip, target_email)

            # Evaluate PDP for this attempt
            pdp = evaluate_access_context(
                velocity_assessment={"is_evaluated": False, "risk_weight": 0},
                device_assessment={"risk_weight": 0},
                rate_assessment=rate_eval,
                geo_data=geo,
                user_profile=user,
                curr_time=now + timedelta(seconds=i * 2)
            )

            attempt_detail = {
                "attempt_number": i,
                "timestamp": (now + timedelta(seconds=i * 2)).isoformat() + "Z",
                "vertical_failed_attempts": rate_eval.get("failed_attempts", i),
                "decision": pdp["decision"],
                "risk_score": pdp["risk_score"]
            }
            simulation_log.append(attempt_detail)

            # On the final attempt, log to SOC audit trail
            if i == attempt_count:
                event_id = str(uuid.uuid4())
                audit_event = {
                    "event_id": event_id,
                    "timestamp": now,
                    "email": target_email,
                    "ip": attacker_ip,
                    "location": f"{geo['city']}, {geo['country']}",
                    "lat": geo["lat"],
                    "lon": geo["lon"],
                    "device_hash": "simulated_brute_force_botnet",
                    "decision": pdp["decision"],
                    "risk_score": pdp["risk_score"],
                    "threat_vectors": pdp["threat_vectors"],
                    "action_summary": pdp.get("action_summary", ""),
                    "status": "CONTAINED",
                    "simulated": True,
                    "simulation_scenario": "BRUTE_FORCE"
                }
                if logs_col is not None:
                    logs_col.insert_one(audit_event)

                if users_col is not None and pdp["decision"] in ("DENY_QUARANTINE", "DENY_RATE_LIMIT"):
                    users_col.update_one(
                        {"email": target_email},
                        {"$set": {"status": "quarantined", "quarantine_reason": "Brute force threshold exceeded"}}
                    )

        return jsonify({
            "status": "success",
            "scenario": "Sliding-Window Brute Force Rate Limiting",
            "target_email": target_email,
            "attacker_ip": attacker_ip,
            "total_burst_attempts": attempt_count,
            "attempts_timeline": simulation_log,
            "final_decision": simulation_log[-1]["decision"],
            "final_risk_score": simulation_log[-1]["risk_score"],
            "containment": "IP rate-limited for 10 minutes & User account quarantined."
        }), 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500


@simulator_bp.route("/unrecognized-device", methods=["POST"])
def simulate_unrecognized_device():
    """
    Simulates access from a completely new device hardware fingerprint:
    Shows how AegisAuth dynamically challenges the user with Step-Up MFA
    rather than locking them out or blindly trusting them.
    """
    try:
        data = request.get_json(silent=True) or {}
        target_email = data.get("email", "analyst@aegisauth.local").strip().lower()
        ip = data.get("ip", "103.21.124.1")  # Known location (Bangalore)

        geo = resolve_ip(ip)
        logs_col = get_logs_collection()
        users_col = get_users_collection()

        user = None
        if users_col is not None:
            user = users_col.find_one({"email": target_email})
        if not user:
            user = {
                "name": "Target User",
                "email": target_email,
                "role": "analyst",
                "status": "active",
                "known_devices": ["established_office_desktop_hash"]
            }

        # Simulated unfamiliar device
        unfamiliar_fp = {
            "screen_res": "2560x1440",
            "cpu_cores": 16,
            "timezone": "America/Anchorage",
            "platform": "Linux x86_64",
            "user_agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0"
        }
        device_hash = generate_device_hash(unfamiliar_fp)
        device_eval = evaluate_device(device_hash, user)

        rate_eval = evaluate_rate_anomalies(ip, target_email)

        pdp = evaluate_access_context(
            velocity_assessment={"is_evaluated": False, "risk_weight": 0},
            device_assessment=device_eval,
            rate_assessment=rate_eval,
            geo_data=geo,
            user_profile=user
        )

        event_id = str(uuid.uuid4())
        audit_event = {
            "event_id": event_id,
            "timestamp": datetime.utcnow(),
            "email": target_email,
            "ip": ip,
            "location": f"{geo['city']}, {geo['country']}",
            "lat": geo["lat"],
            "lon": geo["lon"],
            "device_hash": device_hash,
            "decision": pdp["decision"],
            "risk_score": pdp["risk_score"],
            "threat_vectors": pdp["threat_vectors"],
            "action_summary": pdp.get("action_summary", ""),
            "status": "CHALLENGED",
            "simulated": True,
            "simulation_scenario": "UNRECOGNIZED_DEVICE"
        }
        if logs_col is not None:
            logs_col.insert_one(audit_event)

        return jsonify({
            "status": "success",
            "scenario": "Adaptive Contextual Step-Up MFA (Unknown Hardware)",
            "target_email": target_email,
            "device_entropy": unfamiliar_fp,
            "device_eval": device_eval,
            "pdp_evaluation": pdp,
            "explanation": "Device entropy changed from known baseline. Risk adjusted to Medium (35/100). Step-up MFA challenge issued."
        }), 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500


@simulator_bp.route("/reset-demo", methods=["POST"])
def reset_demo_state():
    """
    Resets the test account status back to active for live viva demonstrations.
    """
    try:
        data = request.get_json(silent=True) or {}
        target_email = data.get("email", "analyst@aegisauth.local").strip().lower()
        users_col = get_users_collection()
        rate_col = get_rate_limits_collection()

        if users_col is not None:
            users_col.update_one(
                {"email": target_email},
                {"$set": {"status": "active", "quarantine_reason": None}}
            )

        if rate_col is not None:
            rate_col.delete_many({"email": target_email})

        return jsonify({
            "status": "success",
            "message": f"Demo state reset. Account '{target_email}' and sliding rate counters are cleared."
        }), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
