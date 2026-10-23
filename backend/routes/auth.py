"""
AegisAuth - Zero-Trust Authentication Blueprint
Endpoints for Register, Context-Aware Login, Step-Up MFA Challenge, and Session Revocation.
"""
import re
import uuid
from datetime import datetime
from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from bson import ObjectId

from database.db import get_users_collection, get_logs_collection, get_sessions_collection
from services.geo_engine import resolve_ip
from services.velocity_engine import evaluate_travel_velocity
from services.fingerprint_engine import generate_device_hash, evaluate_device
from services.rate_limiter import record_attempt, evaluate_rate_anomalies
from services.pdp_engine import evaluate_access_context
from utils.jwt_helper import generate_access_token, generate_mfa_challenge_token, decode_token, jwt_required
from utils.otp_helper import generate_otp, get_otp_expiration, dispatch_challenge_code

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

EMAIL_REGEX = r"^[\w\.-]+@[\w\.-]+\.\w+$"

@auth_bp.route("/register", methods=["POST"])
def register():
    """Enrolls a new user into AegisAuth and establishes their initial baseline."""
    try:
        data = request.get_json(silent=True) or {}
        name = str(data.get("name", "")).strip()
        email = str(data.get("email", "")).strip().lower()
        password = str(data.get("password", ""))
        confirm_password = str(data.get("confirmPassword", ""))
        role = str(data.get("role", "analyst")).strip().lower()
        if role not in ("analyst", "administrator", "student", "faculty"):
            role = "analyst"

        # Validations
        if not name:
            return jsonify({"status": "error", "message": "Full name is required."}), 400
        if not email or not re.match(EMAIL_REGEX, email):
            return jsonify({"status": "error", "message": "Please enter a valid email address."}), 400
        if len(password) < 6:
            return jsonify({"status": "error", "message": "Password must be at least 6 characters long."}), 400
        if confirm_password and password != confirm_password:
            return jsonify({"status": "error", "message": "Passwords do not match."}), 400

        users_col = get_users_collection()
        if users_col is None:
            return jsonify({"status": "error", "message": "Database service is offline."}), 503

        if users_col.find_one({"email": email}):
            return jsonify({"status": "error", "message": "An account with this email already exists."}), 409

        # Capture client context for initial enrollment
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()
        client_data = data.get("client_fingerprint") or {}
        device_hash = generate_device_hash(client_data, dict(request.headers))
        geo = resolve_ip(client_ip)

        now = datetime.utcnow()
        new_user = {
            "name": name,
            "email": email,
            "password_hash": generate_password_hash(password),
            "role": role,
            "status": "active",  # "active" or "quarantined"
            "known_devices": [device_hash],
            "last_login": {
                "timestamp": now,
                "ip": geo["ip"],
                "lat": geo["lat"],
                "lon": geo["lon"],
                "city": geo["city"],
                "country": geo["country"]
            },
            "created_at": now
        }

        result = users_col.insert_one(new_user)
        return jsonify({
            "status": "success",
            "message": "User enrolled successfully! Baseline security context initialized.",
            "user_id": str(result.inserted_id)
        }), 201
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": f"Registration error: {str(e)}"}), 500

@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Context-Aware Zero-Trust Authentication Endpoint.
    Evaluates Geodesic Velocity, Device Entropy, Network ASN, and Sliding-Window Rate Limits
    before granting access or demanding adaptive MFA step-up.
    """
    try:
        data = request.get_json(silent=True) or {}
        email = str(data.get("email", "")).strip().lower()
        password = str(data.get("password", ""))
        client_fingerprint = data.get("client_fingerprint") or {}

        # Optional test simulation parameters (for live viva & lab test scenarios)
        simulated_location = data.get("simulated_location")  # e.g. "frankfurt", "london", "tokyo"
        simulated_ip = data.get("simulated_ip")

        if not email or not password:
            return jsonify({"status": "error", "message": "Email and password are required."}), 400

        users_col = get_users_collection()
        logs_col = get_logs_collection()
        sessions_col = get_sessions_collection()

        if users_col is None:
            return jsonify({"status": "error", "message": "Database service is offline."}), 503

        # Resolve IP address
        real_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1").split(",")[0].strip()
        client_ip = simulated_ip or real_ip

        # 1. Evaluate sliding window rate limits (Brute Force & Credential Stuffing)
        rate_assessment = evaluate_rate_anomalies(client_ip, email)

        # 2. Query user record
        user = users_col.find_one({"email": email})

        # If user does not exist or password mismatch
        if not user or not check_password_hash(user.get("password_hash", ""), password):
            record_attempt(client_ip, email, status="failed")
            # If account is being brute-forced, log security event
            if rate_assessment.get("is_brute_force") or rate_assessment.get("is_stuffing"):
                _log_security_event(
                    email=email,
                    user_id=str(user["_id"]) if user else None,
                    ip=client_ip,
                    decision="DENY_RATE_LIMIT",
                    risk_score=85,
                    risk_level="Critical Threat",
                    vectors=[rate_assessment],
                    geo=resolve_ip(client_ip, simulated_location)
                )
            return jsonify({
                "status": "error",
                "message": "Invalid email or password. Please verify your credentials."
            }), 401

        # Check if account is already quarantined
        if user.get("status") == "quarantined":
            return jsonify({
                "status": "error",
                "message": "Account has been quarantined by AegisAuth due to severe security violations. Contact Security Administrator."
            }), 403

        # 3. Resolve Geolocation Metadata
        geo = resolve_ip(client_ip, simulated_location)

        # 4. Evaluate Geodesic Travel Velocity (Haversine Formula)
        velocity_assessment = evaluate_travel_velocity(user.get("last_login"), geo)

        # 5. Evaluate Client Device Entropy Fingerprint
        device_hash = generate_device_hash(client_fingerprint, dict(request.headers))
        device_assessment = evaluate_device(device_hash, user)

        # 6. Execute Zero-Trust Policy Decision Point (PDP)
        pdp_result = evaluate_access_context(
            velocity_assessment=velocity_assessment,
            device_assessment=device_assessment,
            rate_assessment=rate_assessment,
            geo_data=geo,
            user_profile=user
        )

        user_id = str(user["_id"])
        decision = pdp_result["decision"]
        risk_score = pdp_result["risk_score"]

        # Record successful password attempt in rate limiter
        record_attempt(client_ip, email, status="success")

        # Log security audit record
        event_id = _log_security_event(
            email=email,
            user_id=user_id,
            ip=client_ip,
            decision=decision,
            risk_score=risk_score,
            risk_level=pdp_result["risk_level"],
            vectors=pdp_result["threat_vectors"],
            geo=geo,
            velocity_kmh=velocity_assessment.get("velocity_kmh", 0)
        )

        # -------------------------------------------------------------
        # ADAPTIVE POLICY ENFORCEMENT ACTIONS
        # -------------------------------------------------------------

        # CASE A: CRITICAL THREAT (DENY & QUARANTINE ACCOUNT)
        if decision == "DENY_QUARANTINE":
            users_col.update_one({"_id": user["_id"]}, {"$set": {"status": "quarantined"}})
            # Revoke any active sessions
            if sessions_col is not None:
                sessions_col.delete_many({"user_id": user_id})

            return jsonify({
                "status": "denied",
                "decision": "DENY_QUARANTINE",
                "risk_score": risk_score,
                "risk_level": pdp_result["risk_level"],
                "message": "Access Terminated & Account Quarantined: Critical security anomaly detected.",
                "pdp_evaluation": pdp_result
            }), 403

        # CASE B: SUSPICIOUS ACCESS (CHALLENGE WITH STEP-UP MFA)
        if decision == "CHALLENGE_MFA":
            otp_code = generate_otp()
            expires_at = get_otp_expiration(minutes=5)
            context_id = str(uuid.uuid4())

            # Save step-up challenge state in user document
            users_col.update_one(
                {"_id": user["_id"]},
                {"$set": {
                    "mfa_challenge": {
                        "code": otp_code,
                        "expires_at": expires_at,
                        "context_id": context_id,
                        "pending_geo": geo,
                        "pending_device": device_hash,
                        "risk_score": risk_score
                    }
                }}
            )

            dispatch_info = dispatch_challenge_code(
                email=email,
                code=otp_code,
                reason=f"Adaptive Step-Up Required (Risk Score: {risk_score}/100)"
            )

            mfa_token = generate_mfa_challenge_token(user_id, email, context_id)

            return jsonify({
                "status": "challenge",
                "decision": "CHALLENGE_MFA",
                "risk_score": risk_score,
                "risk_level": pdp_result["risk_level"],
                "message": "Security verification required. Enter the 6-digit challenge code to proceed.",
                "mfa_token": mfa_token,
                "dev_hint": f"Development Code: {otp_code}",
                "pdp_evaluation": pdp_result
            }), 200

        # CASE C: LOW RISK (ALLOW DIRECT ACCESS)
        session_id = str(uuid.uuid4())
        access_token = generate_access_token(
            user_id=user_id,
            email=email,
            name=user.get("name", "User"),
            role=user.get("role", "analyst"),
            session_id=session_id
        )

        # Update last login baseline and enroll verified device
        users_col.update_one(
            {"_id": user["_id"]},
            {
                "$set": {
                    "last_login": {
                        "timestamp": datetime.utcnow(),
                        "ip": geo["ip"],
                        "lat": geo["lat"],
                        "lon": geo["lon"],
                        "city": geo["city"],
                        "country": geo["country"]
                    }
                },
                "$addToSet": {"known_devices": device_hash}
            }
        )

        # Register active session
        if sessions_col is not None:
            sessions_col.insert_one({
                "session_id": session_id,
                "user_id": user_id,
                "email": email,
                "device_hash": device_hash,
                "ip": client_ip,
                "location": f"{geo['city']}, {geo['country']}",
                "created_at": datetime.utcnow()
            })

        return jsonify({
            "status": "success",
            "decision": "ALLOW",
            "risk_score": risk_score,
            "risk_level": pdp_result["risk_level"],
            "message": "Zero-Trust verification passed. Session authenticated.",
            "token": access_token,
            "user": {
                "id": user_id,
                "name": user.get("name", "User"),
                "email": user["email"],
                "role": user.get("role", "analyst")
            },
            "pdp_evaluation": pdp_result
        }), 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": f"Authentication server error: {str(e)}"}), 500

@auth_bp.route("/verify-mfa", methods=["POST"])
def verify_mfa():
    """Verifies the 6-digit challenge code for an adaptive Step-Up MFA event."""
    try:
        data = request.get_json(silent=True) or {}
        mfa_token = str(data.get("mfa_token") or data.get("token") or "").strip()
        code = str(data.get("code") or data.get("otp_code") or data.get("otp") or "").strip()

        if not mfa_token or not code:
            return jsonify({"status": "error", "message": "MFA token and verification code are required."}), 400

        payload = decode_token(mfa_token, expected_type="mfa_challenge")
        if not payload:
            return jsonify({"status": "error", "message": "MFA challenge has expired. Please log in again."}), 401

        users_col = get_users_collection()
        sessions_col = get_sessions_collection()
        user = users_col.find_one({"_id": ObjectId(payload["sub"])})

        if not user or not user.get("mfa_challenge"):
            return jsonify({"status": "error", "message": "No active MFA challenge found."}), 400

        challenge = user["mfa_challenge"]
        if challenge.get("code") != code:
            return jsonify({"status": "error", "message": "Invalid challenge code. Please try again."}), 400

        if datetime.utcnow() > challenge.get("expires_at", datetime.min):
            return jsonify({"status": "error", "message": "Challenge code has expired. Please re-authenticate."}), 400

        # Step-Up succeeded! Enroll pending context into baseline
        pending_geo = challenge.get("pending_geo") or {}
        pending_device = challenge.get("pending_device")
        user_id = str(user["_id"])

        update_query = {
            "$unset": {"mfa_challenge": ""},
            "$set": {
                "last_login": {
                    "timestamp": datetime.utcnow(),
                    "ip": pending_geo.get("ip", "127.0.0.1"),
                    "lat": pending_geo.get("lat", 12.9716),
                    "lon": pending_geo.get("lon", 77.5946),
                    "city": pending_geo.get("city", "Verified City"),
                    "country": pending_geo.get("country", "Verified Country")
                }
            }
        }
        if pending_device:
            update_query["$addToSet"] = {"known_devices": pending_device}

        users_col.update_one({"_id": user["_id"]}, update_query)

        session_id = str(uuid.uuid4())
        access_token = generate_access_token(
            user_id=user_id,
            email=user["email"],
            name=user.get("name", "User"),
            role=user.get("role", "analyst"),
            session_id=session_id
        )

        if sessions_col is not None:
            sessions_col.insert_one({
                "session_id": session_id,
                "user_id": user_id,
                "email": user["email"],
                "device_hash": pending_device or "mfa_verified",
                "ip": pending_geo.get("ip", "127.0.0.1"),
                "location": f"{pending_geo.get('city')}, {pending_geo.get('country')}",
                "created_at": datetime.utcnow()
            })

        return jsonify({
            "status": "success",
            "message": "Step-Up verification successful! Access granted.",
            "token": access_token,
            "user": {
                "id": user_id,
                "name": user.get("name", "User"),
                "email": user["email"],
                "role": user.get("role", "analyst")
            }
        }), 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": f"MFA verification error: {str(e)}"}), 500

@auth_bp.route("/me", methods=["GET"])
@jwt_required
def get_current_user(current_user):
    return jsonify({
        "status": "success",
        "user": current_user
    }), 200

def _log_security_event(email, user_id, ip, decision, risk_score, risk_level, vectors, geo, velocity_kmh=0.0):
    """Internal helper to write an immutable security audit event into MongoDB access_logs."""
    logs_col = get_logs_collection()
    if logs_col is None:
        return None

    event_id = str(uuid.uuid4())
    doc = {
        "event_id": event_id,
        "user_id": user_id,
        "email": email,
        "ip": ip,
        "geo": {
            "city": geo.get("city", "Unknown"),
            "country": geo.get("country", "Unknown"),
            "country_code": geo.get("country_code", "XX"),
            "lat": geo.get("lat"),
            "lon": geo.get("lon")
        },
        "velocity_kmh": velocity_kmh,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "decision": decision,
        "threat_vectors": vectors,
        "timestamp": datetime.utcnow()
    }
    try:
        logs_col.insert_one(doc)
    except Exception as e:
        print(f"[!] Error writing security audit log: {e}")
    return event_id
