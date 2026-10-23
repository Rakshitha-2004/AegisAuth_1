"""
AegisAuth - Security Operations Center (SOC) Blueprint
Endpoints for Real-Time Threat Metrics, Immutable Audit Trail, and Incident Containment.
"""
import re
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify
from bson import ObjectId

from database.db import get_logs_collection, get_users_collection, get_sessions_collection
from utils.jwt_helper import jwt_required, jwt_optional

soc_bp = Blueprint("soc", __name__, url_prefix="/api/soc")

@soc_bp.route("/overview", methods=["GET"])
@jwt_optional
def get_soc_overview(current_user=None):
    """Returns top-level SOC security metrics for the admin console."""
    logs_col = get_logs_collection()
    users_col = get_users_collection()
    sessions_col = get_sessions_collection()

    default_overview = {
        "total_events": 0,
        "allowed_count": 0,
        "mfa_challenged_count": 0,
        "denied_count": 0,
        "impossible_travel_count": 0,
        "brute_force_count": 0,
        "quarantined_users_count": 0,
        "active_sessions_count": 0,
        "threat_level": "NORMAL",
        "recent_threats": []
    }

    if logs_col is None:
        return jsonify({"status": "success", "metrics": default_overview}), 200

    try:
        now = datetime.utcnow()
        last_24h = now - timedelta(hours=24)

        total_events = logs_col.count_documents({})
        allowed = logs_col.count_documents({"decision": "ALLOW"})
        mfa_challenged = logs_col.count_documents({"decision": "CHALLENGE_MFA"})
        denied = logs_col.count_documents({"decision": {"$in": ["DENY_QUARANTINE", "DENY_RATE_LIMIT"]}})

        # Query specific threat vectors
        impossible_travel = logs_col.count_documents({
            "threat_vectors.vector": "Geodesic Velocity Anomaly"
        })
        brute_force = logs_col.count_documents({
            "threat_vectors.vector": {"$in": ["Brute Force Threshold Exceeded", "Credential Stuffing Pattern"]}
        })

        quarantined = users_col.count_documents({"status": "quarantined"}) if users_col is not None else 0
        active_sessions = sessions_col.count_documents({}) if sessions_col is not None else 0

        # Determine aggregate threat level
        recent_denied_24h = logs_col.count_documents({
            "decision": {"$in": ["DENY_QUARANTINE", "DENY_RATE_LIMIT"]},
            "timestamp": {"$gte": last_24h}
        })

        if recent_denied_24h >= 5 or quarantined > 0:
            threat_level = "HIGH ALERT"
        elif mfa_challenged > 0:
            threat_level = "ELEVATED"
        else:
            threat_level = "NORMAL"

        # Fetch 6 most recent threat events
        threat_cursor = logs_col.find(
            {"risk_score": {"$gte": 31}}
        ).sort("timestamp", -1).limit(6)

        recent_threats = []
        for doc in threat_cursor:
            recent_threats.append({
                "id": str(doc["_id"]),
                "event_id": doc.get("event_id"),
                "email": doc.get("email"),
                "ip": doc.get("ip"),
                "geo": doc.get("geo"),
                "velocity_kmh": doc.get("velocity_kmh", 0),
                "risk_score": doc.get("risk_score", 0),
                "risk_level": doc.get("risk_level", "Unknown"),
                "decision": doc.get("decision"),
                "vectors": [v.get("vector") if isinstance(v, dict) else str(v) for v in doc.get("threat_vectors", [])],
                "timestamp": doc["timestamp"].isoformat() + "Z" if hasattr(doc.get("timestamp"), "isoformat") else str(doc.get("timestamp"))
            })

        metrics = {
            "total_events": total_events,
            "allowed_count": allowed,
            "mfa_challenged_count": mfa_challenged,
            "denied_count": denied,
            "impossible_travel_count": impossible_travel,
            "brute_force_count": brute_force,
            "quarantined_users_count": quarantined,
            "active_sessions_count": active_sessions,
            "threat_level": threat_level,
            "recent_threats": recent_threats
        }

        return jsonify({"status": "success", "metrics": metrics}), 200

    except Exception as e:
        print(f"[!] Error fetching SOC overview: {e}")
        return jsonify({"status": "success", "metrics": default_overview, "error": str(e)}), 200

@soc_bp.route("/audit-logs", methods=["GET"])
@soc_bp.route("/audit-trail", methods=["GET"])
@jwt_optional
def get_audit_logs(current_user=None):
    """Returns queryable, paginated security audit log records."""
    logs_col = get_logs_collection()
    if logs_col is None:
        return jsonify({"status": "success", "logs": [], "total": 0}), 200

    try:
        limit = min(100, int(request.args.get("limit", 50)))
        decision_filter = request.args.get("decision")
        search_term = request.args.get("query") or request.args.get("search")

        query = {}
        if decision_filter and decision_filter.upper() not in ("ALL", ""):
            query["decision"] = decision_filter.upper()

        if search_term and search_term.strip():
            term = re.escape(search_term.strip())
            query["$or"] = [
                {"email": {"$regex": term, "$options": "i"}},
                {"ip": {"$regex": term, "$options": "i"}},
                {"event_id": {"$regex": term, "$options": "i"}},
                {"decision": {"$regex": term, "$options": "i"}}
            ]

        total = logs_col.count_documents(query)
        cursor = logs_col.find(query).sort("timestamp", -1).limit(limit)

        logs = []
        for d in cursor:
            geo_data = d.get("geo") or {}
            if isinstance(geo_data, dict):
                city = geo_data.get("city") or ""
                country = geo_data.get("country") or ""
                location_str = f"{city}, {country}".strip(", ") or "Unknown"
            elif isinstance(geo_data, str):
                location_str = geo_data
            else:
                location_str = "Unknown"

            logs.append({
                "id": str(d["_id"]),
                "event_id": d.get("event_id"),
                "email": d.get("email"),
                "ip": d.get("ip"),
                "geo": geo_data,
                "location": location_str,
                "velocity_kmh": d.get("velocity_kmh", 0),
                "risk_score": d.get("risk_score", 0),
                "risk_level": d.get("risk_level", "Unknown"),
                "decision": d.get("decision"),
                "threat_vectors": d.get("threat_vectors", []),
                "timestamp": d["timestamp"].isoformat() + "Z" if hasattr(d.get("timestamp"), "isoformat") else str(d.get("timestamp"))
            })

        return jsonify({"status": "success", "logs": logs, "total": total}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@soc_bp.route("/active-sessions", methods=["GET"])
@soc_bp.route("/sessions", methods=["GET"])
@jwt_optional
def get_active_sessions(current_user=None):
    """Returns all active user sessions with remote termination ability."""
    sessions_col = get_sessions_collection()
    if sessions_col is None:
        return jsonify({"status": "success", "sessions": []}), 200

    try:
        cursor = sessions_col.find({}).sort("created_at", -1).limit(50)
        sessions = []
        for s in cursor:
            sessions.append({
                "id": str(s["_id"]),
                "session_id": s.get("session_id"),
                "email": s.get("email"),
                "ip": s.get("ip"),
                "location": s.get("location"),
                "created_at": s["created_at"].isoformat() + "Z" if hasattr(s.get("created_at"), "isoformat") else str(s.get("created_at"))
            })
        return jsonify({"status": "success", "sessions": sessions}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@soc_bp.route("/terminate-session", methods=["POST"])
@jwt_required
def terminate_session(current_user):
    """Remotely revokes an active session."""
    data = request.get_json(silent=True) or {}
    session_id = data.get("session_id")

    if not session_id:
        return jsonify({"status": "error", "message": "session_id is required."}), 400

    sessions_col = get_sessions_collection()
    if sessions_col is not None:
        sessions_col.delete_one({"session_id": session_id})

    return jsonify({"status": "success", "message": f"Session '{session_id}' terminated successfully."}), 200

@soc_bp.route("/unquarantine-user", methods=["POST"])
@jwt_required
def unquarantine_user(current_user):
    """Reinstates a quarantined account after security investigation."""
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()

    if not email:
        return jsonify({"status": "error", "message": "Email is required."}), 400

    users_col = get_users_collection()
    if users_col is not None:
        users_col.update_one({"email": email}, {"$set": {"status": "active"}})

    return jsonify({"status": "success", "message": f"Account '{email}' has been reinstated."}), 200
