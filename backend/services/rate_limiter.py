"""
AegisAuth - Sliding-Window Attack Detection Engine
Detects Account-Targeted Brute Force and Distributed Credential Stuffing (IP Spraying).
"""
from datetime import datetime, timedelta
from database.db import get_rate_limits_collection
from config import Config

def record_attempt(ip: str, email: str, status: str):
    """Records an authentication attempt in the rate_limits collection for sliding window analysis."""
    col = get_rate_limits_collection()
    if col is None:
        return

    doc = {
        "ip": ip,
        "email": email.strip().lower(),
        "status": status,  # "failed" or "success"
        "timestamp": datetime.utcnow()
    }
    try:
        col.insert_one(doc)
    except Exception as e:
        print(f"[!] Error recording rate limit record: {e}")

def evaluate_rate_anomalies(ip: str, email: str) -> dict:
    """
    Evaluates sliding-window attack vectors:
    1. Vertical Brute Force: >= Config.BRUTE_FORCE_THRESHOLD failed logins for this email in 10 mins.
    2. Horizontal Credential Stuffing: >= Config.CREDENTIAL_STUFFING_THRESHOLD distinct emails from this IP in 5 mins.
    """
    col = get_rate_limits_collection()
    if col is None:
        return {
            "is_brute_force": False,
            "is_stuffing": False,
            "risk_weight": 0,
            "message": "Rate limits collection unavailable."
        }

    now = datetime.utcnow()
    ten_mins_ago = now - timedelta(minutes=10)
    five_mins_ago = now - timedelta(minutes=5)

    clean_email = email.strip().lower()

    # 1. Check Vertical Brute Force on this specific account
    recent_account_failures = col.count_documents({
        "email": clean_email,
        "status": "failed",
        "timestamp": {"$gte": ten_mins_ago}
    })

    if recent_account_failures >= Config.BRUTE_FORCE_THRESHOLD:
        return {
            "is_brute_force": True,
            "is_stuffing": False,
            "failed_attempts": recent_account_failures,
            "risk_weight": 40,
            "severity": "CRITICAL",
            "message": (
                f"Brute Force Anomaly: {recent_account_failures} consecutive failed authentication attempts "
                f"recorded on account '{clean_email}' within the last 10 minutes."
            )
        }

    # 2. Check Horizontal Credential Stuffing / IP Spraying from this IP
    distinct_targeted_accounts = col.distinct("email", {
        "ip": ip,
        "timestamp": {"$gte": five_mins_ago}
    })

    if len(distinct_targeted_accounts) >= Config.CREDENTIAL_STUFFING_THRESHOLD:
        return {
            "is_brute_force": False,
            "is_stuffing": True,
            "targeted_accounts_count": len(distinct_targeted_accounts),
            "risk_weight": 45,
            "severity": "CRITICAL",
            "message": (
                f"Credential Stuffing / IP Spraying detected: Source IP '{ip}' has attempted access across "
                f"{len(distinct_targeted_accounts)} distinct accounts within 5 minutes."
            )
        }

    return {
        "is_brute_force": False,
        "is_stuffing": False,
        "risk_weight": 0,
        "severity": "LOW",
        "message": "Authentication velocity within legitimate thresholds."
    }
