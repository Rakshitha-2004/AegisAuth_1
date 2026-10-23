"""
AegisAuth - Cryptographic JWT Token Service
Generates short-lived, signed Zero-Trust access and challenge tokens using HMAC-SHA256.
"""
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify
from config import Config

def generate_access_token(user_id: str, email: str, name: str, role: str = "user", session_id: str = None) -> str:
    """Generates a standard Zero-Trust short-lived access token valid for 15 minutes."""
    payload = {
        "sub": str(user_id),
        "email": email.strip().lower(),
        "name": name,
        "role": role,
        "session_id": session_id or "",
        "token_type": "access",
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(minutes=15)
    }
    return jwt.encode(payload, Config.JWT_SECRET_KEY, algorithm="HS256")

def generate_mfa_challenge_token(user_id: str, email: str, context_id: str) -> str:
    """Generates a temporary restricted token valid for 5 minutes during Step-Up MFA."""
    payload = {
        "sub": str(user_id),
        "email": email.strip().lower(),
        "context_id": context_id,
        "token_type": "mfa_challenge",
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(minutes=5)
    }
    return jwt.encode(payload, Config.JWT_SECRET_KEY, algorithm="HS256")

def decode_token(token: str, expected_type: str = "access"):
    """Decodes and validates a JWT token against expected token_type."""
    try:
        payload = jwt.decode(token, Config.JWT_SECRET_KEY, algorithms=["HS256"])
        if payload.get("token_type") != expected_type:
            return None
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

def jwt_required(f):
    """Enforces valid JWT access token authentication on protected endpoints."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({
                "status": "error",
                "message": "Authorization token is missing or malformed."
            }), 401

        token = auth_header.split(" ")[1].strip()
        payload = decode_token(token, expected_type="access")
        if not payload:
            return jsonify({
                "status": "error",
                "message": "Session expired or invalid access token. Please authenticate again."
            }), 401

        return f(current_user=payload, *args, **kwargs)
    return decorated

def jwt_optional(f):
    """Allows access with or without a JWT access token. If a valid token is provided, current_user is populated."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        payload = None
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1].strip()
            payload = decode_token(token, expected_type="access")
        return f(current_user=payload, *args, **kwargs)
    return decorated

