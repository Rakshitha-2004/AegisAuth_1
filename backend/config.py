import os
from pathlib import Path
from dotenv import load_dotenv

# Ensure .env is always loaded reliably from backend directory
BACKEND_DIR = Path(__file__).resolve().parent
backend_env = BACKEND_DIR / ".env"
root_env = BACKEND_DIR.parent / ".env"

if backend_env.exists():
    load_dotenv(dotenv_path=backend_env, override=True)
elif root_env.exists():
    load_dotenv(dotenv_path=root_env, override=True)
else:
    load_dotenv()

class Config:
    """Base configuration for AegisAuth backend."""
    SECRET_KEY = os.getenv("SECRET_KEY", "aegisauth-zero-trust-secret-key-2026-prod-grade")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "aegisauth-jwt-token-signing-key-32bytes-secure")

    # MongoDB Configuration
    MONGO_URI = os.getenv("MONGO_URI", "").strip()
    MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "aegisauth_db").strip()

    # Server Configuration
    PORT = int(os.getenv("PORT", 5000))
    DEBUG = os.getenv("FLASK_DEBUG", "True").lower() in ("true", "1", "yes")
    FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")

    # Zero Trust Policy Engine Thresholds
    IMPOSSIBLE_TRAVEL_SPEED_THRESHOLD = float(os.getenv("IMPOSSIBLE_TRAVEL_SPEED_THRESHOLD", 900.0))  # km/h
    BRUTE_FORCE_THRESHOLD = int(os.getenv("BRUTE_FORCE_THRESHOLD", 5))  # max failed attempts before account lock
    CREDENTIAL_STUFFING_THRESHOLD = int(os.getenv("CREDENTIAL_STUFFING_THRESHOLD", 3))  # distinct accounts from 1 IP
    MFA_REQUIRED_SCORE_THRESHOLD = int(os.getenv("MFA_REQUIRED_SCORE_THRESHOLD", 31))  # score 31-70 triggers step-up
    QUARANTINE_SCORE_THRESHOLD = int(os.getenv("QUARANTINE_SCORE_THRESHOLD", 71))  # score 71-100 terminates & locks
