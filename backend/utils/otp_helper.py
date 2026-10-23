"""
AegisAuth - Secure 6-Digit Challenge Code (MFA) Helper
Generates cryptographically random 6-digit step-up challenge codes.
"""
import secrets
from datetime import datetime, timedelta

def generate_otp() -> str:
    """Generates a cryptographically secure 6-digit numeric verification code."""
    return f"{secrets.randbelow(900000) + 100000}"

def get_otp_expiration(minutes: int = 5) -> datetime:
    """Returns expiration timestamp for step-up challenge."""
    return datetime.utcnow() + timedelta(minutes=minutes)

def dispatch_challenge_code(email: str, code: str, reason: str = "Suspicious Access Attempt") -> dict:
    """
    Logs and dispatches the step-up challenge code.
    Prints clearly to backend terminal in development mode.
    """
    banner = f"""
======================================================================
[+] AEGISAUTH ZERO-TRUST STEP-UP CHALLENGE
    Target Account : {email}
    Reason         : {reason}
    Challenge Code : {code}
    Validity       : 5 Minutes
======================================================================
"""
    print(banner)
    return {
        "status": "sent",
        "email": email,
        "dev_code": code,
        "expires_in_minutes": 5
    }
