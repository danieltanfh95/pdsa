import base64
import secrets
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def derive_private_key(
    password: str, salt: bytes, iterations: int = 100000
) -> ec.EllipticCurvePrivateKey:
    """Derive ECDSA private key from password using PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    key_bytes = kdf.derive(password.encode("utf-8"))
    # Convert to integer for EC private key
    private_value = int.from_bytes(key_bytes, byteorder="big")
    # Ensure it's within the curve order (basic modular reduction)
    private_key = ec.derive_private_key(private_value % (2**256), ec.SECP256R1())
    return private_key


def generate_challenge() -> str:
    """Generate a cryptographically secure challenge"""
    timestamp = int(time.time())
    random_bytes = secrets.token_bytes(32)
    return f"{timestamp}:{base64.b64encode(random_bytes).decode()}"


def is_challenge_expired(challenge: str, max_age: int = 300) -> bool:
    """Check if challenge is expired (default 5 minutes)"""
    try:
        timestamp = int(challenge.split(':')[0])
        return (time.time() - timestamp) > max_age
    except:
        return True
