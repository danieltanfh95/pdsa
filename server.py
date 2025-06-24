# PDSA (Password-Derived Signature Authentication) Example
# Server implementation with FastAPI and SQLite

from fastapi import FastAPI, HTTPException
from fastapi.security import HTTPBearer
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
import time
from typing import Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
import base64

from common import generate_challenge

app = FastAPI(title="PDSA Authentication Demo")
security = HTTPBearer()

# Add CORS middleware for browser access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Database setup
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            public_key TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS active_challenges (
            username TEXT PRIMARY KEY,
            challenge TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


init_db()


# Pydantic models
class RegisterRequest(BaseModel):
    username: str
    public_key: str  # Base64 encoded
    salt: str  # Base64 encoded


class LoginRequest(BaseModel):
    username: str


class AuthenticateRequest(BaseModel):
    username: str
    signature: str  # Base64 encoded


class ChallengeResponse(BaseModel):
    challenge: str
    salt: str
    expires_in: int


# Database helpers
def get_user(username: str) -> Optional[dict]:
    """Get user data from database"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT username, public_key, salt FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return {
            'username': row[0],
            'public_key': row[1],
            'salt': row[2]
        }
    return None


def save_user(username: str, public_key: str, salt: str):
    """Save user registration data"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(
        'INSERT OR REPLACE INTO users (username, public_key, salt) VALUES (?, ?, ?)',
        (username, public_key, salt)
    )
    conn.commit()
    conn.close()


def save_challenge(username: str, challenge: str):
    """Save challenge for user"""
    expires_at = int(time.time()) + 300  # 5 minutes
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(
        'INSERT OR REPLACE INTO active_challenges (username, challenge, expires_at) VALUES (?, ?, ?)',
        (username, challenge, expires_at)
    )
    conn.commit()
    conn.close()


def get_challenge(username: str) -> Optional[str]:
    """Get active challenge for user"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(
        'SELECT challenge FROM active_challenges WHERE username = ? AND expires_at > ?',
        (username, int(time.time()))
    )
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None


def clear_challenge(username: str):
    """Clear challenge after use"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM active_challenges WHERE username = ?', (username,))
    conn.commit()
    conn.close()


# API Endpoints
@app.post("/api/register")
async def register(request: RegisterRequest):
    """Register a new user with their public key and salt"""
    try:
        # Check if user already exists
        if get_user(request.username):
            raise HTTPException(status_code=400, detail="Username already exists")

        # Validate base64 encoding
        try:
            base64.b64decode(request.public_key)
            base64.b64decode(request.salt)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid base64 encoding")

        # Save user data
        save_user(request.username, request.public_key, request.salt)

        return {"message": "User registered successfully"}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")


@app.post("/api/login", response_model=ChallengeResponse)
async def login(request: LoginRequest):
    """Initiate login by sending challenge and salt"""
    user = get_user(request.username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Generate new challenge
    challenge = generate_challenge()
    save_challenge(request.username, challenge)

    return ChallengeResponse(
        challenge=challenge,
        salt=user['salt'],
        expires_in=300
    )


@app.post("/api/authenticate")
async def authenticate(request: AuthenticateRequest):
    """Verify signature and complete authentication"""
    try:
        # Get user data
        user = get_user(request.username)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Get active challenge
        challenge = get_challenge(request.username)
        if not challenge:
            raise HTTPException(status_code=400, detail="No active challenge or challenge expired")

        # Decode stored public key
        public_key_bytes = base64.b64decode(user['public_key'])
        public_key = serialization.load_der_public_key(public_key_bytes)

        # Decode signature
        signature_bytes = base64.b64decode(request.signature)

        # Verify signature
        try:
            public_key.verify(
                signature_bytes,
                challenge.encode('utf-8'),
                ec.ECDSA(hashes.SHA256())
            )
        except InvalidSignature:
            raise HTTPException(status_code=401, detail="Invalid signature")

        # Clear the used challenge
        clear_challenge(request.username)

        # In a real app, you'd generate a JWT or session token here
        return {
            "message": "Authentication successful",
            "username": request.username,
            "authenticated": True
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Authentication failed: {str(e)}")


@app.get("/")
async def serve_frontend():
    """Serve the HTML frontend"""
    return FileResponse('static/index.html')


@app.get("/api/")
async def api_root():
    return {"message": "PDSA Authentication Server", "version": "1.0"}


if __name__ == "__main__":
    import uvicorn
    import os

    # Create static directory for frontend files
    os.makedirs("static", exist_ok=True)

    # Mount static files
    app.mount("/static", StaticFiles(directory="static"), name="static")

    print("Starting PDSA Authentication Server...")
    print("Frontend available at: http://localhost:8000")
    print("API endpoints:")
    print("- POST /api/register")
    print("- POST /api/login")
    print("- POST /api/authenticate")
    uvicorn.run(app, host="0.0.0.0", port=8000)
