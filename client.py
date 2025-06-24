# Client example functions (would typically be in a separate file/application)
import base64
import os
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from common import derive_private_key


def register(
        username: str, password: str, server_url: str = "http://localhost:8000"
):
    """Client-side registration"""

    # Generate salt
    salt = os.urandom(32)

    # Derive private key from password
    private_key = derive_private_key(password, salt)

    # Get public key
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_numbers().x.to_bytes(
        32, "big"
    ) + public_key.public_numbers().y.to_bytes(32, "big")

    # Serialize public key properly
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Prepare request
    register_data = {
        "username": username,
        "public_key": base64.b64encode(public_key_der).decode(),
        "salt": base64.b64encode(salt).decode(),
    }

    # Send registration
    response = requests.post(f"{server_url}/api/register", json=register_data)
    return response.json()


def login(
        username: str, password: str, server_url: str = "http://localhost:8000"
):
    """Client-side login"""

    # Step 1: Get challenge
    login_response = requests.post(f"{server_url}/api/login", json={"username": username})
    if login_response.status_code != 200:
        return {"error": "Login initiation failed"}

    login_data = login_response.json()
    challenge = login_data["challenge"]
    salt = base64.b64decode(login_data["salt"])

    # Step 2: Re-derive private key
    private_key = derive_private_key(password, salt)

    # Step 3: Sign challenge
    signature = private_key.sign(challenge.encode("utf-8"), ec.ECDSA(hashes.SHA256()))

    # Step 4: Send signature
    auth_data = {
        "username": username,
        "signature": base64.b64encode(signature).decode(),
    }

    auth_response = requests.post(f"{server_url}/api/authenticate", json=auth_data)
    return auth_response.json()


if __name__ == "__main__":
    # Registration
    # result = register("alice", "my_secure_password")
    # print("Registration:", result)

    # Login
    result = login("alice", "my_secure_password")
    print("Login:", result)
