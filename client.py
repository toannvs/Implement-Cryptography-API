import json
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from Crypto.Random import get_random_bytes  # Used for generating nonce/key

def aes_encrypt(data: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypts data using AES-GCM.
    Returns a tuple of (nonce, tag, ciphertext).
    """
    aesgcm = AESGCM(key)
    nonce = get_random_bytes(12)  # AESGCM requires a 12-byte nonce
    ciphertext_with_tag = aesgcm.encrypt(nonce, data, None)
    # AESGCM appends the tag to the end of the ciphertext, so we split it
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]
    return nonce, tag, ciphertext

def rsa_encrypt(data: bytes) -> bytes:
    """
    Encrypts data using the server's RSA public key with OAEP padding.
    """
    with open("./center_public.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    encrypted = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return encrypted

def encrypt_and_send_data(data: dict):
    """
    Encrypts the provided data using AES-GCM and RSA, then simulates sending it to the server.
    """
    from main import EncryptedPayload, decrypt_traffic_data

    raw_data = json.dumps(data).encode("utf-8")
    try:
        aes_key = get_random_bytes(32)  # 256-bit AES key
        nonce, tag, ciphertext = aes_encrypt(raw_data, aes_key)
        encrypted_aes_key = rsa_encrypt(aes_key)
        payload = {
            "aes_key": encrypted_aes_key.hex(),
            "nonce": nonce.hex(),
            "tag": tag.hex(),
            "ciphertext": ciphertext.hex(),
        }
        print("📦 Encrypted payload prepared, sending to server...")
        # Simulate sending to server by calling the decrypt function directly
        result = decrypt_traffic_data(EncryptedPayload(**payload))
        return payload, result["data"]
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        return {}, {}

def generate_dummy_data(has_image_frame: bool = False):
    """
    Generates dummy traffic data for testing.
    """
    dummy_data = {
        "timestamp": "2025-04-15T10:00:00",
        "location_id": "node_01",
        "vehicle_counts": {"motorbike": 120, "car": 35, "truck": 5, "bus": 2},
        "average_speed": 42.5,
    }
    return dummy_data

API_URL = "https://dev-cert.itd.com.vn/api/traffic-data"

if __name__ == "__main__":
    # Run a test encryption and decryption cycle
    encrypt_and_send_data(generate_dummy_data())