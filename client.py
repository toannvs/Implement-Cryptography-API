import json
from typing import Tuple

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature.pss import MGF1


def aes_encrypt(data: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce, tag, ciphertext


def rsa_encrypt(data: bytes) -> bytes:
    with open("/server/center_public.pem", "rb") as f:
        public_key = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(
        key=public_key, hashAlgo=SHA256, mgfunc=lambda x, y: MGF1(x, y, SHA256)
    )
    return cipher.encrypt(data)


def encrypt_and_send_data(data: dict):
    from main import EncryptedPayload, decrypt_traffic_data

    # Step 1: Convert to JSON string and then to bytes
    raw_data = json.dumps(data).encode("utf-8")
    try:
        # Step 2: Generate random AES key
        aes_key = get_random_bytes(32)
        # Step 3: Encrypt data with AES-GCM
        nonce, tag, ciphertext = aes_encrypt(raw_data, aes_key)
        # Step 4: Load public key and encrypt the AES key
        encrypted_aes_key = rsa_encrypt(aes_key)
        # Step 5: Prepare the payload
        payload = {
            "aes_key": encrypted_aes_key.hex(),
            "nonce": nonce.hex(),
            "tag": tag.hex(),
            "ciphertext": ciphertext.hex(),
        }
        print("📦 Encrypted payload prepared, sending to server...")
        # Step 6: Send to server via POST request
        # response = requests.post(API_URL, json=payload)
        # # Step 7: Process response
        # if response.status_code == 200:
        #     result = response.json()
        #     # Verify the decrypted data matches our original data
        #     if result["data"] == data:
        #         print("\n✅ Original data correctly recovered!")
        #     else:
        #         print(
        #             "\n❌ Warning: Decrypted data doesn't match original data"
        #         )
        #     return payload, result["data"]
        # else:
        #     print(
        #         f"\n❌ Error: Server returned status code {response.status_code}"
        #     )
        #     print(f"Response: {response.text}")
        result = decrypt_traffic_data(EncryptedPayload(**payload))
        return payload, result["data"]
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        return {}, {}
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        return {}, {}


def generate_dummy_data(has_image_frame: bool = False):
    dummy_data = {
        "timestamp": "2025-04-15T10:00:00",
        "location_id": "node_01",
        "vehicle_counts": {"motorbike": 120, "car": 35, "truck": 5, "bus": 2},
        "average_speed": 42.5,
    }

    return dummy_data


API_URL = "https://dev-cert.itd.com.vn/api/traffic-data"

with open("/server/center_public.pem", "rb") as f:
    public_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(
        public_key,
        hashAlgo=SHA256,
        mgfunc=lambda x, y: MGF1(x, y, SHA256),  # type: ignore
    )

if __name__ == "__main__":
    # Server URL
    encrypt_and_send_data(generate_dummy_data())
