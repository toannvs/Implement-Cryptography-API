import json
import zipfile
from typing import Any, Dict

import uvicorn
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# Initialize FastAPI application
app = FastAPI(title="Traffic Data Decryption Service")

class EncryptedPayload(BaseModel):
    """
    Pydantic model for the encrypted payload received from the client.
    All fields are hex-encoded strings.
    """
    aes_key: str      # AES key encrypted with RSA, hex encoded
    nonce: str        # Nonce used for AES-GCM, hex encoded
    tag: str          # Authentication tag from AES-GCM, hex encoded
    ciphertext: str   # Encrypted data, hex encoded

class Token(BaseModel):
    """
    Pydantic model for authentication token response.
    """
    access_token: str
    token_type: str
    access_token_expires: int
    refresh_token: str
    refresh_token_expires: int
    user: Dict[str, Any]

def aes_decrypt(nonce: bytes, tag: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypts AES-GCM encrypted data.
    The tag is appended to the ciphertext as required by AESGCM in cryptography.
    """
    aesgcm = AESGCM(key)
    ciphertext_with_tag = ciphertext + tag  # Combine ciphertext and tag
    return aesgcm.decrypt(nonce, ciphertext_with_tag, None)

def rsa_decrypt(data: bytes) -> bytes:
    """
    Decrypts data using the server's RSA private key with OAEP padding.
    """
    with open("./center_private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )
    decrypted = private_key.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return decrypted

@app.post("/traffic-data", response_model=Dict[str, Any])
def decrypt_traffic_data(payload: EncryptedPayload):
    """
    Endpoint to receive encrypted traffic data, decrypt it using RSA and AES-GCM,
    and return the original data if decryption is successful.
    """
    try:
        # Decode all hex-encoded fields from the payload
        encrypted_aes_key = bytes.fromhex(payload.aes_key)
        aes_key = rsa_decrypt(encrypted_aes_key)
        nonce = bytes.fromhex(payload.nonce)
        tag = bytes.fromhex(payload.tag)
        ciphertext = bytes.fromhex(payload.ciphertext)
        # Decrypt the data using AES-GCM
        decrypted_data = aes_decrypt(nonce, tag, ciphertext, aes_key)
        final_data = json.loads(decrypted_data)
        return {
            "status": "success",
            "message": "Data successfully decrypted and verified",
            "data": final_data,
        }
    except Exception as e:
        # Return HTTP 400 if decryption fails
        raise HTTPException(
            status_code=400, detail=f"Decryption failed: {str(e)}"
        )

class Data(BaseModel):
    """
    Pydantic model for raw data input (used for testing encryption/decryption).
    """
    raw_data: str

@app.post("/enc-dec", response_model=Dict[str, Any])
async def enc_dec_data(data: Data):
    """
    Endpoint for testing: encrypts and then decrypts the provided raw JSON data.
    """
    from client import encrypt_and_send_data
    try:
        json_data = json.loads(data.raw_data)
        encoded, response = encrypt_and_send_data(json_data)
        return {"encoded": encoded, "response": response}
    except json.JSONDecodeError as e:
        print("Decode error: ", e)
        raise HTTPException(status_code=500, detail="Data not in json format")
    except Exception as e:
        print("Error: ", e)
        raise HTTPException(status_code=500, detail="Server error")

@app.get("/download-keypair")
async def download_keypair():
    """
    Endpoint to download the RSA keypair as a ZIP file.
    """
    zip_path = "./keypair.zip"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.write("./center_public.pem", arcname="center_public.pem")
        zipf.write("./center_private.pem", arcname="center_private.pem")
    return FileResponse(
        path=zip_path,
        filename="keypair.zip",
        media_type="application/zip",
    )

@app.get("/")
async def root():
    """
    Health check endpoint.
    """
    return {"status": "online", "service": "Traffic Data Decryption Service"}

@app.post(
    "/login",
    response_model=Token,
    response_model_exclude_none=True,
)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
) -> Token:
    """
    Simple authentication endpoint for demonstration purposes.
    Returns a token if username and password are correct.
    """
    if form_data.username == "admin" and form_data.password == "abc123":
        return Token(
            access_token=form_data.username,
            token_type="bearer",
            access_token_expires=3600,
            refresh_token=form_data.username,
            refresh_token_expires=3600,
            user={"username": form_data.username},
        )
    else:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

if __name__ == "__main__":
    def generate_keys():
        """
        Generates an RSA keypair if not already present in the current directory.
        """
        try:
            import os
            if not (
                os.path.exists("./center_private.pem")
                and os.path.exists("./center_public.pem")
            ):
                from cryptography.hazmat.primitives.asymmetric import rsa
                from cryptography.hazmat.primitives import serialization

                key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend()
                )

                # Save private key in PEM format
                with open("./center_private.pem", "wb") as f:
                    f.write(key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption(),
                    ))

                # Save public key in PEM format
                with open("./center_public.pem", "wb") as f:
                    f.write(key.public_key().public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    ))

                print("🔑 RSA key pair generated!")
            else:
                print("🔑 Using existing RSA keys")
        except Exception as e:
            print(f"❌ Failed to generate keys: {str(e)}")

    # Generate RSA keys if needed and start the FastAPI server
    generate_keys()
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)