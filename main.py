import json
import zipfile
from typing import Any, Dict

import uvicorn
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from Crypto.Hash import SHA256
from Crypto.Signature.pss import MGF1
from server.client import encrypt_and_send_data

app = FastAPI(title="Traffic Data Decryption Service")


# Define the payload structure
class EncryptedPayload(BaseModel):
    aes_key: str  # Base64 encoded encrypted AES key
    nonce: str  # Base64 encoded nonce
    tag: str  # Base64 encoded authentication tag
    ciphertext: str  # Base64 encoded encrypted data


class Token(BaseModel):
    access_token: str
    token_type: str
    access_token_expires: int
    refresh_token: str
    refresh_token_expires: int
    user: Dict[str, Any]


def aes_decrypt(
    nonce: bytes,
    tag: bytes,
    ciphertext: bytes,
    key: bytes,
) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def rsa_decrypt(data: bytes) -> bytes:
    with open("/server/center_private.pem", "rb") as f:
        private_key = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(
        key=private_key, hashAlgo=SHA256, mgfunc=lambda x, y: MGF1(x, y, SHA256)
    )
    return cipher.decrypt(data)


@app.post("/traffic-data", response_model=Dict[str, Any])
def decrypt_traffic_data(payload: EncryptedPayload):
    try:
        encrypted_aes_key = bytes.fromhex(payload.aes_key)
        aes_key = rsa_decrypt(encrypted_aes_key)
        # 2. Decrypt the data using AES-GCM
        nonce = bytes.fromhex(payload.nonce)
        tag = bytes.fromhex(payload.tag)
        ciphertext = bytes.fromhex(payload.ciphertext)

        decrypted_data = aes_decrypt(nonce, tag, ciphertext, aes_key)
        # 3. Parse the decrypted JSON data
        final_data = json.loads(decrypted_data)
        # 4. Return the decrypted data with success status
        return {
            "status": "success",
            "message": "Data successfully decrypted and verified",
            "data": final_data,
        }

    except Exception as e:
        raise HTTPException(
            status_code=400, detail=f"Decryption failed: {str(e)}"
        )


class Data(BaseModel):
    raw_data: str


# Load the RSA private key
try:
    with open("/server/center_private.pem", "rb") as f:
        private_key = RSA.import_key(f.read())
except FileNotFoundError:
    print("Error: RSA private key not found. Please generate keys first.")


@app.post("/enc-dec", response_model=Dict[str, Any])
async def enc_dec_data(data: Data):
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
    zip_path = "/server/keypair.zip"
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.write("/server/center_public.pem", arcname="center_public.pem")
        zipf.write("/server/center_private.pem", arcname="center_private.pem")

    return FileResponse(
        path=zip_path,
        filename="keypair.zip",
        media_type="application/zip",
    )


@app.get("/")
async def root():
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
    Logs in the user provided by form_data.username and form_data.password
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
    # Function to generate keys if needed
    def generate_keys():
        try:
            # Only generate keys if they don't exist
            import os

            if not (
                os.path.exists("/server/center_private.pem")
                and os.path.exists("/server/center_public.pem")
            ):
                from Crypto.PublicKey import RSA

                key = RSA.generate(2048)

                # Save private key
                with open("/server/center_private.pem", "wb") as f:
                    f.write(key.export_key())

                # Save public key
                with open("/server/center_public.pem", "wb") as f:
                    f.write(key.publickey().export_key())

                print("🔑 RSA key pair generated!")
            else:
                print("🔑 Using existing RSA keys")
        except Exception as e:
            print(f"❌ Failed to generate keys: {str(e)}")

    # Generate keys if needed
    generate_keys()
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
