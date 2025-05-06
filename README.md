# Traffic Data Encryption & Decryption Service

This project provides a secure API for encrypting and decrypting traffic data using modern cryptographic standards (AES-GCM and RSA-OAEP). It is designed for scenarios where sensitive traffic information must be securely transmitted between clients and a central server.

## Features

- **AES-GCM** symmetric encryption for data confidentiality and integrity.
- **RSA-OAEP** asymmetric encryption for secure key exchange.
- **RESTful API** built with FastAPI for decryption and testing.
- **Keypair management** with endpoints to download the RSA keypair.
- **Dockerized** for easy deployment.
- **Test utilities** for local encryption/decryption cycles.

## Project Structure

```
Implement-Cryptography-API/
    __init__.py
    center_private.pem
    center_public.pem
    client.py
    Dockerfile
    keypair.zip
    main.py
    requirements.txt
```

- `main.py`: FastAPI server with decryption endpoints and key management.
- `client.py`: Client-side utilities for encrypting and sending data.
- `center_public.pem` / `center_private.pem`: RSA keypair for encryption/decryption.
- `Dockerfile`: Containerization for deployment.
- `requirements.txt`: Python dependencies.

## API Endpoints

### 1. `/traffic-data` (POST)

Decrypts an encrypted payload sent from the client.

**Request Body:**
```json
{
  "aes_key": "<hex-encoded RSA-encrypted AES key>",
  "nonce": "<hex-encoded AES-GCM nonce>",
  "tag": "<hex-encoded AES-GCM tag>",
  "ciphertext": "<hex-encoded AES-GCM ciphertext>"
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Data successfully decrypted and verified",
  "data": { ...original data... }
}
```

### 2. `/enc-dec` (POST)

Test endpoint: encrypts and then decrypts provided raw JSON data.

**Request Body:**
```json
{
  "raw_data": "{...json string...}"
}
```

**Response:**
```json
{
  "encoded": { ...encrypted payload... },
  "response": { ...decrypted data... }
}
```

### 3. `/download-keypair` (GET)

Downloads the current RSA keypair as a ZIP file.

### 4. `/login` (POST)

Simple authentication endpoint (for demonstration).

### 5. `/` (GET)

Health check endpoint.

## Usage

### Prerequisites

- Python 3.11+
- Docker (optional, for containerized deployment)

### Installation

1. **Cd to the project directory:**
    ```sh
    cd Implement-Cryptography-API
    ```

2. **Install dependencies:**
    ```sh
    pip install -r requirements.txt
    ```

3. **Run the server:**
    ```sh
    python main.py
    ```

   Or with Docker:
    ```sh
    docker build -t traffic-crypto-server .
    docker run -p 8000:8000 traffic-crypto-server
    ```

4. **Test encryption/decryption:**
    - Run the client script:
      ```sh
      python client.py
      ```
    - Or use the `/enc-dec` endpoint with a tool like Postman.

## Security Notes

- The RSA keypair is generated automatically if not present.
- **Never share your private key (`center_private.pem`) publicly.**
- For production, secure key storage and proper authentication should be implemented.