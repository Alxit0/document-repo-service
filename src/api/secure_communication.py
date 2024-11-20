from functools import wraps
import json
from flask import Response, request, jsonify
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.serialization import load_pem_parameters
import base64
import os

# Shared secret key for encryption and HMAC
PARAMETERS_FILE = "./dh_parameters.pem"
client_shared_keys = {} # Store client-specific shared keys (keyed by client_id)

def load_or_generate_parameters():
    if os.path.exists(PARAMETERS_FILE):
    
        with open(PARAMETERS_FILE, "rb") as file:
            parameters_pem = file.read()
        return load_pem_parameters(parameters_pem)
    
    else:
        # Generate new DH parameters
        print("Generating parameters (may take a while)")
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        with open(PARAMETERS_FILE, "wb") as file:
            file.write(parameters.parameter_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.ParameterFormat.PKCS3
            ))
        return parameters

parameters = load_or_generate_parameters()

def get_right_body():
    body: dict = None

    if request.method == 'GET':
        body = request.args
    elif request.content_type == 'application/json':
        body = request.get_json()
    elif request.content_type.startswith('multipart/form-data'):
        body = request.form

    return body

# helper functions for encryption, decryption, HMAC, etc.
def decrypt_message(ciphertext, key, iv):
    if not ciphertext:
        return b"{}"
    
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def encrypt_message(message, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(message.encode()) + encryptor.finalize()


def create_hmac(data, key):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

def verify_hmac(data, key, hmac_to_verify):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    h.verify(hmac_to_verify)

# secure decorator
def secure_endpoint():
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:

                body = get_right_body()

                # extract encrypted payload and headers
                payload = base64.b64decode(body.get("payload", ""))
                iv = base64.b64decode(request.headers.get("X-Encrypted-IV", ""))
                received_hmac = base64.b64decode(request.headers.get("X-HMAC", ""))
                encrypted_session_token = request.headers.get("Session", "")
                client_id = request.headers.get("Client-Id", "")

                if client_id not in client_shared_keys:
                    return jsonify({"error": "Need to regnociate secret_key"}), 101

                shared_secret_key = client_shared_keys[client_id]

                print(shared_secret_key.hex())
                # verify the HMAC
                verify_hmac(payload, shared_secret_key, received_hmac)

                # decrypt the payload and nessessary headers
                decrypted_params = decrypt_message(payload, shared_secret_key, iv).decode()
                request.decrypted_params = json.loads(decrypted_params)

                encrypted_session_bytes = base64.b64decode(encrypted_session_token)
                decrypted_session_token = decrypt_message(encrypted_session_bytes, shared_secret_key, iv).decode()
                request.decrypted_headers = {**request.headers, "session": decrypted_session_token}

                
                # execute the original function
                response_message, code = func(*args, **kwargs)
                response_message: Response

                
                # encrypt the response
                if response_message.direct_passthrough:
                    return response_message, code

                response_iv = os.urandom(16)
                encrypted_response = encrypt_message(response_message.get_data().decode(), shared_secret_key, response_iv)
                response_hmac = create_hmac(encrypted_response, shared_secret_key)

                return jsonify({
                    "iv": base64.b64encode(response_iv).decode(),
                    "ciphertext": base64.b64encode(encrypted_response).decode(),
                    "hmac": base64.b64encode(response_hmac).decode()
                }), code

            except Exception as e:
                e.with_traceback()
                return jsonify({"error": "Invalid request", "message": str(e)}), 400

        return wrapper
    
    return decorator
