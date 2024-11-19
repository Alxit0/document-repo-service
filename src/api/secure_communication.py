from functools import wraps
import json
from flask import Response, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
import base64
import os

# Shared secret key for encryption and HMAC
SHARED_SECRET_KEY = b'\xe4\xe1\x9d\xef\xcc\xc8\xf7\x1f5p\xda\x83\xe4\xc1W\x06\xbdQgH\xe7\xda\xd0\xd5c\x13D\x0f\xee$fG'

# Helper functions for encryption, decryption, HMAC, etc.
def decrypt_message(ciphertext, key, iv):
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

# The secure decorator
def secure_endpoint():
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                # Step 1: Extract encrypted payload and headers
                if request.method == 'GET':
                    payload = base64.b64decode(request.args.get("payload", ""))
                else:
                    payload = base64.b64decode(request.get_json().get("payload", ""))

                iv = base64.b64decode(request.headers.get("X-Encrypted-IV", ""))
                received_hmac = base64.b64decode(request.headers.get("X-HMAC", ""))
                encrypted_session_token = request.headers.get("Session", "")

                # Step 2: Verify the HMAC
                verify_hmac(payload, SHARED_SECRET_KEY, received_hmac)

                # Step 3: Decrypt the payload
                decrypted_params = decrypt_message(payload, SHARED_SECRET_KEY, iv).decode()

                if encrypted_session_token:
                    encrypted_session_bytes = base64.b64decode(encrypted_session_token)
                    decrypted_session_token = decrypt_message(encrypted_session_bytes, SHARED_SECRET_KEY, iv).decode()
                
                # Parse parameters into the request context
                if request.method == 'GET':
                    request.decrypted_params = dict(
                        param.split("=") for param in decrypted_params.split("&")
                    )
                else:
                    request.decrypted_params = json.loads(decrypted_params)

                if encrypted_session_token:
                    request.decrypted_headers = {**request.headers, "session": decrypted_session_token}
                    
                # Step 4: Execute the original function
                response_message, code = func(*args, **kwargs)
                response_message: Response

                # Step 5: Encrypt the response
                response_iv = os.urandom(16)
                encrypted_response = encrypt_message(response_message.data.decode(), SHARED_SECRET_KEY, response_iv)
                response_hmac = create_hmac(encrypted_response, SHARED_SECRET_KEY)

                return jsonify({
                    "iv": base64.b64encode(response_iv).decode(),
                    "ciphertext": base64.b64encode(encrypted_response).decode(),
                    "hmac": base64.b64encode(response_hmac).decode()
                }), code

            except Exception as e:
                return jsonify({"error": "Invalid request", "message": str(e)}), 400

        return wrapper
    
    return decorator
