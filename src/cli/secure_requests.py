import json as json_lib
from typing import Literal
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
import base64
import os

# Shared secret key for encryption and HMAC
SHARED_SECRET_KEY = b'\xe4\xe1\x9d\xef\xcc\xc8\xf7\x1f5p\xda\x83\xe4\xc1W\x06\xbdQgH\xe7\xda\xd0\xd5c\x13D\x0f\xee$fG'  # 32 bytes for AES-256


def encrypt_message(message, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(message.encode()) + encryptor.finalize()

def decrypt_message(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def create_hmac(data, key):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

def verify_hmac(data, key, hmac_to_verify):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    h.verify(hmac_to_verify)


def prepare_data(headers, data, mode: Literal["params", "json", "data"]):

    if data is None:
        data = {}

    # encrypt the parameters
    iv = os.urandom(16)

    query_string = json_lib.dumps(data)
    encrypted_params = encrypt_message(query_string, SHARED_SECRET_KEY, iv)

    # generate HMAC for the encrypted parameters
    hmac_value = create_hmac(encrypted_params, SHARED_SECRET_KEY)

    # add the IV and HMAC to headers
    headers = headers or {}
    headers.update({
        "X-Encrypted-IV": base64.b64encode(iv).decode(),
        "X-HMAC": base64.b64encode(hmac_value).decode()
    })

    if "session" in headers:
        encrypted_session_token = encrypt_message(headers["session"], SHARED_SECRET_KEY, iv)
        headers["session"] = base64.b64encode(encrypted_session_token).decode()

    return headers, {mode: {"payload": base64.b64encode(encrypted_params).decode()}}

def prepare_response(response: requests.Response):

    # status_code 201 to skip decryption
    if response.status_code == 201:
        return response

    # Extract encrypted response
    encrypted_response = base64.b64decode(response.json()["ciphertext"])
    response_iv = base64.b64decode(response.json()["iv"])
    response_hmac = base64.b64decode(response.json()["hmac"])

    # Verify the HMAC
    verify_hmac(encrypted_response, SHARED_SECRET_KEY, response_hmac)

    # Decrypt the response
    decrypted_response = decrypt_message(encrypted_response, SHARED_SECRET_KEY, response_iv)
    response._content = decrypted_response
    return response


def secure_get(url, headers=None, params=None):
    
    # encrypt data
    headers, body = prepare_data(headers, params, "params")

    # make request
    response = requests.get(
        url,
        headers=headers,
        **body
    )
    
    # decrypt response
    return prepare_response(response)

def secure_post(url, headers=None, data=None, json=None, files=None):

    # encrypt data
    if data:
        headers, body = prepare_data(headers, data, "data")
    elif json:
        headers, body = prepare_data(headers, json, "json")
    else:
        headers, body = prepare_data(headers, {}, "json")

    # make request
    response = requests.post(
        url, 
        headers=headers,
        **body,
        files=files
    )

    # decrypt response
    return prepare_response(response)


def _example():
    # Example usage

    headers = {"session": "your_jwt_token"}
    params = {"document_name": "example_document"}

    response = secure_get(
        f"http://localhost:5000/file/metadata",
        headers=headers,
        params=params
    )

    print("Decrypted response:", response)
