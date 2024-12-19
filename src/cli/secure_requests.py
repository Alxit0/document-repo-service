import copy
import json as json_lib
from typing import Literal
import uuid
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, serialization
import base64
import os
import utils

# Shared secret key for encryption and HMAC
SHARED_SECRET_KEY = None  # 32 bytes for AES-256


# Diffie-Hellman exchange
def fetch_server_parameters():
    print("Negociating key ... ")
    response = requests.get(f"http://{utils.state['REP_ADDRESS']}/get-parameters")
   
    if response.status_code != 200:
        raise Exception("Failed to fetch DH parameters.")
   
    parameters_pem = base64.b64decode(response.json()["parameters"])
    
    return serialization.load_pem_parameters(parameters_pem)

def initiate_dh_key_exchange():

    parameters = fetch_server_parameters()
    
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # gen client id
    if 'client_id' not in utils.state:
        utils.state['client_id'] = str(uuid.uuid4())
    client_id = utils.state['client_id']
    
    # send the client's public key and ID to the server
    response = requests.post(
        f"http://{utils.state['REP_ADDRESS']}/dh-init",
        json={
            "client_id": client_id,
            "client_public_key": base64.b64encode(public_key_bytes).decode()
        }
    )

    if response.status_code != 200:
        raise Exception(f"Key exchange failed: {response.json()}")

    # parse the server's public key from the response
    server_public_key_bytes = base64.b64decode(response.json()["server_public_key"])
    server_public_key = serialization.load_pem_public_key(server_public_key_bytes)

    # Compute the shared secret
    shared_secret = private_key.exchange(server_public_key)

    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared_secret)
    valid_key = digest.finalize()  # 256-bit (32 bytes) key
    print(valid_key.hex())

    return valid_key

def check_secure_key(force=False):
    global SHARED_SECRET_KEY

    if 'SHARED_SECRET_KEY' in utils.state and not force:
        SHARED_SECRET_KEY = base64.b64decode(utils.state['SHARED_SECRET_KEY'])
        return 
    
    SHARED_SECRET_KEY = initiate_dh_key_exchange()
    utils.state['SHARED_SECRET_KEY'] = base64.b64encode(SHARED_SECRET_KEY).decode()


# secure comunication
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
    new_headers = copy.deepcopy(headers) or {}
    new_headers.update({
        "Client-Id": utils.state['client_id'],
        "X-Encrypted-IV": base64.b64encode(iv).decode(),
        "X-HMAC": base64.b64encode(hmac_value).decode()
    })

    if "session" in new_headers:
        encrypted_session_token = encrypt_message(headers["session"], SHARED_SECRET_KEY, iv)
        new_headers["session"] = base64.b64encode(encrypted_session_token).decode()

    return new_headers, {mode: {"payload": base64.b64encode(encrypted_params).decode()}}

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


def secure_get(url, headers=None, params=None, *, _lvl=0):
    check_secure_key()
    
    # encrypt data
    new_headers, body = prepare_data(headers, params, "params")

    # make request
    response = requests.get(
        url,
        headers=new_headers,
        **body
    )

    # regnociar keys
    if response.status_code == 101 and _lvl < 2:
        check_secure_key(force=True)
        return secure_get(url, headers, params, _lvl=_lvl+1)
    
    # decrypt response
    return prepare_response(response)

def secure_post(url, headers=None, data=None, json=None, files=None, *, _lvl=0):
    check_secure_key()

    # encrypt data
    if data:
        new_headers, body = prepare_data(headers, data, "data")
    elif json:
        new_headers, body = prepare_data(headers, json, "json")
    else:
        new_headers, body = prepare_data(headers, {}, "json")

    # make request
    response = requests.post(
        url, 
        headers=new_headers,
        **body,
        files=files
    )

    # status_code 201 to skip decryption
    if response.status_code == 201:
        return response
    
    # regnociar keys
    if response.status_code == 101 and _lvl < 2:
        check_secure_key(force=True)
        return secure_post(url, headers, data, json, files, _lvl=_lvl+1)

    # decrypt response
    return prepare_response(response)

def secure_put(url, headers=None, data=None, json=None, files=None, *, _lvl=0):
    check_secure_key()

    # encrypt data
    if data:
        new_headers, body = prepare_data(headers, data, "data")
    elif json:
        new_headers, body = prepare_data(headers, json, "json")
    else:
        new_headers, body = prepare_data(headers, {}, "json")

    # make request
    response = requests.put(
        url, 
        headers=new_headers,
        **body,
        files=files
    )

    # status_code 201 to skip decryption
    if response.status_code == 201:
        return response
    
    # regnociar keys
    if response.status_code == 101 and _lvl < 2:
        check_secure_key(force=True)
        return secure_post(url, headers, data, json, files, _lvl=_lvl+1)

    # decrypt response
    return prepare_response(response)

def secure_delete(url, headers=None, data=None, json=None, files=None, *, _lvl=0):
    check_secure_key()

    # encrypt data
    if data:
        new_headers, body = prepare_data(headers, data, "data")
    elif json:
        new_headers, body = prepare_data(headers, json, "json")
    else:
        new_headers, body = prepare_data(headers, {}, "json")

    # make request
    response = requests.delete(
        url, 
        headers=new_headers,
        **body,
        files=files
    )

    # status_code 201 to skip decryption
    if response.status_code == 201:
        return response
    
    # regnociar keys
    if response.status_code == 101 and _lvl < 2:
        check_secure_key(force=True)
        return secure_delete(url, headers, data, json, files, _lvl=_lvl+1)

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
