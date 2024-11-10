import base64
import hashlib
import os
import logging
import json
import random
import secrets
import sys
import click
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import requests

from file_encryption import encrypt_file, VALID_ALGOS_MODES_COMBOS

logging.basicConfig(format='%(levelname)s\t- %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Global state dictionary
state = None

def load_state():
    state = {}
    state_dir = os.path.join(os.path.expanduser('~'), '.sio')
    state_file = os.path.join(state_dir, 'state.json')

    os.makedirs(state_dir, exist_ok=True)

    logger.debug('State folder: ' + state_dir)
    logger.debug('State file: ' + state_file)
    
    if os.path.exists(state_file):
        logger.debug('Loading state')
        with open(state_file,'r') as f:
            state = json.loads(f.read())

    if state is None:
        state = {}

    return state

def parse_env(state):
    if 'REP_ADDRESS' in os.environ:
        state['REP_ADDRESS'] = os.getenv('REP_ADDRESS')
        logger.debug(f'Setting REP_ADDRESS from Environment to: {state["REP_ADDRESS"]}')

    if 'REP_PUB_KEY' in os.environ:
        rep_pub_key = os.getenv('REP_PUB_KEY')
        logger.debug('Loading REP_PUB_KEY fron: ' + state['REP_PUB_KEY'])
        if os.path.exists(rep_pub_key):
            with open(rep_pub_key, 'r') as f:
                state['REP_PUB_KEY'] = f.read()
                logger.debug('Loaded REP_PUB_KEY from Environment')
    return state

def parse_args(state, key, repo, verbose):
    if verbose:
        logger.setLevel(logging.DEBUG)
        logger.info('Setting log level to DEBUG')

    if key:
        if not os.path.exists(key) or not os.path.isfile(key):
            logger.error(f'Key file not found or invalid: {key}')
            sys.exit(-1)
        
        with open(key, 'r') as f:
            state['REP_PUB_KEY'] = f.read()
            logger.info('Overriding REP_PUB_KEY from command line')

    if repo:
        state['REP_ADDRESS'] = repo
        logger.info('Overriding REP_ADDRESS from command line')
    
    return state

def save(state):
    state_dir = os.path.join(os.path.expanduser('~'), '.sio')
    state_file = os.path.join(state_dir, 'state.json')

    if not os.path.exists(state_dir):
        logger.debug('Creating state folder')
        os.mkdir(state_dir)

    with open(state_file, 'w') as f:
        f.write(json.dumps(state, indent=4))

    logger.info('State saved successfully.')
    logger.debug(state)


@click.group(invoke_without_command=True)
@click.option('-k', '--key', type=click.Path(exists=True, dir_okay=False), help="Path to the key file")
@click.option('-r', '--repo', help="Address:Port of the repository")
@click.option('-v', '--verbose', is_flag=True, help="Increase verbosity")
@click.help_option('-h', '--help')
def main(key, repo, verbose):
    global state

    # Load initial state
    state = load_state()
    state = parse_env(state)
    state = parse_args(state, key, repo, verbose)

@main.result_callback()
def save_on_exit(result, **kwargs):
    """Save the state after all commands have been processed."""
    save(state)


# standalone commands
@main.command()
@click.argument('password', required=True, type=str)
@click.argument('cred_file', required=True, type=str)
def rep_subject_credentials(password: str, cred_file: str):
    """Generate a new RSA key pair and encrypt the private key."""

    # Paths for saving keys
    private_key_path = os.path.join(os.path.expanduser('~'), '.sio', 'private_key.pem')
    public_key_path = os.path.join(os.path.expanduser('~'), '.sio', 'public_key.pem')
    
    # gen RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()   
    )
    public_key = private_key.public_key()

    # save public key
    with open(public_key_path, "wb") as pub_file:
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pub_file.write(public_key_bytes)
    logger.info(f"Public key saved to {public_key_path}")

    # save encrypted private key
    encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
    with open(private_key_path, "wb") as priv_file:
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        priv_file.write(private_key_bytes)
    logger.info(f"Private key saved to {private_key_path} (encrypted)")

    # save both keys to given file path
    keys_obj = {
        'REP_PUB_KEY': public_key_bytes.decode(),
        'REP_PRIV_KEY': private_key_bytes.decode()
    }
    state.update(keys_obj)

    with open(cred_file, "+w") as file:
        json.dump(keys_obj, file, indent=4)


# anonymous API commands
@main.command()
@click.argument('organization', required=True, type=str)
@click.argument('username', required=True, type=str)
@click.argument('name', required=True, type=str)
@click.argument('email', required=True, type=str)
@click.argument('pub_key_file', required=True, type=click.Path(exists=True, dir_okay=False))
def rep_create_org(organization: str, username: str, name: str, email: str, pub_key_file: str):
    
    # read public key
    with open(pub_key_file, 'r') as file:
        public_key = file.read()
    
    body = {
        "organization": organization,
        "username": username,
        "name": name,
        "email": email,
        "public_key": public_key
    }

    res = requests.post(f'http://{state['REP_ADDRESS']}/organization/create', json=body)
    logger.debug(res)
    logger.info(res.content.decode())

@main.command()
def rep_list_orgs():

    res = requests.get(f'http://{state['REP_ADDRESS']}/organization/list')

    # check status of api call    
    logger.debug(res)
    if res.status_code != 200:
        print(json.loads(res.content))
        return

    # display info
    print(f"{'Org name':<20} | {'Creator'}")
    print("-"*40)
    for org in json.loads(res.content)['organizations']:
        print(f"{org['organization_name']:<20} | {org['creator_username']}")

@main.command()
@click.argument('organization', required=True, type=str)
@click.argument('username', required=True, type=str)
@click.argument('password', required=True, type=str)
@click.argument('cred_file', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('session_file', required=True, type=click.Path(dir_okay=False))
def rep_create_session(organization: str, username: str, password: str, cred_file: str, session_file: str):
    
    # get challenge
    params = {"username": username}
    res = requests.get(f'http://{state['REP_ADDRESS']}/session/challenge', params=params)

    logger.debug(res)
    if res.status_code != 200:
        logger.info(json.loads(res.content))
        return

    nonce = json.loads(res.content)['nounce']

    # Load and decrypt the private key
    with open(cred_file, 'r') as file:
        keys = json.load(file)
    
    try:
        private_key = serialization.load_pem_private_key(
            keys['REP_PRIV_KEY'].encode('utf-8'),
            password=password.encode()
        )
    except ValueError:
        logger.info("Wrong password.")
        return

    # sign the nonce
    signature = private_key.sign(
        base64.b64decode(nonce),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # get session thorugh challenge
    payload = {
        "organization": organization,
        "username": username,
        "password": password,
        "signature": base64.b64encode(signature).decode()
    }

    res = requests.post(f'http://{state['REP_ADDRESS']}/session/create', json=payload)
    logger.debug(res)
    logger.info(res.content.decode())
    
    if res.status_code != 200:
        return
    
    data = json.loads(res.content)

    with open(session_file, "+w") as file:
        file.write(data['session_token'])

    return

@main.command()
@click.argument('session_file', required=True, type=click.Path(exists=True, dir_okay=False))
@click.argument('document_name', required=True, type=str)
@click.argument('file', required=True, type=click.Path(exists=True, dir_okay=False))
def rep_add_doc(session_file: str, document_name: str, file: str):

    # Extract session
    with open(session_file, 'r') as f:
        session = f.read()

    # encrypt file
    algo, mode = random.choice(VALID_ALGOS_MODES_COMBOS)
    
    encrypted_file_data, key, iv, nonce = encrypt_file(file, algo, mode)

    # gen digest for file handle
    with open(file, 'rb') as f:
        file_handle = hashlib.sha256(f.read()).hexdigest()

    # Encode encrypted file and IV for JSON compatibility
    encrypted_file_b64 = base64.b64encode(encrypted_file_data).decode('utf-8')
    iv_b64 = base64.b64encode(iv).decode('utf-8')
    key_b64 = base64.b64encode(key).decode('utf-8')
    nonce_b64 = base64.b64encode(nonce).decode('utf-8')

    # Prepare request data
    headers = {
        "session": session
    }

    data = {
        "encrypted_file": encrypted_file_b64,
        "name": document_name,
        "file_handle": file_handle,
        
        "iv": iv_b64,
        "encryption_key": key_b64,
        "nonce": nonce_b64,
        "algorithm": f"{algo}-{mode}",
    }

    # Send the request to upload the encrypted file
    response = requests.post(
        f"http://{state['REP_ADDRESS']}/file/upload",
        json=data,
        headers=headers
    )

    # Check response
    if response.status_code == 200:
        print("Document uploaded successfully.")
    else:
        print("Failed to upload document:", response.text)

if __name__ == '__main__':
    main()
