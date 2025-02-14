from datetime import datetime, timedelta
import os
from jwt import encode, decode, exceptions
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey

SECRET = os.getenv('JWT_SECRET')

# cryptografic related functions
def verify_client_identity(password: str, encrypted_private_key_bytes: bytes, stored_public_key_bytes: bytes):
    """Verify client's identity using the provided encrypted private key and password."""
    
    try:
        # Attempt to decrypt the private key with the provided password
        private_key = serialization.load_pem_private_key(
            encrypted_private_key_bytes,
            password=password.encode(),  # provided password to decrypt
            backend=default_backend()
        )

        # Generate the public key from the decrypted private key
        regenerated_public_key = private_key.public_key()
        
        # Serialize regenerated public key to bytes for comparison
        regenerated_public_key_bytes = regenerated_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Compare the regenerated public key with the stored public key
        if regenerated_public_key_bytes == stored_public_key_bytes:
            return True
        else:
            return False

    except ValueError as e:
        # Log the error for debugging (optional)
        print("Decryption failed. Possible incorrect password or corrupted private key.", e)
        return False
    
    except InvalidKey:
        return False

def verify_signature(public_key_pem, nonce, signature):
    # Load the public key
    public_key = serialization.load_pem_public_key(public_key_pem)

    # Verify the signature
    try:
        public_key.verify(
            signature,
            nonce,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True  # Signature is valid
    except Exception as e:
        return False  # Signature is invalid

# JWTokens related functions
def write_token(data: dict) -> str:
    """Generate the jwtoken

    Args:
        data (dict): information to store on the token

    Returns:
        str: the token in str
    """

    # duracao de validade do token
    expier_date = lambda time: datetime.now() + timedelta(minutes=time)
    
    # criacao do token
    token = encode(payload={**data, "exp": expier_date(60)}, key=SECRET, algorithm="HS256")
    return token

def verify_token(token: str, *, verify_exp=True) -> bool:
    """Verificar se token e valido ou nao

    Args:
        token (str): token para validar

    Returns:
        bool: 'True' se for valido 'False' se nao
    """

    options = {"verify_exp": verify_exp}

    try:
        # if it runs with no problem means its valid
        decode(token, key=SECRET, algorithms=["HS256"], options=options)
    except exceptions.DecodeError:
        # in case we cannot decode

        return False
    except exceptions.ExpiredSignatureError:
        # in case the token validation as expired
        return False
    
    return True

def extrat_token_info(token: str, *, verify_exp=True) -> dict | None:
    """Extrat the stored information on the token

    Args:
        token (str): token to extrat the information of

    Returns:
        dict | None: dictionary coded on the token
    """

    options = {"verify_exp": verify_exp}
    try:
        # if it runs with no problem means its valid
        return decode(token, key=SECRET, algorithms=["HS256"], options=options)

    except exceptions.DecodeError:
        # in case we cannot decode
        return None
        
    except exceptions.ExpiredSignatureError:
        # in case the token validation as expired
        return None
