from datetime import datetime, timedelta
from jwt import encode, decode, exceptions
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey

# change for env variable
SECRET = "JrjvV*pV7j5lpY4Xf*CTo_vsn1U*mpikYGJ9FHWHsM&xXgMOAOj%Jd#5VslxUyUzEI4lOQUQNxB#oybe56VGFT%R5p8MEA7P#30VCsm6u&eUHryW#xVt5dJwZm?UHFtld3TVKxfMgNr5h#x5njj4SJjQYYJOqUwU1KGI9OUnuUUtxLE76o5JSdG7Nh4!aRrchWEQoTzG*Kgu1YKHXWdS0_J_v0nersuDki30Nofd5eLpBmwVu53vdFzQYifVUbUGS2L7e6Fz8jbFU?3F?Y%jEmbd#Dl&DefV*Pav4v%1?akD"

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
