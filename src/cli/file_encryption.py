from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

import os

ALGOS = {
    'AES': lambda x,y: algorithms.AES(x),
    'ChaCha20': lambda x,y: algorithms.ChaCha20(x, y),
    'AES128': lambda x,y: algorithms.AES128(x),
    'AES256': lambda x,y: algorithms.AES256(x),
    'Camellia': lambda x,y: algorithms.Camellia(x),
    '': lambda x,y: None,
}

MODES = {
    "CBC": lambda x: modes.CBC(x),
    "OFB": lambda x: modes.OFB(x),
    "CFB": lambda x: modes.CFB(x),
    "ECB": lambda x: modes.ECB(),
    '': lambda x: None,
}

VALID_ALGOS_MODES_COMBOS = [
    ('AES', 'CBC'),
    ('AES', 'OFB'),
    ('AES', 'CFB'),
    ('AES', 'ECB'),
    ('ChaCha20', ''),
    ('AES256', 'CBC'),
    ('AES256', 'OFB'),
    ('AES256', 'CFB'),
    ('AES256', 'ECB'),
    ('Camellia', 'CBC'),
    ('Camellia', 'OFB'),
    ('Camellia', 'CFB'),
    ('Camellia', 'ECB')
]


def encrypt_file(file_path: str, algo='AES', mode='CBC'):
    # gen values
    key = os.urandom(32)
    iv = os.urandom(16)
    nonce = os.urandom(16)

    # read file
    with open(file_path, "rb") as file:
        text = file.read()

    # padding
    padder =  padding.PKCS7(128).padder()
    text = padder.update(text)
    text += padder.finalize()

    # encrypt
    cipher = Cipher(ALGOS[algo](key,nonce), MODES[mode](iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(text) + encryptor.finalize()

    return ct, key, iv, nonce

def decrypt_file(key, iv, nonce, file_path: str, algo='AES', mode='CBC'):
    

    with open(file_path, "rb") as file:
        ct = file.read()
    
    # decrypt
    cipher = Cipher(ALGOS[algo](key,nonce), MODES[mode](iv))
    decryptor = cipher.decryptor()
    text = decryptor.update(ct) + decryptor.finalize()

    # unpadd
    unpadder =  padding.PKCS7(128).unpadder()
    data = unpadder.update(text)
    data += unpadder.finalize()

def main():
    """To generate all the valid combinations of algo/modes"""
    
    for i in ALGOS:
        for j in MODES:
            try:
                encrypt_file('./README.md', i, j)
                print((i, j))
            except:
                pass

if __name__ == '__main__':
    main()