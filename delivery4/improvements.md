# Improvements made after the defense

## Encrypt data in the database

On server initialazation, it loads a key that will use to encrypt and decrypt sencible data.

This improvement just makes the data to be stored encrypted. The processing and usage are all in the raw form.

**Code reference**:
```python
cur.execute(
    """
    INSERT INTO document_metadata (document_id, encryption_key, alg, iv, nonce)
    VALUES (?, ?, ?, ?, ?)
    """,
    (
        doc_id, 
        cipher_suite.encrypt(encrypted_key.encode()), 
        cipher_suite.encrypt(alg.encode()), 
        cipher_suite.encrypt(iv.encode()), 
        cipher_suite.encrypt(nonce.encode())
    )
)
```
> api/app.py 480-492 

## Replay attacks prevention

This improvement implements a sequence protocol to invalidate past requests. (to prevent against replay attacks)

**Assign and Store Sequence Numbers**: Each client has a sequence number, which will be incremented for each request. The sequence numbers are saved on the server, mapped to the client ID.

**Validate Sequence Numbers**: When a request is received, the sequence number must be strictly greater than the last sequence number we have stored for the client.

**Update the Sequence Number**: After validating the request, the stored sequence number is updated for the client.

**In Case of Rebooting**: In case of server reboting we are going to lose all the numberings. However, in this case of server rebooting, the shared keys will also be lost, wich will require the renegotiating of the shared key, wich will render the request useless for replaying.  

**Code reference**:
```python
# verify numbering
if client_id not in client_sequence_numbers:
    client_sequence_numbers[client_id] = 0

if sequence_number <= client_sequence_numbers[client_id]:
    return jsonify({"error": "Invalid sequence number"}), 403

client_sequence_numbers[client_id] = sequence_number
```
> api/secure_communication.py 124-131

## Validate server

The server sends the chalenge signed with tis private key for the user to validate.

### Steps for Mutual Authentication (both client and server):
- **Server Signs the Nonce**: When the client requests a challenge, the server signs the nonce with its private key to prove its identity.

- **Client Verifies the Server's Signature**: The client checks the signature using the pre-shared server public key, ensuring the server is legitimate.

- **Client Signs the Nonce**: The client signs the nonce with its own private key to authenticate itself to the server.

- **Server Verifies the Client's Signature**: The server checks the client's signature using the client's stored public key, authenticating the client.

**Code reference**:
```python
server_signature = response_data['signature']

# verify server signature
server_public_key = serialization.load_pem_public_key(utils.state['REP_PUB_KEY'].encode())
try:
    server_public_key.verify(
        base64.b64decode(server_signature),
        nonce.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
except Exception as e:
    logger.info("Failed to verify server signature.")
    return -1
```
> cli/rep_create_session 48-64

## Db refactor

The refactor involved the deletion and modification of certain tables. 

These tables were identified as unnecessary because their concepts and purposes were duplicated elsewhere in the database.
