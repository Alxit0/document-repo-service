# Improvements made after the defense

## Encrypt data in the database

On server initialazation, it loads a key that will use to encrypt and decrypt sencible data.

This improvement just makes the data to be stored encrypted. The processing and usage are all in the raw form.

## Replay attacks prevention

This improvement implements a sequence protocol to invalidate past requests. (to prevent against replay attacks)

**Assign and Store Sequence Numbers**: Each client has a sequence number, which will be incremented for each request. The sequence numbers are saved on the server, mapped to the client ID.

**Validate Sequence Numbers**: When a request is received, the sequence number must be strictly greater than the last sequence number we have stored for the client.

**Update the Sequence Number**: After validating the request, the stored sequence number is updated for the client.

**In Case of Rebooting**: In case of server reboting we are going to lose all the numberings. However, in this case of server rebooting, the shared keys will also be lost, wich will require the renegotiating of the shared key, wich will render the request useless for replaying.  

## Validate server

The server sends the chalenge signed with tis private key for the user to validate.

### Steps for Mutual Authentication (both client and server):
- **Server Signs the Nonce**: When the client requests a challenge, the server signs the nonce with its private key to prove its identity.

- **Client Verifies the Server's Signature**: The client checks the signature using the pre-shared server public key, ensuring the server is legitimate.

- **Client Signs the Nonce**: The client signs the nonce with its own private key to authenticate itself to the server.

- **Server Verifies the Client's Signature**: The server checks the client's signature using the client's stored public key, authenticating the client.

## Db refactor

The refactor involved the deletion and modification of certain tables. 

These tables were identified as unnecessary because their concepts and purposes were duplicated elsewhere in the database.
