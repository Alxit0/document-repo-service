# Command Line Interface Documentation

This document provides details on how to use the command-line interface (CLI) for managing RSA keys and repository configurations with the provided script. 

## Command: `rep_subject_credentials`

The `rep_subject_credentials` command generates a new RSA key pair and encrypts the private key with a password.

### Description

This command creates a new RSA private and public key pair, saving the public key in a PEM format and the private key in an encrypted PEM format using the specified password. The keys are stored in the user's home directory under the `.sio` folder.

### Usage

```bash
python client.py [OPTIONS] rep_subject_credentials <password> <credentials file>
```

### Parameters

- `password` (required): The password used to encrypt the private key. This should be a secure and memorable string.
- `credentials file` (required): The path of the file to save the public and encrypted private key in JSON format.

### Key Files Generated

- **Public Key**: 
  - Location: `~/.sio/public_key.pem`
  - Format: PEM
  - Description: This file contains the public part of the RSA key pair, which can be shared publicly.

- **Private Key**:
  - Location: `~/.sio/private_key.pem`
  - Format: PEM (encrypted)
  - Description: This file contains the private part of the RSA key pair, encrypted using the provided password. It should be kept secure and private.