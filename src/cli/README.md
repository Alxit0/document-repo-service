# Command Line Interface Documentation

This document provides details on how to use the command-line interface (CLI) for managing RSA keys and repository configurations with the provided script. 

## Command: `rep_subject_credentials`

The `rep_subject_credentials` command generates a new RSA key pair and encrypts the private key with a password.

### Description

This command creates a new RSA private and public key pair, saving the public key in a PEM format and the private key in an encrypted PEM format using the specified password. The keys are stored in the user's home directory under the `.sio` folder.

### Usage

```bash
rep_subject_credentials [OPTIONS]  <password> <credentials file>
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

## Command: `rep_create_org`

The `rep_create_org` command is used to create a new organization in the system by providing details about the organization, user, and public key file. This command requires several arguments to be provided, including organization details, user information, and the path to a public key file.

### Usage

```bash
rep_create_org [OPTIONS] <organization> <username> <name> <email> <pub_key_file>
```

### Parameters

- `organization` (required): The name of the organization you wish to create.
- `username` (required): The username of the person creating the organization.
- `name` (required): The full name of the person creating the organization.
- `email` (required): The email address of the person creating the organization.
- `pub_key_file` (required): Path to a file containing the public key for the organization. This file must exist, and it must be a file (not a directory).

### Notes
- Ensure that the public key file exists and is specified correctly as a file path.
- The command will log the response from the server.

## Command: `rep_list_orgs`
The `rep_list_orgs` command retrieves and displays a list of organizations currently registered in the system. The command sends a request to an API endpoint and displays each organization's name along with the username of the creator.

### Usage
```bash
rep_list_orgs [OPTIONS]
```
This command does not require any arguments.

When run, this command will output a table that shows the list of organizations and their respective creators. The format of the output is as follows:


```
Org name             | Creator
----------------------------------------
ExampleOrg           | creator_username
AnotherOrg           | another_creator
```

### Notes
The command will log the API response for debugging purposes.
If the API call is unsuccessful (i.e., it does not return a 200 status code), the command will print the error message from the server and terminate without displaying the table.

## Command: `rep_create_session`
The `rep_create_session` command initiates a session with the server by authenticating the user with their organization, username, password, and a signature derived from a private key. This command generates and stores a session token for future authenticated requests.

### Usage
```bash
rep_create_session [OPTIONS] <organization> <username> <password> <cred_file> <session_file>
```

This command uses a challenge-response mechanism to securely create a session. It signs a server-provided nonce using the user’s private key and stores the session token in the specified session file.

### Parameters
- `organization` (required): Name of the organization associated with the user.
- `username` (required): Username of the user initiating the session.
- `password` (required): Password for decrypting the private key in the credential file.
- `cred_file` (required): Path to a JSON file containing the user's encrypted private key. This file must exist and contain the `REP_PRIV_KEY`.
- `session_file` (required): Path to the file where the session token will be saved. If the file does not exist, it will be created.

### Notes
- The command first retrieves a nonce from the server and signs it with the private key found in `cred_file`.
- If the password for the private key is incorrect, an error will be returned.
- The session token is saved to `session_file`, allowing subsequent commands to use this token for authentication.
- Ensure `utils.state['REP_ADDRESS']` contains the correct server address for this command to connect to the appropriate server endpoints (`/session/challenge` and `/session/create`).

## Command: `rep_add_doc`
The `rep_add_doc` command encrypts and uploads a document to the system, using a session file to authenticate the upload. The document is encrypted with a randomly selected encryption algorithm and mode before being sent to the server.

### Usage
```bash
rep_add_doc [OPTIONS] <session_file> <document_name> <file>
```
The command will read the session token, encrypt the specified document, and upload the encrypted data to the server.

### Parameters
- `session_file` (required): Path to the file containing the session token used for authentication. This file must exist.
- `document_name` (required): The name of the document to be uploaded.
- `file` (required): Path to the document file that will be encrypted and uploaded. This file must exist.

### Notes
- Ensure that both the session file and document file paths are valid and exist.
- The encryption algorithm and mode are randomly selected from a list of valid combinations
