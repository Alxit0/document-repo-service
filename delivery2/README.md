[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/n4Xu0y1X)
[![Open in Visual Studio Code](https://classroom.github.com/assets/open-in-vscode-2e0aaae1b6195c2367325f4f02e2d04e9abb55f0b24a779b69b11b9e10269abc.svg)](https://classroom.github.com/online_ide?assignment_repo_id=16738923&assignment_repo_type=AssignmentRepo)
# sio_2425_project

# Group members
- Bernardo Borges (103592)
- Alexandre Regalado (124562)
- António Moreira (93279)

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

## Command: `rep_list_docs`
The `rep_list_docs` command retrieves a list of documents, with options to filter results by username and/or date. Authentication is handled through a session file containing a session token.

### Usage
```bash
rep_list_docs [OPTIONS] <session_file>
```

This command reads the session token from the provided session file and retrieves document information from the server. Optional filters include username and date.

### Parameters
- `session_file` (required): Path to the file containing the session token used for authentication. This file must exist and contain a valid session token.
- `username` (optional): Username to filter the document list. Only documents associated with this username will be shown.
- `date` (optional): A date filter to narrow down results by specific date criteria. Specify the date in two parts:
  - Filter type: Use one of the following:
    - `'nt'` - Show documents on or after the specified date
    - `'ot'` - Show documents on or before the specified date
    - `'et'` - Show documents from exactly the specified date
  - Date value: Format the date as `'YYYY-MM-DD'`

### Notes
- If the `date` option is used, ensure the format follows `[nt|ot|et] YYYY-MM-DD`.
- Invalid date formats or unsupported filter types will return an error message.
- The command communicates with the server endpoint `http://localhost:5000/file/list`, passing the session token in the request header and applying any specified filters.

## Command: `rep_get_file`
The `rep_get_file` command retrieves a specified file from the server using its unique handle. The command can print the file contents directly or save them to a specified file path.

### Usage
```bash
rep_get_file [OPTIONS] <file_handle> [file]
```

This command downloads a file identified by `file_handle` from the server. If a file path is provided, the content is saved to this location; otherwise, it is printed to the console in base64 encoding.

### Parameters
- `file_handle` (required): The unique identifier for the file on the server.
- `file` (optional): The local path where the downloaded file will be saved. If omitted, the file content is printed in base64 format.

### Notes
- If `file` is not provided, the file content will be displayed in base64-encoded format in the console.
- The server endpoint for downloading files is derived from `utils.state['REP_ADDRESS']` combined with `/file/download/{file_handle}`.
- Ensure that `utils.state['REP_ADDRESS']` is set correctly to connect to the proper server address.

## Command: `rep_get_doc_metadata`
The `rep_get_doc_metadata` command retrieves metadata for a specific document on the server using a session token for authentication.

### Usage
```bash
rep_get_doc_metadata [OPTIONS] <session_file> <document_name>
```

This command reads the session token from `session_file` and fetches metadata for the document identified by `document_name`. The metadata is printed in JSON format.

### Parameters
- `session_file` (required): Path to the file containing the session token. This file must exist and include a valid session token for authentication.
- `document_name` (required): The name of the document for which metadata is requested.

### Notes
- If metadata retrieval fails, an error message with the server’s response is displayed.
- The server endpoint for retrieving metadata is `http://{utils.state['REP_ADDRESS']}/file/metadata`.
- Ensure `utils.state['REP_ADDRESS']` contains the correct server address for the metadata request to succeed.

## Command: `rep_list_subjects`
The `rep_list_subjects` command lists subjects associated with the organization. Optionally, the results can be filtered by a specific username.

### Usage
```bash
rep_list_subjects [OPTIONS] <session_file> [username]
```

This command uses the session token from `session_file` to authenticate the request. If `username` is provided, only the details for that user will be returned. Otherwise, the command lists all subjects for the organization.

### Parameters
- `session_file` (required): Path to the file containing the session token. This file must exist and contain a valid session token.
- `username` (optional): The username to filter the list of subjects. If not provided, all subjects are listed.

### Notes
- The server endpoint for listing subjects is `http://{utils.state['REP_ADDRESS']}/subject/list`.
- Each subject is displayed with their username, name, and status (Active or Suspended).
- If no subjects match the criteria, a message indicating this is displayed.
- Ensure `utils.state['REP_ADDRESS']` is set to the correct server address.

## Command: `rep_add_subject`
The `rep_add_subject` command adds a new subject to the system, providing their username, name, email, and public key. This is done using the session token for authentication.

### Usage
```bash
rep_add_subject [OPTIONS] <session_file> <username> <name> <email> <cred_file>
```

This command uses the session token from `session_file` and the public key from the provided `cred_file` to add a new subject to the system with the given `username`, `name`, and `email`.

### Parameters
- `session_file` (required): Path to the file containing the session token. This file must exist and contain a valid session token.
- `username` (required): The username of the subject being added.
- `name` (required): The full name of the subject.
- `email` (required): The email address of the subject.
- `cred_file` (required): Path to the file containing the subject’s public key. This file must exist and contain a valid public key under the key `REP_PUB_KEY`.

### Notes
- The command loads and decrypts the public key from `cred_file`.
- The server endpoint for adding a subject is `http://{utils.state['REP_ADDRESS']}/subject/add`.
- The command sends a POST request with the subject details (username, name, email, and public key) in the request body.
- Ensure that `utils.state['REP_ADDRESS']` is correctly set to the appropriate server address for communication.

## Command: `rep_suspend_subject`
The `rep_suspend_subject` command suspends a specified subject in the system. It requires a valid session token and the username of the subject to be suspended.

### Usage
```bash
rep_suspend_subject [OPTIONS] <session_file> <username>
```

This command uses the session token from `session_file` to authenticate the request and suspends the subject identified by `username`.

### Parameters
- `session_file` (required): Path to the file containing the session token. This file must exist and include a valid session token.
- `username` (required): The username of the subject to suspend.

### Notes
- The server endpoint for suspending a subject is `http://{utils.state['REP_ADDRESS']}/subject/suspend`.
- Upon successful suspension, a message indicating the success is displayed.
- If the suspension fails, an error message is shown along with the response text from the server.
- Ensure that `utils.state['REP_ADDRESS']` is configured to the correct server address.

## Command: `rep_activate_subject`
The `rep_activate_subject` command reactivates a suspended subject in the system. It requires a valid session token and the username of the subject to be reactivated.

### Usage
```bash
rep_activate_subject [OPTIONS] <session_file> <username>
```

This command uses the session token from `session_file` to authenticate the request and reactivates the subject identified by `username`.

### Parameters
- `session_file` (required): Path to the file containing the session token. This file must exist and include a valid session token.
- `username` (required): The username of the subject to reactivate.

### Notes
- The server endpoint for reactivating a subject is `http://{utils.state['REP_ADDRESS']}/subject/activate`.
- Upon successful reactivation, a message indicating success is displayed.
- If the reactivation fails, an error message is shown along with the response text from the server.
- Ensure that `utils.state['REP_ADDRESS']` is configured to the correct server address.

## Command: `rep_get_doc_file`
The `rep_get_doc_file` command retrieves a document from the server, downloads its metadata and file content, and decrypts the file based on the metadata. The decrypted content is either printed to the console or saved to a specified file.

### Usage
```bash
rep_get_doc_file [OPTIONS] <session_file> <document_name> [file]
```

This command uses the session token from `session_file` to authenticate the request. It first retrieves the document metadata, then fetches and decrypts the document file. The decrypted file can be output to the console or saved to the specified file.

### Parameters
- `session_file` (required): Path to the file containing the session token. This file must exist and include a valid session token.
- `document_name` (required): The name of the document to retrieve.
- `file` (optional): The local path where the decrypted file will be saved. If omitted, the file content is printed to the console.

### Notes
- The command first fetches metadata for the document, including its encryption details and file handle.
- The file is then downloaded and decrypted using the encryption key, IV, and nonce from the metadata.
- If `file` is not provided, the decrypted file is printed as plain text. If a `file` path is given, the decrypted content is saved to that file.
- The server endpoint for retrieving metadata is `http://{utils.state['REP_ADDRESS']}/file/metadata` and for downloading the file is `http://{utils.state['REP_ADDRESS']}/file/download/{file_handle}`.
- Ensure that `utils.state['REP_ADDRESS']` is configured to the correct server address.

## Command: `rep_decrypt_file`
The `rep_decrypt_file` command decrypts an encrypted file using the provided metadata. It reads the decryption parameters from the metadata file, decrypts the encrypted file, and logs the success of the operation.

### Usage
```bash
rep_decrypt_file [OPTIONS] <encrypted_file> <metadata>
```

This command decrypts the file specified by `encrypted_file` using the decryption parameters found in the `metadata` file.

### Parameters
- `encrypted_file` (required): Path to the encrypted file that needs to be decrypted. This file must exist.
- `metadata` (required): Path to the file containing the metadata for decryption, including the encryption key, IV, nonce, and algorithm details. This file must exist.

### Notes
- The `metadata` file must contain a JSON object with a `metadata` field that includes:
  - `encryption_key`: The encryption key (base64 encoded).
  - `iv`: The initialization vector (base64 encoded).
  - `nonce`: The nonce used in encryption (base64 encoded).
  - `algorithm`: The encryption algorithm and mode (e.g., `AES-GCM`).
- The decryption process is done using the `decrypt_file` function, which takes the decryption parameters (key, iv, nonce, algorithm, and mode) to decrypt the file.
- After the file is decrypted, a success message is logged.
- Ensure that the paths to both the encrypted file and metadata file are correct.

## Command: `rep_delete_doc`
The `rep_delete_doc` command deletes a specified document from the system. It requires a valid session token and the document's name to be deleted.

### Usage
```bash
rep_delete_doc [OPTIONS] <session_file> <document_name>
```

This command uses the session token from `session_file` to authenticate the request and delete the document identified by `document_name`.

### Parameters
- `session_file` (required): Path to the file containing the session token. This file must exist and include a valid session token.
- `document_name` (required): The name of the document to delete.

### Notes
- The server endpoint for deleting the document is `http://{utils.state['REP_ADDRESS']}/file/delete`.
- The command sends a PUT request with the document name in the request body for deletion.
- After the request is made, the response from the server is logged.
- Ensure that `utils.state['REP_ADDRESS']` is configured to the correct server address.

## Command: `rep_add_role`
The `rep_add_role` command adds a new role to the system. It requires a valid session token and the name of the role to be added.

### Usage
```bash
rep_add_role [OPTIONS] <session_file> <role>
```

This command uses the session token from `session_file` to authenticate the request and adds the specified `role` to the system.

### Parameters
- `session_file` (required): Path to the file containing the session token. This file must exist and include a valid session token.
- `role` (required): The name of the role to be added.

### Notes
- The server endpoint for adding a role is `http://{utils.state['REP_ADDRESS']}/role/add`.
- The command sends a POST request with the role name in the request body.
- After the request is made, the server's response is logged.
- Ensure that `utils.state['REP_ADDRESS']` is configured to the correct server address.

## Command: `rep_add_permission`
The `rep_add_permission` command assigns a permission to a specified role for a given target. It requires a valid session token, a role name, and the target resource for the permission.

### Usage
```bash
rep_add_permission [OPTIONS] <session_file> <role> <target>
```

This command uses the session token from `session_file` to authenticate the request and assigns the permission for the `role` on the specified `target`.

### Parameters
- `session_file` (required): Path to the file containing the session token. This file must exist and include a valid session token.
- `role` (required): The name of the role to which the permission will be added.
- `target` (required): The target resource or action for which the permission will be granted.

### Notes
- The server endpoint for adding permissions is `http://{utils.state['REP_ADDRESS']}/role/add_permission`.
- The command sends a PUT request with the role and target in the request body.
- After the request is made, the server's response is logged.
- Ensure that `utils.state['REP_ADDRESS']` is configured to the correct server address.

## Command: `rep_remove_permission`
The `rep_remove_permission` command removes a permission from a specified role for a given target. It requires a valid session token, a role name, and the target resource for the permission.

### Usage
```bash
rep_remove_permission [OPTIONS] <session_file> <role> <target>
```

This command uses the session token from `session_file` to authenticate the request and removes the permission for the `role` on the specified `target`.

### Parameters
- `session_file` (required): Path to the file containing the session token. This file must exist and include a valid session token.
- `role` (required): The name of the role from which the permission will be removed.
- `target` (required): The target resource or action from which the permission will be revoked.

### Notes
- The server endpoint for removing permissions is `http://{utils.state['REP_ADDRESS']}/role/remove_permission`.
- The command sends a DELETE request with the role and target in the request body.
- After the request is made, the server's response is logged.
- Ensure that `utils.state['REP_ADDRESS']` is configured to the correct server address.

## Command: `rep_add_subject`
The `rep_add_subject` command allows a user to assume a specified role and obtain a new session token associated with that role. The new token is written back to the session file.

### Usage
```bash
rep_add_subject [OPTIONS] <session_file> <role>
```

This command uses the session token from `session_file` to authenticate the request and attempts to assume the `role` specified.

### Parameters
- `session_file` (required): Path to the file containing the session token. This file must exist and include a valid session token. The file will be updated with the new session token upon success.
- `role` (required): The role that the user wishes to assume.

### Notes
- The server endpoint for assuming a role is `http://{utils.state['REP_ADDRESS']}/role/assume`.
- The command sends a POST request with the role in the request body.
- If successful, the new session token is logged and written to the `session_file`.
- Ensure that `utils.state['REP_ADDRESS']` is configured to the correct server address.

## Command: `rep_drop_role`
The `rep_drop_role` command allows a user to drop a specified role and obtain a new session token that excludes the dropped role. The new token is updated in the session file.

### Usage
```bash
rep_drop_role [OPTIONS] <session_file> <role>
```

This command uses the session token from `session_file` to authenticate the request and drops the specified `role` from the session.

### Parameters
- `session_file` (required): Path to the file containing the session token. This file must exist and include a valid session token. The file will be updated with the new session token upon success.
- `role` (required): The role to be dropped from the current session.

### Notes
- The server endpoint for dropping a role is `http://{utils.state['REP_ADDRESS']}/role/drop`.
- The command sends a PUT request with the role in the request body.
- Upon success, the new session token is logged and written to the `session_file`.
- Ensure that `utils.state['REP_ADDRESS']` is configured to the correct server address.

## Command: `rep_list_roles`
The `rep_list_roles` command lists all roles associated with the current session, displaying their status (active or suspended) and name.

### Usage
```bash
rep_list_roles [OPTIONS] <session_file>
```

This command retrieves and prints a sorted list of roles, with active roles displayed first.

### Parameters
- `session_file` (required): Path to the file containing the session token. This file must exist and include a valid session token.

### Output
- The roles are displayed in a table format with two columns: `Status` and `Name`.
- Status is shown as `Active` or `Suspended`.

### Notes
- The server endpoint for listing roles is `http://{utils.state['REP_ADDRESS']}/role/list`.
- Roles are sorted by their status, with active roles appearing first.
- Ensure that `utils.state['REP_ADDRESS']` is correctly configured to point to the server.

## Command: `rep_list_role_subjects`

The `rep_list_role_subjects` command retrieves and displays the list of subjects (users) assigned to a specific role, along with their status.

---

### Usage
```bash
rep_list_role_subjects [OPTIONS] <session_file> <role>
```

---

### Parameters
1. **`session_file`** (required):  
   Path to the session token file. The file must exist and contain a valid session token.
   
2. **`role`** (required):  
   The name of the role for which to list the subjects.

---

### Output
- A list of users assigned to the specified role. Each entry includes:
  - **Username**: The subject's unique identifier.
  - **Name**: The subject's full name.
  - **Status**: `Active` or `Suspended`.

---

### Notes
- The server endpoint for this functionality is:  
  `http://{utils.state['REP_ADDRESS']}/role/list_subjects`
- The command uses the session token to authenticate the request.
- Ensure that `utils.state['REP_ADDRESS']` is configured to point to the appropriate server.

## Command: `rep_list_subject_roles`

The `rep_list_subject_roles` command retrieves and displays all roles assigned to a specific subject (user), along with their status.

---

### Usage
```bash
rep_list_subject_roles [OPTIONS] <session_file> <username>
```

---

### Parameters
1. **`session_file`** (required):  
   Path to the session token file. The file must exist and contain a valid session token.
   
2. **`username`** (required):  
   The username of the subject whose roles are to be listed.

---

### Output
- A list of roles assigned to the specified subject. Each entry includes:
  - **Status**: `Active` or `Suspended`.
  - **Name**: The name of the role.

---

### Notes
- The server endpoint for this functionality is:  
  `http://{utils.state['REP_ADDRESS']}/role/list_subject_roles`
- The command uses the session token to authenticate the request.
- Ensure that `utils.state['REP_ADDRESS']` is configured to point to the appropriate server.

## Command: `rep_list_role_permissions`

The `rep_list_role_permissions` command is used to retrieve and display the permissions associated with a specified role.

---

### Usage
```bash
rep_list_role_permissions [OPTIONS] <session_file> <role>
```

---

### Parameters
1. **`session_file`** (required):  
   Path to the session token file. The file must exist and contain a valid session token for authentication.

2. **`role`** (required):  
   The name of the role whose permissions you want to list.

---

### Output
- A list of permissions assigned to the specified role.
  - Each permission will be listed on a new line, prefixed by a tab for formatting.

---

### Notes
- The server endpoint for this functionality is:  
  `http://{utils.state['REP_ADDRESS']}/role/list_permissions`
- The command uses the session token for authentication and the provided role to fetch the permissions.
- Ensure that `utils.state['REP_ADDRESS']` is configured to point to the appropriate server.

## Command: `rep_list_permission_roles`

The `rep_list_permission_roles` command is used to retrieve and display the roles that have a specific permission. It provides detailed information on each role, including its status and, in some cases, associated document information.

---

### Usage
```bash
rep_list_permission_roles [OPTIONS] <session_file> <permission>
```

---

### Parameters
1. **`session_file`** (required):  
   Path to the session token file. The file must exist and contain a valid session token for authentication.

2. **`permission`** (required):  
   The permission whose associated roles you want to list.

---

### Output
- A list of roles that have the specified permission.
  - Each role will include:
    - **Status**: Whether the role is active or suspended.
    - **Name**: The name of the role.
    - If the permission relates to a document, the **Document** column will also be displayed.

---

### Format
- The command will output the roles in a table format:
  - If the permission is related to a document, the columns displayed will be **Document**, **Status**, and **Name**.
  - If the permission is not related to a document, only **Status** and **Name** will be shown.

---

### Example Output (Document Permission)
```
Document              | Status     | Name                 
------------------------------------------------
document_1.pdf        | Active     | role_1               
document_2.pdf        | Suspended  | role_2
```

### Example Output (Non-Document Permission)
```
Status     | Name                
-----------------
Active     | role_1              
Suspended  | role_2
```

---

### Notes
- The server endpoint for this functionality is:  
  `http://{utils.state['REP_ADDRESS']}/role/list_permission_roles`
- The command uses the session token for authentication and the provided permission to fetch the associated roles.
- Ensure that `utils.state['REP_ADDRESS']` is configured to point to the appropriate server.

## Command: `rep_suspend_role`

The `rep_suspend_role` command is used to suspend a role within the system. By setting the role's status to `False`, this command effectively deactivates it.

---

### Usage
```bash
rep_suspend_role [OPTIONS] <session_file> <role>
```

---

### Parameters
1. **`session_file`** (required):  
   The path to the session token file. The file must exist and contain a valid session token for authentication.

2. **`role`** (required):  
   The name of the role to be suspended.

---

### Functionality
- The command reads the session token from the `session_file` to authenticate the request.
- The role name provided is used to identify which role needs to be suspended.
- The status of the specified role is set to `False`, which means the role will be suspended in the system.
- The command then sends a PUT request to update the role's status.
  
---

### Response
- If the request is successful (status code 200), the response will include a message confirming the role suspension.
- If the request fails, an error message is logged with the response content.

---

### Example Output
```plaintext
{
  "message": "Role 'admin' suspended successfully."
}
```

If the request fails:
```plaintext
{
  "error": "Failed to suspend role 'admin'."
}
```

---

### Notes
- The server endpoint for this functionality is:  
  `http://{utils.state['REP_ADDRESS']}/role/status`
- The `status` key in the request body is set to `False`, which indicates that the role should be suspended.
- The `utils.state['REP_ADDRESS']` should be configured to the correct server address.

## Command: `rep_reactivate_role`

The `rep_reactivate_role` command is used to reactivate a previously suspended role within the system. By setting the role's status to `True`, this command reactivates it.

---

### Usage
```bash
rep_reactivate_role [OPTIONS] <session_file> <role>
```

---

### Parameters
1. **`session_file`** (required):  
   The path to the session token file. The file must exist and contain a valid session token for authentication.

2. **`role`** (required):  
   The name of the role to be reactivated.

---

### Functionality
- The command reads the session token from the `session_file` to authenticate the request.
- The role name provided is used to identify which role needs to be reactivated.
- The status of the specified role is set to `True`, which means the role will be reactivated in the system.
- The command then sends a PUT request to update the role's status.

---

### Response
- If the request is successful (status code 200), the response will include a message confirming the role reactivation.
- If the request fails, an error message is logged with the response content.

---

### Example Output
```plaintext
{
  "message": "Role 'admin' reactivated successfully."
}
```

If the request fails:
```plaintext
{
  "error": "Failed to reactivate role 'admin'."
}
```

---

### Notes
- The server endpoint for this functionality is:  
  `http://{utils.state['REP_ADDRESS']}/role/status`
- The `status` key in the request body is set to `True`, which indicates that the role should be reactivated.
- The `utils.state['REP_ADDRESS']` should be configured to the correct server address.

## Command: `rep_acl_doc`

The `rep_acl_doc` command allows for managing document-level permissions for roles. You can add or remove a role's permission for a specific document by performing an access control list (ACL) operation.

---

### Usage
```bash
rep_acl_doc [OPTIONS] <session_file> <document_name> <operation> <role> <permission>
```

---

### Parameters

1. **`session_file`** (required):  
   The path to the session token file. This file must exist and contain a valid session token for authenticating the request.

2. **`document_name`** (required):  
   The name of the document for which the ACL operation is being applied.

3. **`operation`** (required):  
   The operation to be performed, which can either be:
   - `+` to **add** the permission.
   - `-` to **remove** the permission.

4. **`role`** (required):  
   The name of the role for which the permission is being granted or revoked.

5. **`permission`** (required):  
   The permission to be added or removed for the role (e.g., `read`, `write`, etc.).

---

### Functionality

- The command reads the session token from the `session_file` to authenticate the request.
- Based on the operation (`+` or `-`), the command will either add or remove the specified permission for the given role on the specified document.
- The operation is performed by sending either a `PUT` request (to add the permission) or a `DELETE` request (to remove the permission) to the corresponding endpoint.

---

### Example Usage

**To add a permission for a role:**
```bash
rep_acl_doc session.txt document1 + admin read
```
This will add the `read` permission for the `admin` role on `document1`.

**To remove a permission for a role:**
```bash
rep_acl_doc session.txt document1 - admin write
```
This will remove the `write` permission for the `admin` role on `document1`.

---

### Response

- If the request is successful (status code 200), the response will contain a message confirming the operation was completed.
  
  **Example:**
  ```json
  {
    "message": "Permission 'read' added to role 'admin' for document 'document1'."
  }
  ```

- If the request fails, an error message will be logged with the response content.

---

### Notes

- **Endpoints:**
  - Add permission: `http://{utils.state['REP_ADDRESS']}/role/acl_doc/add`
  - Remove permission: `http://{utils.state['REP_ADDRESS']}/role/acl_doc/remove`
  
- The `utils.state['REP_ADDRESS']` should be correctly configured with the address of the server handling the requests.
  
- If the operation is invalid (anything other than `+` or `-`), the command will log an error message and terminate the operation.

