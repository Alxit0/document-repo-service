#!/bin/bash

# Set initial variables
PASSWORD="StrongPassword123"
CREDENTIALS_FILE="$HOME/.sio/credentials.json"
PUBLIC_KEY_FILE="$HOME/.sio/public_key.pem"
PRIVATE_KEY_FILE="$HOME/.sio/private_key.pem"
SESSION_FILE="$HOME/.sio/session_token.json"
DOCUMENT_PATH="$HOME/Documents/sample.txt"
DOCUMENT_NAME="Document1"
ORGANIZATION="NewOrg"
USERNAME="orguser"
USER_NAME="Org User"
EMAIL="orguser@example.com"

# Define the path to client.py
CLIENT_PY_PATH="$HOME/Desktop/SIO/sio-2425-project-93279_103592_124572/src/cli/client.py"

# Ensure .sio directory exists
mkdir -p "$HOME/.sio"

# Check if client.py exists
if [ ! -f "$CLIENT_PY_PATH" ]; then
    echo "Error: client.py not found at $CLIENT_PY_PATH"
    exit 1
fi

echo "Using client.py at: $CLIENT_PY_PATH"
echo "Creating .sio directory at $HOME/.sio"

# Step 1: Generate RSA Key Pair
echo "=== Step 1: Generate RSA Key Pair ==="
python "$CLIENT_PY_PATH" rep_subject_credentials "$PASSWORD" "$CREDENTIALS_FILE"
if [ $? -ne 0 ]; then
    echo "Error: Failed to generate RSA key pair"
    exit 1
fi
echo "RSA Key Pair created and stored in $CREDENTIALS_FILE, public key at $PUBLIC_KEY_FILE"

# Step 2: Create New Organization
echo "=== Step 2: Create New Organization ==="
if [ ! -f "$PUBLIC_KEY_FILE" ]; then
    echo "Error: Public key file not found at $PUBLIC_KEY_FILE"
    exit 1
fi

python "$CLIENT_PY_PATH" rep_create_org "$ORGANIZATION" "$USERNAME" "$USER_NAME" "$EMAIL" "$PUBLIC_KEY_FILE"
if [ $? -ne 0 ]; then
    echo "Error: Failed to create organization"
    exit 1
fi
echo "Organization '$ORGANIZATION' created successfully."

# Step 3: List All Organizations
echo "=== Step 3: List All Organizations ==="
python "$CLIENT_PY_PATH" rep_list_orgs
if [ $? -ne 0 ]; then
    echo "Error: Failed to list organizations"
    exit 1
fi

# Step 4: Add Document to Repository
echo "=== Step 4: Add Document to Repository ==="
if [ ! -f "$SESSION_FILE" ]; then
    echo "Error: Session file not found at $SESSION_FILE"
    exit 1
fi

if [ ! -f "$DOCUMENT_PATH" ]; then
    echo "Error: Document file not found at $DOCUMENT_PATH"
    exit 1
fi

python "$CLIENT_PY_PATH" rep_add_doc "$SESSION_FILE" "$DOCUMENT_NAME" "$DOCUMENT_PATH"
if [ $? -ne 0 ]; then
    echo "Error: Failed to add document to repository"
    exit 1
fi
echo "Document '$DOCUMENT_NAME' successfully encrypted and uploaded."

echo "=== All Steps Completed Successfully ==="

