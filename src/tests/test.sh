#!/bin/bash

# Set the repository address
# Ensure to set this to your actual API server's network address
export REP_ADDRESS="127.0.0.1:5000"  # Adjust this as necessary

# Set initial variables
PASSWORD="StrongPassword123"
CREDENTIALS_FILE="credentials.json"
PUBLIC_KEY_FILE="credentials.json"  # Make sure this points to an actual public key if different
PRIVATE_KEY_FILE="private_key.pem"
SESSION_FILE="session_token.json"
DOCUMENT_PATH="$HOME/Documents/sample.txt"
DOCUMENT_NAME="Document1"
ORGANIZATION="Org1"
USERNAME="User"
USER_NAME="User Name"
EMAIL="User@example.com"

# Check if the sample document exists, create if not
if [ ! -f "$DOCUMENT_PATH" ]; then
    echo "Creating a new sample document at $DOCUMENT_PATH."
    echo "This is a sample document for testing purposes." > "$DOCUMENT_PATH"
fi


# Change to the 'cli' directory
cd src/cli

echo "Test: Step 1 - Generate RSA Key Pair"
# Step 1: Generate RSA Key Pair
./rep_subject_credentials "$PASSWORD" "$CREDENTIALS_FILE"

echo " "
# Step 2: Create New Organization
echo "Test: Step 2 - Create New Organization"
# Create the organization
./rep_create_org "$ORGANIZATION" "$USERNAME" "$USER_NAME" "$EMAIL" "$PUBLIC_KEY_FILE"

echo " "
# Step 3: List All Organizations
echo "Test: Step 3 - List All Organizations"
# List organizations
./rep_list_orgs

echo " "
# Step 4: Creat a session
echo "Test: Step 4 - Creat a session"
# Add the document to the repository
./rep_create_session "$ORGANIZATION" "$USERNAME" "$PASSWORD" "$CREDENTIALS_FILE" "$SESSION_FILE"

echo " "
# Step 5: Add Document to Repository
echo "Test: Step 5 - Add Document to Repository"
# Add the document to the repository
./rep_add_doc "$SESSION_FILE" "$DOCUMENT_NAME" "$DOCUMENT_PATH"

echo "=== All Steps Completed Successfully ==="

# Navigate back to original directory
cd -

