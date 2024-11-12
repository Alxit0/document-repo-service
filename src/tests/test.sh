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
ORGANIZATION="NewOrg"
USERNAME="orguser"
USER_NAME="Org User"
EMAIL="orguser@example.com"

# Change to the 'cli' directory
cd src/cli

echo "Test: Step 1 - Generate RSA Key Pair"
# Step 1: Generate RSA Key Pair
./rep_subject_credentials "$PASSWORD" "$CREDENTIALS_FILE"

# Step 2: Create New Organization
echo "Test: Step 2 - Create New Organization"
# Create the organization
./rep_create_org "$ORGANIZATION" "$USERNAME" "$USER_NAME" "$EMAIL" "$PUBLIC_KEY_FILE"

# Step 3: List All Organizations
echo "Test: Step 3 - List All Organizations"
# List organizations
./rep_list_orgs

# Step 4: Add Document to Repository
echo "Test: Step 4 - Add Document to Repository"
# Add the document to the repository
./rep_add_doc "$SESSION_FILE" "$DOCUMENT_NAME" "$DOCUMENT_PATH"

echo "=== All Steps Completed Successfully ==="

# Navigate back to original directory
cd -

