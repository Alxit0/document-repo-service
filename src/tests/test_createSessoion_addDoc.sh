#!/bin/bash

# Set the repository address
# Ensure to set this to your actual API server's network address
export REP_ADDRESS="127.0.0.1:5000"  # Adjust this as necessary

# Set initial variables for Org0
PASSWORD0="StrongPassword123"
CREDENTIALS_FILE0="LOL_cred.json"
ORG0="LOL"
USERNAME0="ap13"
USER_NAME0="Antonio Moreira"
EMAIL0="Antonio@example.com"

SESSION_FILE0="LOL_session.json"
DOCUMENT_PATH0="$HOME/Documents/LOL_1.txt"
DOCUMENT_NAME0="LOL_1"
DOCUMENT_PATH00="$HOME/Documents/LOL_2.txt"
DOCUMENT_NAME00="LOL_2"

# Set initial variables for Org1
PASSWORD1="Password123"
CREDENTIALS_FILE1="WOW_cred.json"
ORG1="WOW"
USERNAME1="benny"
USER_NAME1="Bernardo"
EMAIL1="Bernardo@example.com"
SESSION_FILE1="WOW_session.json"
DOCUMENT_PATH1="$HOME/Documents/WOW_1.txt"
DOCUMENT_NAME1="WOW_1"

# Change to the 'cli' directory
cd src/cli

# Check if the sample document exists, create if not
if [ ! -f "$DOCUMENT_PATH0" ]; then
    echo "Creating a new sample document at $DOCUMENT_PATH0."
    echo "This is a sample document for testing purposes." > "$DOCUMENT_PATH0"
fi

# Check if the sample document exists, create if not
if [ ! -f "$DOCUMENT_PATH00" ]; then
    echo "Creating a new sample document at $DOCUMENT_PATH00."
    echo "This is a sample document for testing purposes." > "$DOCUMENT_PATH00"
fi

# Check if the sample document exists, create if not
if [ ! -f "$DOCUMENT_PATH1" ]; then
    echo "Creating a new sample document at $DOCUMENT_PATH1."
    echo "This is a sample document for testing purposes." > "$DOCUMENT_PATH1"
fi

echo " "
# Step 1: List All Organizations
echo "List All Organizations"
# List organizations
./rep_list_orgs
echo $?

# Create Sessiopn in org0
echo " "
echo "Creating session ORG0"
# Creat a session"
./rep_create_session "$ORG0" "$USERNAME0" "$PASSWORD0" "$CREDENTIALS_FILE0" "$SESSION_FILE0"
echo $?
# Add 2 Document to Repository
./rep_add_doc "$SESSION_FILE0" "$DOCUMENT_NAME0" "$DOCUMENT_PATH0"
echo $?
./rep_add_doc "$SESSION_FILE0" "$DOCUMENT_NAME00" "$DOCUMENT_PATH00"
echo $?

# Create Sessiopn in org1
echo " "
echo "Creating session ORG1"
# Creat a session"
./rep_create_session "$ORG1" "$USERNAME1" "$PASSWORD1" "$CREDENTIALS_FILE1" "$SESSION_FILE1"
echo $?
# Add 2 Document to Repository
./rep_add_doc "$SESSION_FILE1" "$DOCUMENT_NAME1" "$DOCUMENT_PATH1"
echo $?

echo " "
echo "=== All Steps Completed Successfully ==="

cd -