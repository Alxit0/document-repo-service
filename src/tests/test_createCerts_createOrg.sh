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

# Set initial variables for Org1
PASSWORD1="Password123"
CREDENTIALS_FILE1="WOW_cred.json"
ORG1="WOW"
USERNAME1="benny"
USER_NAME1="Bernardo"
EMAIL1="Bernardo@example.com"

# Change to the 'cli' directory
cd src/cli

echo "Creating ORG0"
# Step 1: Generate RSA Key Pair
./rep_subject_credentials "$PASSWORD0" "$CREDENTIALS_FILE0"
echo $?
# Step 2: Create New Organization
./rep_create_org "$ORG0" "$USERNAME0" "$USER_NAME0" "$EMAIL0" "$CREDENTIALS_FILE0"
echo $?

echo "Creating ORG1"
# Step 1: Generate RSA Key Pair
./rep_subject_credentials "$PASSWORD1" "$CREDENTIALS_FILE1"
echo $?
# Step 2: Create New Organization
./rep_create_org "$ORG1" "$USERNAME1" "$USER_NAME1" "$EMAIL1" "$CREDENTIALS_FILE1"
echo $?

echo " "
# Step 3: List All Organizations
echo "Test: Step 3 - List All Organizations"
# List organizations
./rep_list_orgs
echo $?

cd -