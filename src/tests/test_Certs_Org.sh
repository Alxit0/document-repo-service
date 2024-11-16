#!/bin/bash

# Set the repository address
# Ensure to set this to your actual API server's network address
export REP_ADDRESS="127.0.0.1:5000"  # Adjust this as necessary

# Set initial variables for Org
PASSWORD_LOL="StrongPassword123"
CREDENTIALS_FILE_LOL="LOL_cred.json"
ORG_LOL="LOL"
USERNAME0="ap13"
USER_NAME0="Antonio Moreira"
EMAIL0="Antonio@example.com"

# Set initial variables for Org
PASSWORD_WOW="Password123"
CREDENTIALS_FILE_WOW="WOW_cred.json"
ORG_WOW="WOW"
USERNAME1="benny"
USER_NAME1="Bernardo"
EMAIL1="Bernardo@example.com"

# Change to the 'cli' directory
cd src/cli

echo " "
echo "======================================================"
echo "|               Creating Org. LOL                    |"
echo "======================================================"
# Step 1: Generate RSA Key Pair
./rep_subject_credentials "$PASSWORD_LOL" "$CREDENTIALS_FILE_LOL"
if [ $? -ne 0 ]
then
	echo "Error: Failed to create Cerdentials"
	exit 1
fi

# Step 2: Create New Organization
./rep_create_org "$ORG_LOL" "$USERNAME0" "$USER_NAME0" "$EMAIL0" "$CREDENTIALS_FILE_LOL"
if [ $? -ne 0 ]
then
	echo "Error: Failed to create Organization"
	exit 1
fi

echo " "
echo "======================================================"
echo "|                reating Org. WOW                    |"
echo "======================================================"
 
# Step 1: Generate RSA Key Pair
./rep_subject_credentials "$PASSWORD_WOW" "$CREDENTIALS_FILE_WOW"
if [ $? -ne 0 ]
then
	echo "Error: Failed to create Cerdentials"
	exit 1
fi

# Step 2: Create New Organization
./rep_create_org "$ORG_WOW" "$USERNAME1" "$USER_NAME1" "$EMAIL1" "$CREDENTIALS_FILE_WOW"
if [ $? -ne 0 ]
then
	echo "Error: Failed to create Organization"
	exit 1
fi

echo " "
echo "======================================================"
echo "|            List of Organizations                   |"
echo "======================================================"
#List All Organizations
./rep_list_orgs
if [ $? -ne 0 ]
then
	echo "Error: Failed to list Organizations"
	exit 1
fi

echo " "
cd -