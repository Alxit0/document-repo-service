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
SESSION_FILE_LOL="LOL_session.json"

# Set initial variables for Org
PASSWORD_WOW="Password123"
CREDENTIALS_FILE_WOW="WOW_cred.json"
ORG_WOW="WOW"
USERNAME1="benny"
USER_NAME1="Bernardo"
EMAIL1="Bernardo@example.com"
SESSION_FILE_WOW="WOW_session.json"

DOCUMENT_PATH0="$HOME/Documents/LOL_1.txt"
DOCUMENT_NAME0="LOL_1"
FILE_HANDLE0="b367cfbe8009b171bd85c0294aa4a8dd1242d026820171f864aad9dd77fa8024"

DOCUMENT_PATH1="$HOME/Documents/LOL_2.txt"
DOCUMENT_NAME1="LOL_2"
FILE_HANDLE1="35e34d121176ffa0793c26966528f0037e54efd9e617598513a7f425b1abae90"
DOWNLOAD_PATH1="$HOME/Downloads/LOL_2_copy.txt"

DOCUMENT_PATH2="$HOME/Documents/WOW_1.txt"
DOCUMENT_NAME2="WOW_1"
FILE_HANDLE2="6d83b23024c75911246bc1756f0cab3d5a6234017129a0f7b4f8de2e4be1baee"
DOWNLOAD_PATH2="$HOME/Downloads/WOW_1_copy.txt"

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
echo "======================================================"
echo "|             Creating sample docs                   |"
echo "======================================================"
# Check if the sample document exists, create if not
if [ ! -f "$DOCUMENT_PATH0" ]; then
    echo "Creating a new sample document at $DOCUMENT_PATH0."
    echo "This is a sample document 0 for testing purposes of Org. LOL." > "$DOCUMENT_PATH0"
fi

# Check if the sample document exists, create if not
if [ ! -f "$DOCUMENT_PATH1" ]; then
    echo "Creating a new sample document at $DOCUMENT_PATH1."
    echo "This is a sample document 1 for testing purposes of Org. LOL." > "$DOCUMENT_PATH1"
fi

# Check if the sample document exists, create if not
if [ ! -f "$DOCUMENT_PATH2" ]; then
    echo "Creating a new sample document at $DOCUMENT_PATH2."
    echo "This is a sample document 3 for testing purposes of Org. WOW." > "$DOCUMENT_PATH2"
fi


echo " "
echo "======================================================"
echo "|           Creating Session for ORG LOL             |"
echo "======================================================"
# Creat a session"
./rep_create_session "$ORG_LOL" "$USERNAME0" "$PASSWORD_LOL" "$CREDENTIALS_FILE_LOL" "$SESSION_FILE_LOL"
if [ $? -ne 0 ]
then
    echo "Error: Failed to create Session for Organization $ORG_LOL"
    exit 1
fi

echo "- - - - - - - - - - - - - - - - - - - - - - - - - - - -"
echo "Adding Document"
# Add a Document
./rep_add_doc "$SESSION_FILE_LOL" "$DOCUMENT_NAME0" "$DOCUMENT_PATH0"
if [ $? -ne 0 ]
then
    echo "Error: Failed to add Document $DOCUMENT_NAME0"
    exit 1
fi

echo "- - - - - - - - - - - - - - - - - - - - - - - - - - - -"
echo "Adding Document"
# Add a Document
./rep_add_doc "$SESSION_FILE_LOL" "$DOCUMENT_NAME1" "$DOCUMENT_PATH1"
if [ $? -ne 0 ]
then
    echo "Error: Failed to add Document $DOCUMENT_NAME1"
    exit 1
fi

echo " "
echo "======================================================"
echo "|           Creating Session for ORG WOW             |"
echo "======================================================"
# Creat a session"
./rep_create_session "$ORG_WOW" "$USERNAME1" "$PASSWORD_WOW" "$CREDENTIALS_FILE_WOW" "$SESSION_FILE_WOW"
if [ $? -ne 0 ]
then
    echo "Error: Failed to create Session for Organization $ORG_WOW"
    exit 1
fi


echo "- - - - - - - - - - - - - - - - - - - - - - - - - - - -"
echo "Adding Document"
# Add Document
./rep_add_doc "$SESSION_FILE_WOW" "$DOCUMENT_NAME2" "$DOCUMENT_PATH2"
if [ $? -ne 0 ]
then
    echo "Error: Failed to add Document $DOCUMENT_NAME1"
    exit 1
fi

echo "======================================================"
echo "|       List All Docs in Session of Org LOL          |"
echo "======================================================"

# List Docs
./rep_list_docs "$SESSION_FILE_LOL"
if [ $? -ne 0 ]
then
    echo "Error: Failed to list Docs"
    exit 1
fi

echo " "
echo "======================================================"
echo "|       List All Docs in Session of Org WOW          |"
echo "======================================================"

# List Docs
./rep_list_docs "$SESSION_FILE_WOW"
if [ $? -ne 0 ]
then
    echo "Error: Failed to list Docs"
    exit 1
fi

echo " "
echo "======================================================"
echo "|              Get Docs Metadata                     |"
echo "======================================================"

# Doc0 in LOL Session
./rep_get_doc_metadata "$SESSION_FILE_LOL" "$DOCUMENT_NAME0"
if [ $? -ne 0 ]
then
    echo "Error: Failed to list Docs"
    exit 1
fi

echo " "
echo "- - - - - - - - - - - - - - - - - - - - - - - - - - "
# Doc1 in LOL Session
./rep_get_doc_metadata "$SESSION_FILE_LOL" "$DOCUMENT_NAME1"
if [ $? -ne 0 ]
then
    echo "Error: Failed to list Docs"
    exit 1
fi

echo " "
echo "- - - - - - - - - - - - - - - - - - - - - - - - - - "
# Doc2 in WOW Session
./rep_get_doc_metadata "$SESSION_FILE_WOW" "$DOCUMENT_NAME2"
if [ $? -ne 0 ]
then
    echo "Error: Failed to list Docs"
    exit 1
fi

echo " "
echo "======================================================"
echo "|                 Get File                           |"
echo "======================================================"

# get file and print in terminal
./rep_get_file "$FILE_HANDLE0"
if [ $? -ne 0 ]
then
    echo "Error: Failed to get file"
    exit 1
fi

echo " "
echo "- - - - - - - - - - - - - - - - - - - - - - - - - - "
# get file and Download it
./rep_get_file "$FILE_HANDLE1" "$DOWNLOAD_PATH1"
if [ $? -ne 0 ]
then
    echo "Error: Failed to get file"
    exit 1
fi

echo " "
echo "- - - - - - - - - - - - - - - - - - - - - - - - - - "
# get file and Download it
./rep_get_file "$FILE_HANDLE2" "$DOWNLOAD_PATH2"
if [ $? -ne 0 ]
then
    echo "Error: Failed to get file"
    exit 1
fi

echo " "
cd -