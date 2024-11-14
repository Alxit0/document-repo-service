#!/bin/bash

#delete database file
rm src/api/database.db

#delete org credentials
rm src/cli/WOW_cred.json
rm src/cli/LOL_cred.json

#delete org sessions
rm src/cli/LOL_session.json
rm src/cli/WOW_session.json

#delete semplefile
rm $HOME/Documents/LOL_1.txt
rm $HOME/Documents/LOL_2.txt
rm $HOME/Documents/WOW_1.txt