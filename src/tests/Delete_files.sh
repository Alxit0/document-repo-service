#!/bin/bash
cd ..

#delete database file
rm api/database.db

#delete org credentials
rm cli/*_cred.json

#delete org sessions
rm cli/*_session.json

#delete metadata directory
rm -rf cli/metadatas

#delete sample files
rm $HOME/Documents/LOL_*.txt
rm $HOME/Documents/WOW_*.txt

#delete sample files
rm $HOME/Downloads/*_?_copy.txt

#delete ./sio directory in $HOME
rm -rf $HOME/.sio